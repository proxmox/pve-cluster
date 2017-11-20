package PVE::API2::ClusterConfig;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster;
use PVE::Corosync;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'nodes' },
	    { name => 'totem' },
	    ];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'nodes',
    path => 'nodes',
    method => 'GET',
    description => "Corosync node list.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		node => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{node}" } ],
    },
    code => sub {
	my ($param) = @_;


	my $conf = PVE::Cluster::cfs_read_file('corosync.conf');
	my $nodelist = PVE::Corosync::nodelist($conf);

	return PVE::RESTHandler::hash_to_array($nodelist, 'node');
    }});

# lock method to ensure local and cluster wide atomicity
# if we're a single node cluster just lock locally, we have no other cluster
# node which we could contend with, else also acquire a cluster wide lock
my $config_change_lock = sub {
    my ($code) = @_;

    my $local_lock_fn = "/var/lock/pvecm.lock";
    PVE::Tools::lock_file($local_lock_fn, 10, sub {
	PVE::Cluster::cfs_update(1);
	my $members = PVE::Cluster::get_members();
	if (scalar(keys %$members) > 1) {
	    return PVE::Cluster::cfs_lock_file('corosync.conf', 10, $code);
	} else {
	    return $code->();
	}
    });
};


__PACKAGE__->register_method ({
    name => 'addnode',
    path => 'nodes/{node}',
    method => 'POST',
    protected => 1,
    description => "Adds a node to the cluster configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    nodeid => {
		type => 'integer',
		description => "Node id for this node.",
		minimum => 1,
		optional => 1,
	    },
	    votes => {
		type => 'integer',
		description => "Number of votes for this node",
		minimum => 0,
		optional => 1,
	    },
	    force => {
		type => 'boolean',
		description => "Do not throw error if node already exists.",
		optional => 1,
	    },
	    ring0_addr => {
		type => 'string', format => 'address',
		description => "Hostname (or IP) of the corosync ring0 address of this node.".
		    " Defaults to nodes hostname.",
		optional => 1,
	    },
	    ring1_addr => {
		type => 'string', format => 'address',
		description => "Hostname (or IP) of the corosync ring1 address, this".
		    " needs an valid bindnet1_addr.",
		optional => 1,
	    },
	},
    },
    returns => {
	type => "object",
	properties => {
	    corosync_authkey => {
		type => 'string',
	    },
	    corosync_conf => {
		type => 'string',
	    }
	},
    },
    code => sub {
	my ($param) = @_;

	PVE::Cluster::check_cfs_quorum();

	my $code = sub {
	    my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
	    my $nodelist = PVE::Corosync::nodelist($conf);
	    my $totem_cfg = PVE::Corosync::totem_config($conf);

	    my $name = $param->{node};

	    # ensure we do not reuse an address, that can crash the whole cluster!
	    my $check_duplicate_addr = sub {
		my $addr = shift;
		return if !defined($addr);

		while (my ($k, $v) = each %$nodelist) {
		    next if $k eq $name; # allows re-adding a node if force is set
			if ($v->{ring0_addr} eq $addr || ($v->{ring1_addr} && $v->{ring1_addr} eq $addr)) {
			    die "corosync: address '$addr' already defined by node '$k'\n";
			}
		}
	    };

	    &$check_duplicate_addr($param->{ring0_addr});
	    &$check_duplicate_addr($param->{ring1_addr});

	    $param->{ring0_addr} = $name if !$param->{ring0_addr};

	    die "corosync: using 'ring1_addr' parameter needs a configured ring 1 interface!\n"
		if $param->{ring1_addr} && !defined($totem_cfg->{interface}->{1});

	    die "corosync: ring 1 interface configured but 'ring1_addr' parameter not defined!\n"
		if defined($totem_cfg->{interface}->{1}) && !defined($param->{ring1_addr});

	    if (defined(my $res = $nodelist->{$name})) {
		$param->{nodeid} = $res->{nodeid} if !$param->{nodeid};
		$param->{votes} = $res->{quorum_votes} if !defined($param->{votes});

		if ($res->{quorum_votes} == $param->{votes} &&
		    $res->{nodeid} == $param->{nodeid} && $param->{force}) {
		    print "forcing overwrite of configured node '$name'\n";
		} else {
		    die "can't add existing node '$name'\n";
		}
	    } elsif (!$param->{nodeid}) {
		my $nodeid = 1;

		while(1) {
		    my $found = 0;
		    foreach my $v (values %$nodelist) {
			if ($v->{nodeid} eq $nodeid) {
			    $found = 1;
			    $nodeid++;
			    last;
			}
		    }
		    last if !$found;
		};

		$param->{nodeid} = $nodeid;
	    }

	    $param->{votes} = 1 if !defined($param->{votes});

	    PVE::Cluster::gen_local_dirs($name);

	    eval { PVE::Cluster::ssh_merge_keys(); };
	    warn $@ if $@;

	    $nodelist->{$name} = {
		ring0_addr => $param->{ring0_addr},
		nodeid => $param->{nodeid},
		name => $name,
	    };
	    $nodelist->{$name}->{ring1_addr} = $param->{ring1_addr} if $param->{ring1_addr};
	    $nodelist->{$name}->{quorum_votes} = $param->{votes} if $param->{votes};

	    PVE::Cluster::log_msg('notice', 'root@pam', "adding node $name to cluster");

	    PVE::Corosync::update_nodelist($conf, $nodelist);
	};

	$config_change_lock->($code);
	die $@ if $@;

	my $clusterconf = "/etc/pve/corosync.conf";
	my $authfile = "/etc/corosync/authkey";

	my $res = {
	    corosync_authkey => PVE::Tools::file_get_contents($authfile),
	    corosync_conf => PVE::Tools::file_get_contents($clusterconf),
	};

	return $res;
    }});


__PACKAGE__->register_method ({
    name => 'delnode',
    path => 'nodes/{node}',
    method => 'DELETE',
    protected => 1,
    description => "Removes a node from the cluster configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $local_node = PVE::INotify::nodename();
	die "Cannot delete myself from cluster!\n" if $param->{node} eq $local_node;

	PVE::Cluster::check_cfs_quorum();

	my $code = sub {
	    my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
	    my $nodelist = PVE::Corosync::nodelist($conf);

	    my $node;
	    my $nodeid;

	    foreach my $tmp_node (keys %$nodelist) {
		my $d = $nodelist->{$tmp_node};
		my $ring0_addr = $d->{ring0_addr};
		my $ring1_addr = $d->{ring1_addr};
		if (($tmp_node eq $param->{node}) ||
		    (defined($ring0_addr) && ($ring0_addr eq $param->{node})) ||
		    (defined($ring1_addr) && ($ring1_addr eq $param->{node}))) {
		    $node = $tmp_node;
		    $nodeid = $d->{nodeid};
		    last;
		}
	    }

	    die "Node/IP: $param->{node} is not a known host of the cluster.\n"
		if !defined($node);

	    PVE::Cluster::log_msg('notice', 'root@pam', "deleting node $node from cluster");

	    delete $nodelist->{$node};

	    PVE::Corosync::update_nodelist($conf, $nodelist);

	    PVE::Tools::run_command(['corosync-cfgtool','-k', $nodeid]) if defined($nodeid);
	};

	$config_change_lock->($code);
	die $@ if $@;

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'totem',
    path => 'totem',
    method => 'GET',
    description => "Get corosync totem protocol settings.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => "object",
	properties => {},
    },
    code => sub {
	my ($param) = @_;


	my $conf = PVE::Cluster::cfs_read_file('corosync.conf');

	my $totem_cfg = $conf->{main}->{totem};

	return $totem_cfg;
    }});

1;
