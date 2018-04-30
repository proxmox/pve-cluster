package PVE::API2::ClusterConfig;

use strict;
use warnings;

use PVE::Tools;
use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster;
use PVE::APIClient::LWP;
use PVE::Corosync;

use base qw(PVE::RESTHandler);

my $clusterconf = "/etc/pve/corosync.conf";
my $authfile = "/etc/corosync/authkey";
my $local_cluster_lock = "/var/lock/pvecm.lock";

my $ring0_desc = {
    type => 'string', format => 'address',
    description => "Hostname (or IP) of the corosync ring0 address of this node.",
    default => "Hostname of the node",
    optional => 1,
};
PVE::JSONSchema::register_standard_option("corosync-ring0-addr", $ring0_desc);

my $ring1_desc = {
    type => 'string', format => 'address',
    description => "Hostname (or IP) of the corosync ring1 address of this node.".
	" Requires a valid configured ring 1 (bindnet1_addr) in the cluster.",
    optional => 1,
};
PVE::JSONSchema::register_standard_option("corosync-ring1-addr", $ring1_desc);

my $nodeid_desc = {
    type => 'integer',
    description => "Node id for this node.",
    minimum => 1,
    optional => 1,
};
PVE::JSONSchema::register_standard_option("corosync-nodeid", $nodeid_desc);

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
	    { name => 'join' },
	];

	return $result;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    protected => 1,
    description => "Generate new cluster configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    clustername => {
		description => "The name of the cluster.",
		type => 'string', format => 'pve-node',
		maxLength => 15,
	    },
	    nodeid => get_standard_option('corosync-nodeid'),
	    votes => {
		type => 'integer',
		description => "Number of votes for this node.",
		minimum => 1,
		optional => 1,
	    },
	    bindnet0_addr => {
		type => 'string', format => 'ip',
		description => "This specifies the network address the corosync ring 0".
		    " executive should bind to and defaults to the local IP address of the node.",
		optional => 1,
	    },
	    ring0_addr => get_standard_option('corosync-ring0-addr'),
	    bindnet1_addr => {
		type => 'string', format => 'ip',
		description => "This specifies the network address the corosync ring 1".
		    " executive should bind to and is optional.",
		optional => 1,
	    },
	    ring1_addr => get_standard_option('corosync-ring1-addr'),
	},
    },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	-f $clusterconf && die "cluster config '$clusterconf' already exists\n";

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $code = sub {
	    STDOUT->autoflush();
	    PVE::Cluster::setup_sshd_config(1);
	    PVE::Cluster::setup_rootsshconfig();
	    PVE::Cluster::setup_ssh_keys();

	    PVE::Tools::run_command(['/usr/sbin/corosync-keygen', '-lk', $authfile])
		if !-f $authfile;
	    die "no authentication key available\n" if -f !$authfile;

	    my $nodename = PVE::INotify::nodename();

	    # get the corosync basis config for the new cluster
	    my $config = PVE::Corosync::create_conf($nodename, %$param);

	    print "Writing corosync config to /etc/pve/corosync.conf\n";
	    PVE::Corosync::atomic_write_conf($config);

	    my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);
	    PVE::Cluster::ssh_merge_keys();
	    PVE::Cluster::gen_pve_node_files($nodename, $local_ip_address);
	    PVE::Cluster::ssh_merge_known_hosts($nodename, $local_ip_address, 1);

	    print "Restart corosync and cluster filesystem\n";
	    PVE::Tools::run_command('systemctl restart corosync pve-cluster');
	};

	my $worker = sub {
	    PVE::Tools::lock_file($local_cluster_lock, 10, $code);
	    die $@ if $@;
	};

	return $rpcenv->fork_worker('clustercreate', $param->{clustername},  $authuser, $worker);
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

    PVE::Tools::lock_file($local_cluster_lock, 10, sub {
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
	    nodeid => get_standard_option('corosync-nodeid'),
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
	    ring0_addr => get_standard_option('corosync-ring0-addr'),
	    ring1_addr => get_standard_option('corosync-ring1-addr'),
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

__PACKAGE__->register_method ({
    name => 'join_info',
    path => 'join',
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    method => 'GET',
    description => "Get information needed to join this cluster over the connected node.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node', {
		description => "The node for which the joinee gets the nodeinfo. ",
		default => "current connected node",
		optional => 1,
	    }),
	},
    },
    returns => {
	type => 'object',
	additionalProperties => 0,
	properties => {
	    nodelist => {
		type => 'array',
		items => {
		    type => "object",
		    additionalProperties => 1,
		    properties => {
			name => get_standard_option('pve-node'),
			nodeid => get_standard_option('corosync-nodeid'),
			ring0_addr => get_standard_option('corosync-ring0-addr'),
			quorum_votes => { type => 'integer', minimum => 0 },
			pve_addr => { type => 'string', format => 'ip' },
			pve_fp => get_standard_option('fingerprint-sha256'),
		    },
		},
	    },
	    preferred_node => get_standard_option('pve-node'),
	    totem => { type => 'object' },
	    config_digest => { type => 'string' },
	},
    },
    code => sub {
	my ($param) = @_;

	my $nodename = $param->{node} // PVE::INotify::nodename();

	PVE::Cluster::cfs_update(1);
	my $conf = PVE::Cluster::cfs_read_file('corosync.conf');

	die "node is not in a cluster, no join info available!\n"
	    if !($conf && $conf->{main});

	my $totem_cfg = $conf->{main}->{totem} // {};
	my $nodelist = $conf->{main}->{nodelist}->{node} // {};
	my $corosync_config_digest = $conf->{digest};

	die "unknown node '$nodename'\n" if ! $nodelist->{$nodename};

	foreach my $name (keys %$nodelist) {
	    my $node = $nodelist->{$name};
	    $node->{pve_fp} = PVE::Cluster::get_node_fingerprint($name);
	    $node->{pve_addr} = scalar(PVE::Cluster::remote_node_ip($name));
	}

	my $res = {
	    nodelist => [ values %$nodelist ],
	    preferred_node => $nodename,
	    totem => $totem_cfg,
	    config_digest => $corosync_config_digest,
	};

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'join',
    path => 'join',
    method => 'POST',
    protected => 1,
    description => "Joins this node into an existing cluster.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    hostname => {
		type => 'string',
		description => "Hostname (or IP) of an existing cluster member."
	    },
	    nodeid => get_standard_option('corosync-nodeid'),
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
	    ring0_addr => get_standard_option('corosync-ring0-addr', {
		default => "IP resolved by node's hostname",
	    }),
	    ring1_addr => get_standard_option('corosync-ring1-addr'),
	    fingerprint => get_standard_option('fingerprint-sha256'),
	    password => {
		description => "Superuser (root) password of peer node.",
		type => 'string',
		maxLength => 128,
	    },
	},
    },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $worker = sub {
	    STDOUT->autoflush();
	    PVE::Tools::lock_file($local_cluster_lock, 10, \&PVE::Cluster::join, $param);
	    die $@ if $@;
	};

	return $rpcenv->fork_worker('clusterjoin', $param->{hostname},  $authuser, $worker);
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
