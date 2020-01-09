package PVE::API2::ClusterConfig;

use strict;
use warnings;

use PVE::Exception;
use PVE::Tools;
use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster;
use PVE::APIClient::LWP;
use PVE::Corosync;
use PVE::Cluster::Setup;

use IO::Socket::UNIX;

use base qw(PVE::RESTHandler);

my $clusterconf = "/etc/pve/corosync.conf";
my $authfile = "/etc/corosync/authkey";
my $local_cluster_lock = "/var/lock/pvecm.lock";

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
	    { name => 'qdevice' },
	];

	return $result;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    path => '',
    method => 'POST',
    protected => 1,
    description => "Generate new cluster configuration. If no links given,"
		 . " default to local IP address as link0.",
    parameters => {
	additionalProperties => 0,
	properties => PVE::Corosync::add_corosync_link_properties({
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
	}),
    },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	-f $clusterconf && die "cluster config '$clusterconf' already exists\n";

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $code = sub {
	    STDOUT->autoflush();
	    PVE::Cluster::Setup::setup_sshd_config(1);
	    PVE::Cluster::Setup::setup_rootsshconfig();
	    PVE::Cluster::Setup::setup_ssh_keys();

	    PVE::Tools::run_command(['/usr/sbin/corosync-keygen', '-lk', $authfile])
		if !-f $authfile;
	    die "no authentication key available\n" if -f !$authfile;

	    my $nodename = PVE::INotify::nodename();

	    # get the corosync basis config for the new cluster
	    my $config = PVE::Corosync::create_conf($nodename, $param);

	    print "Writing corosync config to /etc/pve/corosync.conf\n";
	    PVE::Corosync::atomic_write_conf($config);

	    my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);
	    PVE::Cluster::Setup::ssh_merge_keys();
	    PVE::Cluster::Setup::gen_pve_node_files($nodename, $local_ip_address);
	    PVE::Cluster::Setup::ssh_merge_known_hosts($nodename, $local_ip_address, 1);

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
	    my $res = PVE::Cluster::cfs_lock_file('corosync.conf', 10, $code);

	    # cfs_lock_file only sets $@ but lock_file doesn't propagates $@ unless we die here
	    die $@ if defined($@);

	    return $res;
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
    description => "Adds a node to the cluster configuration. This call is for internal use.",
    parameters => {
	additionalProperties => 0,
	properties => PVE::Corosync::add_corosync_link_properties({
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
	    new_node_ip => {
		type => 'string',
		description => "IP Address of node to add. Used as fallback if no links are given.",
		format => 'ip',
		optional => 1,
	    },
	}),
    },
    returns => {
	type => "object",
	properties => {
	    corosync_authkey => {
		type => 'string',
	    },
	    corosync_conf => {
		type => 'string',
	    },
	    warnings => {
		type => 'array',
		items => {
		    type => 'string',
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	PVE::Cluster::check_cfs_quorum();

	my $vc_errors;
	my $vc_warnings;

	my $code = sub {
	    my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
	    my $nodelist = PVE::Corosync::nodelist($conf);
	    my $totem_cfg = PVE::Corosync::totem_config($conf);

	    ($vc_errors, $vc_warnings) = PVE::Corosync::verify_conf($conf);
	    die if scalar(@$vc_errors);

	    my $name = $param->{node};

	    # ensure we do not reuse an address, that can crash the whole cluster!
	    my $check_duplicate_addr = sub {
		my $link = shift;
		return if !defined($link) || !defined($link->{address});
		my $addr = $link->{address};

		while (my ($k, $v) = each %$nodelist) {
		    next if $k eq $name; # allows re-adding a node if force is set

		    for my $linknumber (0..PVE::Corosync::MAX_LINK_INDEX) {
			my $id = "ring${linknumber}_addr";
			next if !defined($v->{$id});

			die "corosync: address '$addr' already used on link $id by node '$k'\n"
			    if $v->{$id} eq $addr;
		    }
		}
	    };

	    my $links = PVE::Corosync::extract_corosync_link_args($param);
	    foreach my $link (values %$links) {
		$check_duplicate_addr->($link);
	    }

	    # Make sure that the newly added node has links compatible with the
	    # rest of the cluster. To start, extract all links that currently
	    # exist. Check any node, all have the same links here (because of
	    # verify_conf above).
	    my $node_options = (values %$nodelist)[0];
	    my $cluster_links = {};
	    foreach my $opt (keys %$node_options) {
		my ($linktype, $linkid) = PVE::Corosync::parse_link_entry($opt);
		next if !defined($linktype);
		$cluster_links->{$linkid} = $node_options->{$opt};
	    }

	    # in case no fallback IP was passed, but instead only a single link,
	    # treat it as fallback to allow link-IDs to be matched automatically
	    # FIXME: remove in 8.0 or when joining an old node not supporting
	    # new_node_ip becomes infeasible otherwise
	    my $legacy_fallback = 0;
	    if (!$param->{new_node_ip} && scalar(%$links) == 1) {
		my $passed_link_id = (keys %$links)[0];
		my $passed_link = delete $links->{$passed_link_id};
		$param->{new_node_ip} = $passed_link->{address};
		$legacy_fallback = 1;
	    }

	    if (scalar(%$links)) {
		# verify specified links exist and none are missing
		for my $linknum (0..PVE::Corosync::MAX_LINK_INDEX) {
		    my $have_cluster_link = defined($cluster_links->{$linknum});
		    my $have_new_link = defined($links->{$linknum});

		    die "corosync: link $linknum exists in cluster config but wasn't specified for new node\n"
			if $have_cluster_link && !$have_new_link;
		    die "corosync: link $linknum specified for new node doesn't exist in cluster config\n"
			if !$have_cluster_link && $have_new_link;
		}
	    } else {
		# when called without any link parameters, fall back to
		# new_node_ip, if all existing nodes only have a single link too
		die "no links and no fallback ip (new_node_ip) given, cannot join cluster\n"
		    if !$param->{new_node_ip};

		my $cluster_link_count = scalar(%$cluster_links);
		if ($cluster_link_count == 1) {
		    my $linknum = (keys %$cluster_links)[0];
		    $links->{$linknum} = { address => $param->{new_node_ip} };
		} else {
		    die "cluster has $cluster_link_count links, but only 1 given"
			if $legacy_fallback;
		    die "no links given but multiple links found on other nodes,"
		      . " fallback only supported on single-link clusters\n";
		}
	    }

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

	    PVE::Cluster::Setup::gen_local_dirs($name);

	    eval { PVE::Cluster::Setup::ssh_merge_keys(); };
	    warn $@ if $@;

	    $nodelist->{$name} = {
		nodeid => $param->{nodeid},
		name => $name,
	    };
	    $nodelist->{$name}->{quorum_votes} = $param->{votes} if $param->{votes};

	    foreach my $link (keys %$links) {
		$nodelist->{$name}->{"ring${link}_addr"} = $links->{$link}->{address};
	    }

	    PVE::Cluster::log_msg('notice', 'root@pam', "adding node $name to cluster");

	    PVE::Corosync::update_nodelist($conf, $nodelist);
	};

	$config_change_lock->($code);

	# If vc_errors is set, we died because of verify_conf.
	# Raise this error, since it contains more information than just a
	# single-line string.
	if (defined($vc_errors) && scalar(@$vc_errors)) {
	    my $err_hash = {};
	    my $add_errs = sub {
		my $type = shift;
		my @arr = @_;
		return if !scalar(@arr);

		my %newhash = map { $type . $_ => $arr[$_] } 0..$#arr;
		$err_hash = {
		    %$err_hash,
		    %newhash,
		};
	    };

	    $add_errs->("warning", @$vc_warnings);
	    $add_errs->("error", @$vc_errors);

	    PVE::Exception::raise("invalid corosync.conf\n", errors => $err_hash);
	}

	die $@ if $@;

	my $res = {
	    corosync_authkey => PVE::Tools::file_get_contents($authfile),
	    corosync_conf => PVE::Tools::file_get_contents($clusterconf),
	    warnings => $vc_warnings,
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
			ring0_addr => get_standard_option('corosync-link'),
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
    description => "Joins this node into an existing cluster. If no links are"
		 . " given, default to IP resolved by node's hostname on single"
		 . " link (fallback fails for clusters with multiple links).",
    parameters => {
	additionalProperties => 0,
	properties => PVE::Corosync::add_corosync_link_properties({
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
	    fingerprint => get_standard_option('fingerprint-sha256'),
	    password => {
		description => "Superuser (root) password of peer node.",
		type => 'string',
		maxLength => 128,
	    },
	}),
    },
    returns => { type => 'string' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $worker = sub {
	    STDOUT->autoflush();
	    PVE::Tools::lock_file($local_cluster_lock, 10, \&PVE::Cluster::Setup::join, $param);
	    die $@ if $@;
	};

	return $rpcenv->fork_worker('clusterjoin', undef,  $authuser, $worker);
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

__PACKAGE__->register_method ({
    name => 'status',
    path => 'qdevice',
    method => 'GET',
    description => 'Get QDevice status',
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => "object",
    },
    code => sub {
	my ($param) = @_;

	my $result = {};
	my $socket_path = "/var/run/corosync-qdevice/corosync-qdevice.sock";
	return $result if !-S $socket_path;

	my $qdevice_socket = IO::Socket::UNIX->new(
	    Type => SOCK_STREAM,
	    Peer => $socket_path,
	);

	print $qdevice_socket "status verbose\n";
	my $qdevice_keys = {
	    "Algorithm" => 1,
	    "Echo reply" => 1,
	    "Last poll call" => 1,
	    "Model" => 1,
	    "QNetd host" => 1,
	    "State" => 1,
	    "Tie-breaker" => 1,
	};
	while (my $line = <$qdevice_socket>) {
	    chomp $line;
	    next if $line =~ /^\s/;
	    if ($line =~ /^(.*?)\s*:\s*(.*)$/) {
		$result->{$1} = $2 if $qdevice_keys->{$1};
	    }
	}

	return $result;
    }});
#TODO: possibly add setup and remove methods


1;
