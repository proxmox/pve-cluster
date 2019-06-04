package PVE::CLI::pvecm;

use strict;
use warnings;

use File::Path;
use File::Basename;
use PVE::Tools qw(run_command);
use PVE::Cluster;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RPCEnvironment;
use PVE::CLIHandler;
use PVE::PTY;
use PVE::API2::ClusterConfig;
use PVE::Corosync;

use base qw(PVE::CLIHandler);

$ENV{HOME} = '/root'; # for ssh-copy-id

my $basedir = "/etc/pve";
my $clusterconf = "$basedir/corosync.conf";
my $libdir = "/var/lib/pve-cluster";
my $authfile = "/etc/corosync/authkey";


sub setup_environment {
    PVE::RPCEnvironment->setup_default_cli_env();
}

__PACKAGE__->register_method ({
    name => 'keygen',
    path => 'keygen',
    method => 'PUT',
    description => "Generate new cryptographic key for corosync.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    filename => {
		type => 'string',
		description => "Output file name"
	    }
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	my $filename = $param->{filename};

	# test EUID
	$> == 0 || die "Error: Authorization key must be generated as root user.\n";
	my $dirname = dirname($filename);

	die "key file '$filename' already exists\n" if -e $filename;

	File::Path::make_path($dirname) if $dirname;

	run_command(['corosync-keygen', '-l', '-k', $filename]);

	return undef;
    }});

my $foreach_member = sub {
    my ($code, $noerr) = @_;

    my $members = PVE::Cluster::get_members();
    foreach my $node (sort keys %$members) {
	if (my $ip = $members->{$node}->{ip}) {
	    $code->($node, $ip);
	} else {
	    die "cannot get the cluster IP for node '$node'.\n" if !$noerr;
	    warn "cannot get the cluster IP for node '$node'.\n";
	    return undef;
	}
    }
};

__PACKAGE__->register_method ({
    name => 'setup_qdevice',
    path => 'setup_qdevice',
    method => 'PUT',
    description => "Setup the use of a QDevice",
    parameters => {
        additionalProperties => 0,
	properties => {
	    address => {
		type => 'string', format => 'ip',
		description => "Specifies the network address of an external corosync QDevice" ,
	    },
	    network => {
		type => 'string',
		format => 'CIDR',
		description => 'The network which should be used to connect to the external qdevice',
		optional => 1,
	    },
	    force => {
		type => 'boolean',
		description => "Do not throw error on possible dangerous operations.",
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	die "Node not in a cluster. Aborting.\n"
	    if !PVE::Corosync::check_conf_exists(1);

	my $members = PVE::Cluster::get_members();
	foreach my $node (sort keys %$members) {
	    die "All nodes must be online! Node $node is offline, aborting.\n"
		if !$members->{$node}->{online};
	}

	my $conf = PVE::Cluster::cfs_read_file("corosync.conf");

	die "QDevice already configured!\n"
	    if defined($conf->{main}->{quorum}->{device}) && !$param->{force};

	my $network = $param->{network};

	my $model = "net";
	my $algorithm = 'ffsplit';
	if (scalar($members) & 1) {
	    if ($param->{force}) {
		$algorithm = 'lms';
	    } else {
		die "Clusters with an odd node count are not officially supported!\n";
	    }
	}

	my $qnetd_addr = $param->{address};
	my $base_dir = "/etc/corosync/qdevice/net";
	my $db_dir_qnetd = "/etc/corosync/qnetd/nssdb";
	my $db_dir_node = "$base_dir/nssdb";
	my $ca_export_base = "qnetd-cacert.crt";
	my $ca_export_file = "$db_dir_qnetd/$ca_export_base";
	my $crq_file_base = "qdevice-net-node.crq";
	my $p12_file_base = "qdevice-net-node.p12";
	my $qdevice_certutil = "corosync-qdevice-net-certutil";
	my $qnetd_certutil= "corosync-qnetd-certutil";
	my $clustername = $conf->{main}->{totem}->{cluster_name};

	run_command(['ssh-copy-id', '-i', '/root/.ssh/id_rsa', "root\@$qnetd_addr"]);

	if (-d $db_dir_node) {
	    # FIXME: check on all nodes?!
	    if ($param->{force}) {
		rmtree $db_dir_node;
	    } else {
		die "QDevice certificate store already initialised, set force to delete!\n";
	    }
	}

	my $ssh_cmd = ['ssh', '-o', 'BatchMode=yes', '-lroot'];
	my $scp_cmd = ['scp', '-o', 'BatchMode=yes'];

	print "\nINFO: initializing qnetd server\n";
	run_command(
	    [@$ssh_cmd, $qnetd_addr, $qnetd_certutil, "-i"],
	    noerr => 1
	);

	print "\nINFO: copying CA cert and initializing on all nodes\n";
	run_command([@$scp_cmd, "root\@\[$qnetd_addr\]:$ca_export_file", "/etc/pve/$ca_export_base"]);
	$foreach_member->(sub {
	    my ($node, $ip) = @_;
	    my $outsub = sub { print "\nnode '$node': " . shift };
	    run_command(
		[@$ssh_cmd, $ip, $qdevice_certutil, "-i", "-c", "/etc/pve/$ca_export_base"],
		noerr => 1, outfunc => \&$outsub
	    );
	});
	unlink "/etc/pve/$ca_export_base";

	print "\nINFO: generating cert request\n";
	run_command([$qdevice_certutil, "-r", "-n", $clustername]);

	print "\nINFO: copying exported cert request to qnetd server\n";
	run_command([@$scp_cmd, "$db_dir_node/$crq_file_base", "root\@\[$qnetd_addr\]:/tmp"]);

	print "\nINFO: sign and export cluster cert\n";
	run_command([
		@$ssh_cmd, $qnetd_addr, $qnetd_certutil, "-s", "-c",
		"/tmp/$crq_file_base", "-n", "$clustername"
	    ]);

	print "\nINFO: copy exported CRT\n";
	run_command([
		@$scp_cmd, "root\@\[$qnetd_addr\]:$db_dir_qnetd/cluster-$clustername.crt",
		"$db_dir_node"
	    ]);

	print "\nINFO: import certificate\n";
	run_command(["$qdevice_certutil", "-M", "-c", "$db_dir_node/cluster-$clustername.crt"]);

	print "\nINFO: copy and import pk12 cert to all nodes\n";
	run_command([@$scp_cmd, "$db_dir_node/$p12_file_base", "/etc/pve/"]);
	$foreach_member->(sub {
	    my ($node, $ip) = @_;
	    my $outsub = sub { print "\nnode '$node': " . shift };
	    run_command([
		    @$ssh_cmd, $ip, "$qdevice_certutil", "-m", "-c",
		    "/etc/pve/$p12_file_base"], outfunc => \&$outsub
		);
	});
	unlink "/etc/pve/$p12_file_base";


	my $code = sub {
	    my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
	    my $quorum_section = $conf->{main}->{quorum};

	    die "Qdevice already configured, must be removed before setting up new one!\n"
		if defined($quorum_section->{device}); # must not be forced!

	    my $qdev_section = {
		model => $model,
		"$model" => {
		    tls => 'on',
		    host => $qnetd_addr,
		    algorithm => $algorithm,
		}
	    };
	    $qdev_section->{votes} = 1 if $algorithm eq 'ffsplit';

	    $quorum_section->{device} = $qdev_section;

	    PVE::Corosync::atomic_write_conf($conf);
	};

	print "\nINFO: add QDevice to cluster configuration\n";
	PVE::Cluster::cfs_lock_file('corosync.conf', 10, $code);
	die $@ if $@;

	$foreach_member->(sub {
	    my ($node, $ip) = @_;
	    my $outsub = sub { print "\nnode '$node': " . shift };
	    print "\nINFO: start and enable corosync qdevice daemon on node '$node'...\n";
	    run_command([@$ssh_cmd, $ip, 'systemctl', 'start', 'corosync-qdevice'], outfunc => \&$outsub);
	    run_command([@$ssh_cmd, $ip, 'systemctl', 'enable', 'corosync-qdevice'], outfunc => \&$outsub);
	});

	run_command(['corosync-cfgtool', '-R']); # do cluster wide config reload

	return undef;
}});

__PACKAGE__->register_method ({
    name => 'remove_qdevice',
    path => 'remove_qdevice',
    method => 'DELETE',
    description => "Remove a configured QDevice",
    parameters => {
        additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	die "Node not in a cluster. Aborting.\n"
	    if !PVE::Corosync::check_conf_exists(1);

	my $members = PVE::Cluster::get_members();
	foreach my $node (sort keys %$members) {
	    die "All nodes must be online! Node $node is offline, aborting.\n"
		if !$members->{$node}->{online};
	}

	my $ssh_cmd = ['ssh', '-o', 'BatchMode=yes', '-lroot'];

	my $code = sub {
	    my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
	    my $quorum_section = $conf->{main}->{quorum};

	    die "No QDevice configured!\n" if !defined($quorum_section->{device});

	    delete $quorum_section->{device};

	    PVE::Corosync::atomic_write_conf($conf);

	    # cleanup qdev state (cert storage)
	    my $qdev_state_dir =  "/etc/corosync/qdevice";
	    $foreach_member->(sub {
		my (undef, $ip) = @_;
		run_command([@$ssh_cmd, $ip, '--', 'rm', '-rf', $qdev_state_dir]);
	    });
	};

	PVE::Cluster::cfs_lock_file('corosync.conf', 10, $code);
	die $@ if $@;

	$foreach_member->(sub {
	    my (undef, $ip) = @_;
	    run_command([@$ssh_cmd, $ip, 'systemctl', 'stop', 'corosync-qdevice']);
	    run_command([@$ssh_cmd, $ip, 'systemctl', 'disable', 'corosync-qdevice']);
	});

	run_command(['corosync-cfgtool', '-R']);

	print "\nRemoved Qdevice.\n";

	return undef;
}});

__PACKAGE__->register_method ({
    name => 'add',
    path => 'add',
    method => 'PUT',
    description => "Adds the current node to an existing cluster.",
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
	    ring0_addr => get_standard_option('corosync-ring0-addr'),
	    ring1_addr => get_standard_option('corosync-ring1-addr'),
	    fingerprint => get_standard_option('fingerprint-sha256', {
		optional => 1,
	    }),
	    'use_ssh' => {
		type => 'boolean',
		description => "Always use SSH to join, even if peer may do it over API.",
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	my $nodename = PVE::INotify::nodename();

	my $host = $param->{hostname};
	my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);

	PVE::Cluster::assert_joinable($local_ip_address, $param->{ring0_addr}, $param->{ring1_addr}, $param->{force});

	my $worker = sub {

	    if (!$param->{use_ssh}) {
		print "Please enter superuser (root) password for '$host':\n";
		my $password = PVE::PTY::read_password("Password for root\@$host: ");

		delete $param->{use_ssh};
		$param->{password} = $password;

		my $local_cluster_lock = "/var/lock/pvecm.lock";
		PVE::Tools::lock_file($local_cluster_lock, 10, \&PVE::Cluster::join, $param);

		if (my $err = $@) {
		    if (ref($err) eq 'PVE::APIClient::Exception' && defined($err->{code}) && $err->{code} == 501) {
			$err = "Remote side is not able to use API for Cluster join!\n" .
			       "Pass the 'use_ssh' switch or update the remote side.\n";
		    }
		    die $err;
		}
		return; # all OK, the API join endpoint successfully set us up
	    }

	    # allow fallback to old ssh only join if wished or needed

	    PVE::Cluster::setup_sshd_config();
	    PVE::Cluster::setup_rootsshconfig();
	    PVE::Cluster::setup_ssh_keys();

	    # make sure known_hosts is on local filesystem
	    PVE::Cluster::ssh_unmerge_known_hosts();

	    my $cmd = ['ssh-copy-id', '-i', '/root/.ssh/id_rsa', "root\@$host"];
	    run_command($cmd, 'outfunc' => sub {}, 'errfunc' => sub {},
				    'errmsg' => "unable to copy ssh ID");

	    $cmd = ['ssh', $host, '-o', 'BatchMode=yes',
		    'pvecm', 'addnode', $nodename, '--force', 1];

	    push @$cmd, '--nodeid', $param->{nodeid} if $param->{nodeid};
	    push @$cmd, '--votes', $param->{votes} if defined($param->{votes});
	    push @$cmd, '--ring0_addr', $param->{ring0_addr} // $local_ip_address;
	    push @$cmd, '--ring1_addr', $param->{ring1_addr} if defined($param->{ring1_addr});

	    if (system (@$cmd) != 0) {
		my $cmdtxt = join (' ', @$cmd);
		die "unable to add node: command failed ($cmdtxt)\n";
	    }

	    my $tmpdir = "$libdir/.pvecm_add.tmp.$$";
	    mkdir $tmpdir;

	    eval {
		print "copy corosync auth key\n";
		$cmd = ['rsync', '--rsh=ssh -l root -o BatchMode=yes', '-lpgoq',
			"[$host]:$authfile $clusterconf", $tmpdir];

		system(@$cmd) == 0 || die "can't rsync data from host '$host'\n";

		my $corosync_conf = PVE::Tools::file_get_contents("$tmpdir/corosync.conf");
		my $corosync_authkey = PVE::Tools::file_get_contents("$tmpdir/authkey");

		PVE::Cluster::finish_join($host, $corosync_conf, $corosync_authkey);
	    };
	    my $err = $@;

	    rmtree $tmpdir;

	    die $err if $err;
	};

	# use a synced worker so we get a nice task log when joining through CLI
	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	$rpcenv->fork_worker('clusterjoin', '',  $authuser, $worker);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'status',
    path => 'status',
    method => 'GET',
    description => "Displays the local view of the cluster status.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	PVE::Corosync::check_conf_exists();

	my $cmd = ['corosync-quorumtool', '-siH'];

	exec (@$cmd);

	exit (-1); # should not be reached
    }});

__PACKAGE__->register_method ({
    name => 'nodes',
    path => 'nodes',
    method => 'GET',
    description => "Displays the local view of the cluster nodes.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	PVE::Corosync::check_conf_exists();

	my $cmd = ['corosync-quorumtool', '-l'];

	exec (@$cmd);

	exit (-1); # should not be reached
    }});

__PACKAGE__->register_method ({
    name => 'expected',
    path => 'expected',
    method => 'PUT',
    description => "Tells corosync a new value of expected votes.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    expected => {
		type => 'integer',
		description => "Expected votes",
		minimum => 1,
	    },
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	PVE::Corosync::check_conf_exists();

	my $cmd = ['corosync-quorumtool', '-e', $param->{expected}];

	exec (@$cmd);

	exit (-1); # should not be reached

    }});

__PACKAGE__->register_method ({
    name => 'updatecerts',
    path => 'updatecerts',
    method => 'PUT',
    description => "Update node certificates (and generate all needed files/directories).",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    force => {
		description => "Force generation of new SSL certifate.",
		type => 'boolean',
		optional => 1,
	    },
	    silent => {
		description => "Ignore errors (i.e. when cluster has no quorum).",
		type => 'boolean',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	# we get called by the pve-cluster.service ExecStartPost and as we do
	# IO (on /etc/pve) which can hang (uninterruptedly D state). That'd be
	# no-good for ExecStartPost as it fails the whole service in this case
	PVE::Tools::run_fork_with_timeout(30, sub {
	    PVE::Cluster::updatecerts_and_ssh($param->@{qw(force silent)});
	});

	return undef;
    }});

our $cmddef = {
    keygen => [ __PACKAGE__, 'keygen', ['filename']],
    create => [ 'PVE::API2::ClusterConfig', 'create', ['clustername']],
    add => [ __PACKAGE__, 'add', ['hostname']],
    addnode => [ 'PVE::API2::ClusterConfig', 'addnode', ['node']],
    delnode => [ 'PVE::API2::ClusterConfig', 'delnode', ['node']],
    status => [ __PACKAGE__, 'status' ],
    nodes => [ __PACKAGE__, 'nodes' ],
    expected => [ __PACKAGE__, 'expected', ['expected']],
    updatecerts => [ __PACKAGE__, 'updatecerts', []],
    qdevice => {
	setup => [ __PACKAGE__, 'setup_qdevice', ['address']],
	remove => [ __PACKAGE__, 'remove_qdevice', []],
    }
};

1;
