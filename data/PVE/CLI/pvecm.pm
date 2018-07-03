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

	PVE::Cluster::assert_joinable($param->{ring0_addr}, $param->{ring1_addr}, $param->{force});

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

__PACKAGE__->register_method ({
    name => 'mtunnel',
    path => 'mtunnel',
    method => 'POST',
    description => "Used by VM/CT migration - do not use manually.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    get_migration_ip => {
		type => 'boolean',
		default => 0,
		description => 'return the migration IP, if configured',
		optional => 1,
	    },
	    migration_network => {
		type => 'string',
		format => 'CIDR',
		description => 'the migration network used to detect the local migration IP',
		optional => 1,
	    },
	    'run-command' => {
		type => 'boolean',
		description => 'Run a command with a tcp socket as standard input.'
		              .' The IP address and port are printed via this'
			      ." command's stdandard output first, each on a separate line.",
		optional => 1,
	    },
	    'extra-args' => PVE::JSONSchema::get_standard_option('extra-args'),
	},
    },
    returns => { type => 'null'},
    code => sub {
	my ($param) = @_;

	if (!PVE::Cluster::check_cfs_quorum(1)) {
	    print "no quorum\n";
	    return undef;
	}

	my $network = $param->{migration_network};
	if ($param->{get_migration_ip}) {
	    die "cannot use --run-command with --get_migration_ip\n"
		if $param->{'run-command'};
	    if (my $ip = PVE::Cluster::get_local_migration_ip($network)) {
		print "ip: '$ip'\n";
	    } else {
		print "no ip\n";
	    }
	    # do not keep tunnel open when asked for migration ip
	    return undef;
	}

	if ($param->{'run-command'}) {
	    my $cmd = $param->{'extra-args'};
	    die "missing command\n"
		if !$cmd || !scalar(@$cmd);

	    # Get an ip address to listen on, and find a free migration port
	    my ($ip, $family);
	    if (defined($network)) {
		$ip = PVE::Cluster::get_local_migration_ip($network)
		    or die "failed to get migration IP address to listen on\n";
		$family = PVE::Tools::get_host_address_family($ip);
	    } else {
		my $nodename = PVE::INotify::nodename();
		($ip, $family) = PVE::Network::get_ip_from_hostname($nodename, 0);
	    }
	    my $port = PVE::Tools::next_migrate_port($family, $ip);

	    PVE::Tools::pipe_socket_to_command($cmd, $ip, $port);
	    return undef;
	}

	print "tunnel online\n";
	*STDOUT->flush();

	while (my $line = <STDIN>) {
	    chomp $line;
	    last if $line =~ m/^quit$/;
	}

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
    mtunnel => [ __PACKAGE__, 'mtunnel', ['extra-args']],
};

1;
