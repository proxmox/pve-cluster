package PVE::CLI::pvecm;

use strict;
use warnings;

use Net::IP;
use File::Path;
use File::Basename;
use PVE::Tools qw(run_command);
use PVE::Cluster;
use PVE::INotify;
use PVE::JSONSchema;
use PVE::CLIHandler;
use PVE::Corosync;

use base qw(PVE::CLIHandler);

$ENV{HOME} = '/root'; # for ssh-copy-id

my $basedir = "/etc/pve";
my $clusterconf = "$basedir/corosync.conf";
my $libdir = "/var/lib/pve-cluster";
my $backupdir = "/var/lib/pve-cluster/backup";
my $dbfile = "$libdir/config.db";
my $authfile = "/etc/corosync/authkey";

sub backup_database {

    print "backup old database\n";

    mkdir $backupdir;

    my $ctime = time();
    my $cmd = [
	['echo', '.dump'],
	['sqlite3', $dbfile],
	['gzip', '-', \ ">${backupdir}/config-${ctime}.sql.gz"],
    ];

    run_command($cmd, 'errmsg' => "cannot backup old database\n");

    # purge older backup
    my $maxfiles = 10;

    my @bklist = ();
    foreach my $fn (<$backupdir/config-*.sql.gz>) {
	if ($fn =~ m!/config-(\d+)\.sql.gz$!) {
	    push @bklist, [$fn, $1];
	}
    }

    @bklist = sort { $b->[1] <=> $a->[1] } @bklist;

    while (scalar (@bklist) >= $maxfiles) {
	my $d = pop @bklist;
	print "delete old backup '$d->[0]'\n";
	unlink $d->[0];
    }
}

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
    name => 'create',
    path => 'create',
    method => 'PUT',
    description => "Generate new cluster configuration.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    clustername => {
		description => "The name of the cluster.",
		type => 'string', format => 'pve-node',
		maxLength => 15,
	    },
	    nodeid => {
		type => 'integer',
		description => "Node id for this node.",
		minimum => 1,
		optional => 1,
	    },
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
	    ring0_addr => {
		type => 'string', format => 'address',
		description => "Hostname (or IP) of the corosync ring0 address of this node.".
		    " Defaults to the hostname of the node.",
		optional => 1,
	    },
	    bindnet1_addr => {
		type => 'string', format => 'ip',
		description => "This specifies the network address the corosync ring 1".
		    " executive should bind to and is optional.",
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
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	-f $clusterconf && die "cluster config '$clusterconf' already exists\n";

	PVE::Cluster::setup_sshd_config(1);
	PVE::Cluster::setup_rootsshconfig();
	PVE::Cluster::setup_ssh_keys();

	-f $authfile || __PACKAGE__->keygen({filename => $authfile});

	-f $authfile || die "no authentication key available\n";

	my $clustername = $param->{clustername};

	$param->{nodeid} = 1 if !$param->{nodeid};

	$param->{votes} = 1 if !defined($param->{votes});

	my $nodename = PVE::INotify::nodename();

	my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);

	$param->{bindnet0_addr} = $local_ip_address
	    if !defined($param->{bindnet0_addr});

	$param->{ring0_addr} = $nodename if !defined($param->{ring0_addr});

	die "Param bindnet1_addr and ring1_addr are dependend, use both or none!\n"
	    if (defined($param->{bindnet1_addr}) != defined($param->{ring1_addr}));

	my $bind_is_ipv6 = Net::IP::ip_is_ipv6($param->{bindnet0_addr});

	# use string as here-doc format distracts more
	my $interfaces = "interface {\n    ringnumber: 0\n" .
	    "    bindnetaddr: $param->{bindnet0_addr}\n  }";

	my $ring_addresses = "ring0_addr: $param->{ring0_addr}" ;

	# allow use of multiple rings (rrp) at cluster creation time
	if ($param->{bindnet1_addr}) {
	    die "IPv6 and IPv4 cannot be mixed, use one or the other!\n"
		if Net::IP::ip_is_ipv6($param->{bindnet1_addr}) != $bind_is_ipv6;

	    $interfaces .= "\n  interface {\n    ringnumber: 1\n" .
		"    bindnetaddr: $param->{bindnet1_addr}\n  }\n";

	    $interfaces .= "rrp_mode: passive\n"; # only passive is stable and tested

	    $ring_addresses .= "\n    ring1_addr: $param->{ring1_addr}";
	}

	# No, corosync cannot deduce this on its own
	my $ipversion = $bind_is_ipv6 ? 'ipv6' : 'ipv4';

	my $config = <<_EOD;
totem {
  version: 2
  secauth: on
  cluster_name: $clustername
  config_version: 1
  ip_version: $ipversion
  $interfaces
}

nodelist {
  node {
    $ring_addresses
    name: $nodename
    nodeid: $param->{nodeid}
    quorum_votes: $param->{votes}
  }
}

quorum {
  provider: corosync_votequorum
}

logging {
  to_syslog: yes
  debug: off
}
_EOD
;
	PVE::Tools::file_set_contents($clusterconf, $config);

	PVE::Cluster::ssh_merge_keys();

	PVE::Cluster::gen_pve_node_files($nodename, $local_ip_address);

	PVE::Cluster::ssh_merge_known_hosts($nodename, $local_ip_address, 1);

	run_command('systemctl restart pve-cluster'); # restart

	run_command('systemctl restart corosync'); # restart

	return undef;
}});

__PACKAGE__->register_method ({
    name => 'addnode',
    path => 'addnode',
    method => 'PUT',
    description => "Adds a node to the cluster configuration.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => PVE::JSONSchema::get_standard_option('pve-node'),
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
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	if (!$param->{force} && (-t STDIN || -t STDOUT)) {
	    die "error: `addnode` should not get called interactively!\nUse ".
		"`pvecm add <cluster-node>` to add a node to a cluster!\n";
	}

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
		    $res->{nodeid} == $param->{nodeid}) {
		    print "node $name already defined\n";
		    if ($param->{force}) {
			exit (0);
		    } else {
			exit (-1);
		    }
		} else {
		    die "can't add existing node\n";
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

	    eval { 	PVE::Cluster::ssh_merge_keys(); };
	    warn $@ if $@;

	    $nodelist->{$name} = {
		ring0_addr => $param->{ring0_addr},
		nodeid => $param->{nodeid},
		name => $name,
	    };
	    $nodelist->{$name}->{ring1_addr} = $param->{ring1_addr} if $param->{ring1_addr};
	    $nodelist->{$name}->{quorum_votes} = $param->{votes} if $param->{votes};

	    PVE::Corosync::update_nodelist($conf, $nodelist);
	};

	$config_change_lock->($code);
	die $@ if $@;

	exit (0);
    }});


__PACKAGE__->register_method ({
    name => 'delnode',
    path => 'delnode',
    method => 'PUT',
    description => "Removes a node to the cluster configuration.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => {
		type => 'string',
		description => "Hostname or IP of the corosync ring0 address of this node.",
	    },
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

	    delete $nodelist->{$node};

	    PVE::Corosync::update_nodelist($conf, $nodelist);

	    run_command(['corosync-cfgtool','-k', $nodeid]) if defined($nodeid);
	};

	$config_change_lock->($code);
	die $@ if $@;

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
		    " needs an valid configured ring 1 interface in the cluster.",
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	my $nodename = PVE::INotify::nodename();

	PVE::Cluster::setup_sshd_config();
	PVE::Cluster::setup_rootsshconfig();
	PVE::Cluster::setup_ssh_keys();

	my $host = $param->{hostname};

	my ($errors, $warnings) = ('', '');

	my $error = sub {
	    my ($msg, $suppress) = @_;

	    if ($suppress) {
		$warnings .= "* $msg\n";
	    } else {
		$errors .= "* $msg\n";
	    }
	};

	if (!$param->{force}) {

	    if (-f $authfile) {
		&$error("authentication key '$authfile' already exists", $param->{force});
	    }

	    if (-f $clusterconf)  {
		&$error("cluster config '$clusterconf' already exists", $param->{force});
	    }

	    my $vmlist = PVE::Cluster::get_vmlist();
	    if ($vmlist && $vmlist->{ids} && scalar(keys %{$vmlist->{ids}})) {
		&$error("this host already contains virtual guests", $param->{force});
	    }

	    if (system("corosync-quorumtool -l >/dev/null 2>&1") == 0) {
		&$error("corosync is already running, is this node already in a cluster?!", $param->{force});
	    }
	}

	# check if corosync ring IPs are configured on the current nodes interfaces
	my $check_ip = sub {
	    my $ip = shift;
	    if (defined($ip)) {
		if (!PVE::JSONSchema::pve_verify_ip($ip, 1)) {
		    my $host = $ip;
		    eval { $ip = PVE::Network::get_ip_from_hostname($host); };
		    if ($@) {
			&$error("cannot use '$host': $@\n") ;
			return;
		    }
		}

		my $cidr = (Net::IP::ip_is_ipv6($ip)) ? "$ip/128" : "$ip/32";
		my $configured_ips = PVE::Network::get_local_ip_from_cidr($cidr);

		&$error("cannot use IP '$ip', it must be configured exactly once on local node!\n")
		    if (scalar(@$configured_ips) != 1);
	    }
	};

	&$check_ip($param->{ring0_addr});
	&$check_ip($param->{ring1_addr});

	warn "warning, ignore the following errors:\n$warnings" if $warnings;
	die "detected the following error(s):\n$errors" if $errors;

	# make sure known_hosts is on local filesystem
	PVE::Cluster::ssh_unmerge_known_hosts();

	my $cmd = ['ssh-copy-id', '-i', '/root/.ssh/id_rsa', "root\@$host"];
	run_command($cmd, 'outfunc' => sub {}, 'errfunc' => sub {},
				'errmsg' => "unable to copy ssh ID");

	$cmd = ['ssh', $host, '-o', 'BatchMode=yes',
		'pvecm', 'addnode', $nodename, '--force', 1];

	push @$cmd, '--nodeid', $param->{nodeid} if $param->{nodeid};

	push @$cmd, '--votes', $param->{votes} if defined($param->{votes});

	push @$cmd, '--ring0_addr', $param->{ring0_addr} if defined($param->{ring0_addr});

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

	    mkdir "/etc/corosync";
	    my $confbase = basename($clusterconf);

	    $cmd = "cp '$tmpdir/$confbase' '/etc/corosync/$confbase'";
	    system($cmd) == 0 || die "can't copy cluster configuration\n";

	    my $keybase = basename($authfile);
	    system ("cp '$tmpdir/$keybase' '$authfile'") == 0 ||
		die "can't copy '$tmpdir/$keybase' to '$authfile'\n";

	    print "stopping pve-cluster service\n";

	    system("umount $basedir -f >/dev/null 2>&1");
	    system("systemctl stop pve-cluster") == 0 ||
		die "can't stop pve-cluster service\n";

	    backup_database();

	    unlink $dbfile;

	    system("systemctl start pve-cluster") == 0 ||
		die "starting pve-cluster failed\n";

	    system("systemctl start corosync");

	    # wait for quorum
	    my $printqmsg = 1;
	    while (!PVE::Cluster::check_cfs_quorum(1)) {
		if ($printqmsg) {
		    print "waiting for quorum...";
		    STDOUT->flush();
		    $printqmsg = 0;
		}
		sleep(1);
	    }
	    print "OK\n" if !$printqmsg;

	    my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);

	    print "generating node certificates\n";
	    PVE::Cluster::gen_pve_node_files($nodename, $local_ip_address);

	    print "merge known_hosts file\n";
	    PVE::Cluster::ssh_merge_known_hosts($nodename, $local_ip_address, 1);

	    print "restart services\n";
	    # restart pvedaemon (changed certs)
	    system("systemctl restart pvedaemon");
	    # restart pveproxy (changed certs)
	    system("systemctl restart pveproxy");

	    print "successfully added node '$nodename' to cluster.\n";
	};
	my $err = $@;

	rmtree $tmpdir;

	die $err if $err;

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

	PVE::Cluster::setup_rootsshconfig();

	PVE::Cluster::gen_pve_vzdump_symlink();

	if (!PVE::Cluster::check_cfs_quorum(1)) {
	    return undef if $param->{silent};
	    die "no quorum - unable to update files\n";
	}

	PVE::Cluster::setup_ssh_keys();

	my $nodename = PVE::INotify::nodename();

	my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);

	PVE::Cluster::gen_pve_node_files($nodename, $local_ip_address, $param->{force});
	PVE::Cluster::ssh_merge_keys();
	PVE::Cluster::ssh_merge_known_hosts($nodename, $local_ip_address);
	PVE::Cluster::gen_pve_vzdump_files();

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
    create => [ __PACKAGE__, 'create', ['clustername']],
    add => [ __PACKAGE__, 'add', ['hostname']],
    addnode => [ __PACKAGE__, 'addnode', ['node']],
    delnode => [ __PACKAGE__, 'delnode', ['node']],
    status => [ __PACKAGE__, 'status' ],
    nodes => [ __PACKAGE__, 'nodes' ],
    expected => [ __PACKAGE__, 'expected', ['expected']],
    updatecerts => [ __PACKAGE__, 'updatecerts', []],
    mtunnel => [ __PACKAGE__, 'mtunnel', ['extra-args']],
};

1;
