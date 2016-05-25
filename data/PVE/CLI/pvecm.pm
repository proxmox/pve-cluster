package PVE::CLI::pvecm;

use strict;
use warnings;
use Getopt::Long;
use Socket;
use IO::File;
use Net::IP;
use File::Path;
use File::Basename;
use Data::Dumper; # fixme: remove 
use PVE::Tools;
use PVE::Cluster;
use PVE::INotify;
use PVE::JSONSchema;
use PVE::CLIHandler;

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
    my $cmd = "echo '.dump' |";
    $cmd .= "sqlite3 '$dbfile' |";
    $cmd .= "gzip - >'${backupdir}/config-${ctime}.sql.gz'";

    system($cmd) == 0 ||
	die "can't backup old database: $!\n";

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
	my $basename = basename($filename);

	die "key file '$filename' already exists\n" if -e $filename;

	File::Path::make_path($dirname) if $dirname;

	my $cmd = ['corosync-keygen', '-l', '-k', $filename];
	PVE::Tools::run_command($cmd);   

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
	    rrp_mode => {
		type => 'string',
		enum => ['none', 'active', 'passive'],
		description => "This specifies the mode of redundant ring, which" .
		    " may be none, active or passive. Using multiple interfaces".
		    " only allows 'active' or 'passive'.",
		default => 'none',
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

	PVE::Cluster::setup_sshd_config();
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

	    die "rrp_mode 'none' is not allowed when using multiple interfaces,".
		" use 'active' or 'passive'!\n"
		if !$param->{rrp_mode} || $param->{rrp_mode} eq 'none';

	    $interfaces .= "\n  interface {\n    ringnumber: 1\n" .
		"    bindnetaddr: $param->{bindnet1_addr}\n  }\n";

	    $ring_addresses .= "\n    ring1_addr: $param->{ring1_addr}";

	} elsif($param->{rrp_mode} && $param->{rrp_mode} ne 'none') {

	    warn "rrp_mode '$param->{rrp_mode}' useless when using only one".
		" ring, using 'none' instead";
	    # corosync defaults to none if only one interface is configured
	    $param->{rrp_mode} = undef;

	}

	$interfaces = "rrp_mode: $param->{rrp_mode}\n  " . $interfaces
	    if $param->{rrp_mode};

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

	PVE::Tools::run_command('systemctl restart pve-cluster'); # restart

	PVE::Tools::run_command('systemctl restart corosync'); # restart
	
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

	PVE::Cluster::check_cfs_quorum();

	my $conf = PVE::Cluster::cfs_read_file("corosync.conf");

	my $nodelist = corosync_nodelist($conf);

	my $totem_cfg = corosync_totem_config($conf);

	my $name = $param->{node};

	$param->{ring0_addr} = $name if !$param->{ring0_addr};

	die " ring1_addr needs a configured ring 1 interface!\n"
	    if $param->{ring1_addr} && !defined($totem_cfg->{interface}->{1});

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
	
	corosync_update_nodelist($conf, $nodelist);
	
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
	    node => PVE::JSONSchema::get_standard_option('pve-node'),
	},
    },
    returns => { type => 'null' },
    
    code => sub {
	my ($param) = @_;

	PVE::Cluster::check_cfs_quorum();

	my $conf = PVE::Cluster::cfs_read_file("corosync.conf");

	my $nodelist = corosync_nodelist($conf);

	my $nd = delete $nodelist->{$param->{node}};
	die "no such node '$param->{node}'\n" if !$nd;
	
	corosync_update_nodelist($conf, $nodelist);

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

	if (!$param->{force}) {
	    
	    if (-f $authfile) {
		die "authentication key already exists\n";
	    }

	    if (-f $clusterconf)  {
		die "cluster config '$clusterconf' already exists\n";
	    }

	    my $vmlist = PVE::Cluster::get_vmlist();
	    if ($vmlist && $vmlist->{ids} && scalar(keys %{$vmlist->{ids}})) {
		die "this host already contains virtual machines - please remove them first\n";
	    }

	    if (system("corosync-quorumtool >/dev/null 2>&1") == 0) {
		die "corosync is already running\n";
	    }
	}

	# make sure known_hosts is on local filesystem
	PVE::Cluster::ssh_unmerge_known_hosts();

	my $cmd = "ssh-copy-id -i /root/.ssh/id_rsa 'root\@$host' >/dev/null 2>&1";
	system ($cmd) == 0 ||
	    die "unable to copy ssh ID\n";

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

	    # system("systemctl start clvm");

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

	PVE::Cluster::check_corosync_conf_exists();

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

	PVE::Cluster::check_corosync_conf_exists();

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

	PVE::Cluster::check_corosync_conf_exists();

	my $cmd = ['corosync-quorumtool', '-e', $param->{expected}];

	exec (@$cmd);

	exit (-1); # should not be reached

    }});

sub corosync_update_nodelist {
    my ($conf, $nodelist) = @_;

    delete $conf->{digest};
    
    my $version = PVE::Cluster::corosync_conf_version($conf);
    PVE::Cluster::corosync_conf_version($conf, undef, $version + 1);

    my $children = [];
    foreach my $v (values %$nodelist) {
	next if !($v->{ring0_addr} || $v->{name});
	my $kv = [];
	foreach my $k (keys %$v) {
	    push @$kv, { key => $k, value => $v->{$k} };
	} 
	my $ns = { section => 'node', children => $kv };
	push @$children, $ns;
    }
    
    foreach my $main (@{$conf->{children}}) {
	next if !defined($main->{section});
	if ($main->{section} eq 'nodelist') {
	    $main->{children} = $children;
	    last;
	}
    }

    
    PVE::Cluster::cfs_write_file("corosync.conf.new", $conf);
    
    rename("/etc/pve/corosync.conf.new", "/etc/pve/corosync.conf")
	|| die "activate  corosync.conf.new failed - $!\n";
}

sub corosync_nodelist {
    my ($conf) = @_;

    my $nodelist = {};

    foreach my $main (@{$conf->{children}}) {
	next if !defined($main->{section});
	if ($main->{section} eq 'nodelist') {
	    foreach my $ne (@{$main->{children}}) {
		next if !defined($ne->{section}) || ($ne->{section} ne 'node');
		my $node = { quorum_votes => 1 };
		my $name;
		foreach my $child (@{$ne->{children}}) {
		    next if !defined($child->{key});
		    $node->{$child->{key}} = $child->{value};
		    # use 'name' over 'ring0_addr' if set
		    if ($child->{key} eq 'name') {
			delete $nodelist->{$name} if $name;
			$name = $child->{value};
			$nodelist->{$name} = $node;
		    } elsif(!$name && $child->{key} eq 'ring0_addr') {
			$name = $child->{value};
			$nodelist->{$name} = $node;
		    }
		}
	    }
	}
    }   

    return $nodelist;
}

# get a hash representation of the corosync config totem section
sub corosync_totem_config {
    my ($conf) = @_;

    my $res = {};

    foreach my $main (@{$conf->{children}}) {
	next if !defined($main->{section}) ||
	    $main->{section} ne 'totem';

	foreach my $e (@{$main->{children}}) {

	    if ($e->{section} && $e->{section} eq 'interface') {
		my $entry = {};

		$res->{interface} = {};

		foreach my $child (@{$e->{children}}) {
		    next if !defined($child->{key});
		    $entry->{$child->{key}} = $child->{value};
		    if($child->{key} eq 'ringnumber') {
			$res->{interface}->{$child->{value}} = $entry;
		    }
		}

	    } elsif  ($e->{key}) {
		$res->{$e->{key}} = $e->{value};
	    }
	}
    }

    return $res;
}

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
};

1;
