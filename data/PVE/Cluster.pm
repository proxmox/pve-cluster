package PVE::Cluster;

use strict;
use warnings;

use Encode;
use File::stat qw();
use JSON;
use Net::SSLeay;
use POSIX qw(ENOENT);
use Socket;
use Storable qw(dclone);

use PVE::Certificate;
use PVE::INotify;
use PVE::IPCC;
use PVE::JSONSchema;
use PVE::Network;
use PVE::SafeSyslog;
use PVE::Tools qw(run_command);

use PVE::Cluster::IPCConst;

use base 'Exporter';

our @EXPORT_OK = qw(
cfs_read_file
cfs_write_file
cfs_register_file
cfs_lock_file);

# x509 certificate utils

my $basedir = "/etc/pve";
my $authdir = "$basedir/priv";
my $lockdir = "/etc/pve/priv/lock";

# cfs and corosync files
my $dbfile = "/var/lib/pve-cluster/config.db";
my $dbbackupdir = "/var/lib/pve-cluster/backup";

# this is just a readonly copy, the relevant one is in status.c from pmxcfs
# observed files are the one we can get directly through IPCC, they are cached
# using a computed version and only those can be used by the cfs_*_file methods
my $observed = {
    'vzdump.cron' => 1,
    'storage.cfg' => 1,
    'datacenter.cfg' => 1,
    'replication.cfg' => 1,
    'corosync.conf' => 1,
    'corosync.conf.new' => 1,
    'user.cfg' => 1,
    'domains.cfg' => 1,
    'priv/shadow.cfg' => 1,
    'priv/tfa.cfg' => 1,
    '/qemu-server/' => 1,
    '/openvz/' => 1,
    '/lxc/' => 1,
    'ha/crm_commands' => 1,
    'ha/manager_status' => 1,
    'ha/resources.cfg' => 1,
    'ha/groups.cfg' => 1,
    'ha/fence.cfg' => 1,
    'status.cfg' => 1,
    'ceph.conf' => 1,
    'sdn.cfg' => 1,
    'sdn.cfg.new' => 1,
};

sub base_dir {
    return $basedir;
}

sub auth_dir {
    return $authdir;
}

sub check_cfs_quorum {
    my ($noerr) = @_;

    # note: -w filename always return 1 for root, so wee need
    # to use File::lstat here
    my $st = File::stat::lstat("$basedir/local");
    my $quorate = ($st && (($st->mode & 0200) != 0));

    die "cluster not ready - no quorum?\n" if !$quorate && !$noerr;

    return $quorate;
}

sub check_cfs_is_mounted {
    my ($noerr) = @_;

    my $res = -l "$basedir/local";

    die "pve configuration filesystem not mounted\n"
	if !$res && !$noerr;

    return $res;
}

my $versions = {};
my $vmlist = {};
my $clinfo = {};

my $ipcc_send_rec = sub {
    my ($msgid, $data) = @_;

    my $res = PVE::IPCC::ipcc_send_rec($msgid, $data);

    die "ipcc_send_rec[$msgid] failed: $!\n" if !defined($res) && ($! != 0);

    return $res;
};

my $ipcc_send_rec_json = sub {
    my ($msgid, $data) = @_;

    my $res = PVE::IPCC::ipcc_send_rec($msgid, $data);

    die "ipcc_send_rec[$msgid] failed: $!\n" if !defined($res) && ($! != 0);

    return decode_json($res);
};

my $ipcc_get_config = sub {
    my ($path) = @_;

    my $bindata = pack "Z*", $path;
    my $res = PVE::IPCC::ipcc_send_rec(CFS_IPC_GET_CONFIG, $bindata);
    if (!defined($res)) {
	if ($! != 0) {
	    return undef if $! == ENOENT;
	    die "$!\n";
	}
	return '';
    }

    return $res;
};

my $ipcc_get_status = sub {
    my ($name, $nodename) = @_;

    my $bindata = pack "Z[256]Z[256]", $name, ($nodename || "");
    return PVE::IPCC::ipcc_send_rec(CFS_IPC_GET_STATUS, $bindata);
};

my $ipcc_remove_status = sub {
    my ($name) = @_;
    # we just omit the data payload, pmxcfs takes this as hint and removes this
    # key from the status hashtable
    my $bindata = pack "Z[256]", $name;
    return &$ipcc_send_rec(CFS_IPC_SET_STATUS, $bindata);
};

my $ipcc_update_status = sub {
    my ($name, $data) = @_;

    my $raw = ref($data) ? encode_json($data) : $data;
    # update status
    my $bindata = pack "Z[256]Z*", $name, $raw;

    return &$ipcc_send_rec(CFS_IPC_SET_STATUS, $bindata);
};

my $ipcc_log = sub {
    my ($priority, $ident, $tag, $msg) = @_;

    my $bindata = pack "CCCZ*Z*Z*", $priority, bytes::length($ident) + 1,
    bytes::length($tag) + 1, $ident, $tag, $msg;

    return &$ipcc_send_rec(CFS_IPC_LOG_CLUSTER_MSG, $bindata);
};

my $ipcc_get_cluster_log = sub {
    my ($user, $max) = @_;

    $max = 0 if !defined($max);

    my $bindata = pack "VVVVZ*", $max, 0, 0, 0, ($user || "");
    return &$ipcc_send_rec(CFS_IPC_GET_CLUSTER_LOG, $bindata);
};

my $ccache = {};

sub cfs_update {
    my ($fail) = @_;
    eval {
	my $res = &$ipcc_send_rec_json(CFS_IPC_GET_FS_VERSION);
	die "no starttime\n" if !$res->{starttime};

	if (!$res->{starttime} || !$versions->{starttime} ||
	    $res->{starttime} != $versions->{starttime}) {
	    #print "detected changed starttime\n";
	    $vmlist = {};
	    $clinfo = {};
	    $ccache = {};
	}

	$versions = $res;
    };
    my $err = $@;
    if ($err) {
	$versions = {};
	$vmlist = {};
	$clinfo = {};
	$ccache = {};
	die $err if $fail;
	warn $err;
    }

    eval {
	if (!$clinfo->{version} || $clinfo->{version} != $versions->{clinfo}) {
	    #warn "detected new clinfo\n";
	    $clinfo = &$ipcc_send_rec_json(CFS_IPC_GET_CLUSTER_INFO);
	}
    };
    $err = $@;
    if ($err) {
	$clinfo = {};
	die $err if $fail;
	warn $err;
    }

    eval {
	if (!$vmlist->{version} || $vmlist->{version} != $versions->{vmlist}) {
	    #warn "detected new vmlist1\n";
	    $vmlist = &$ipcc_send_rec_json(CFS_IPC_GET_GUEST_LIST);
	}
    };
    $err = $@;
    if ($err) {
	$vmlist = {};
	die $err if $fail;
	warn $err;
    }
}

sub get_vmlist {
    return $vmlist;
}

sub get_clinfo {
    return $clinfo;
}

sub get_members {
    return $clinfo->{nodelist};
}

sub get_nodelist {
    my $nodelist = $clinfo->{nodelist};

    my $nodename = PVE::INotify::nodename();

    if (!$nodelist || !$nodelist->{$nodename}) {
	return [ $nodename ];
    }

    return [ keys %$nodelist ];
}

# only stored in a in-memory hashtable inside pmxcfs, local data is gone after
# a restart (of pmxcfs or the node), peer data is still available then
# best used for status data, like running (ceph) services, package versions, ...
sub broadcast_node_kv {
    my ($key, $data) = @_;

    if (!defined($data)) {
	eval {
	    $ipcc_remove_status->("kv/$key");
	};
    } else {
	die "cannot send a reference\n" if ref($data);
	my $size = length($data);
	die "data for '$key' too big\n" if $size >= (32 * 1024); # limit from pmxfs

	eval {
	    $ipcc_update_status->("kv/$key", $data);
	};
    }

    warn $@ if $@;
}

# nodename is optional
sub get_node_kv {
    my ($key, $nodename) = @_;

    my $res = {};
    my $get_node_data = sub {
	my ($node) = @_;
	my $raw = $ipcc_get_status->("kv/$key", $node);
	$res->{$node} = unpack("Z*", $raw) if $raw;
    };

    if ($nodename) {
	$get_node_data->($nodename);
    } else {
	my $nodelist = get_nodelist();

	foreach my $node (@$nodelist) {
	    $get_node_data->($node);
	}
    }

    return $res;
}

# property: a config property you want to get, e.g., this is perfect to get
# the 'lock' entry of a guest _fast_ (>100 faster than manual parsing here)
# vmid: optipnal, if a valid is passed we only check that one, else return all
# NOTE: does *not* searches snapshot and PENDING entries sections!
sub get_guest_config_property {
    my ($property, $vmid) = @_;

    die "property is required" if !defined($property);

    my $bindata = pack "VZ*", $vmid // 0, $property;
    my $res = $ipcc_send_rec_json->(CFS_IPC_GET_GUEST_CONFIG_PROPERTY, $bindata);

    return $res;
}

# $data must be a chronological descending ordered array of tasks
sub broadcast_tasklist {
    my ($data) = @_;

    # the serialized list may not get bigger than 32kb (CFS_MAX_STATUS_SIZE
    # from pmxcfs) - drop older items until we satisfy this constraint
    my $size = length(encode_json($data));
    while ($size >= (32 * 1024)) {
	pop @$data;
	$size = length(encode_json($data));
    }

    eval {
	&$ipcc_update_status("tasklist", $data);
    };

    warn $@ if $@;
}

my $tasklistcache = {};

sub get_tasklist {
    my ($nodename) = @_;

    my $kvstore = $versions->{kvstore} || {};

    my $nodelist = get_nodelist();

    my $res = [];
    foreach my $node (@$nodelist) {
	next if $nodename && ($nodename ne $node);
	eval {
	    my $ver = $kvstore->{$node}->{tasklist} if $kvstore->{$node};
	    my $cd = $tasklistcache->{$node};
	    if (!$cd || !$ver || !$cd->{version} ||
		($cd->{version} != $ver)) {
		my $raw = &$ipcc_get_status("tasklist", $node) || '[]';
		my $data = decode_json($raw);
		push @$res, @$data;
		$cd = $tasklistcache->{$node} = {
		    data => $data,
		    version => $ver,
		};
	    } elsif ($cd && $cd->{data}) {
		push @$res, @{$cd->{data}};
	    }
	};
	my $err = $@;
	syslog('err', $err) if $err;
    }

    return $res;
}

sub broadcast_rrd {
    my ($rrdid, $data) = @_;

    eval {
	&$ipcc_update_status("rrd/$rrdid", $data);
    };
    my $err = $@;

    warn $err if $err;
}

my $last_rrd_dump = 0;
my $last_rrd_data = "";

sub rrd_dump {

    my $ctime = time();

    my $diff = $ctime - $last_rrd_dump;
    if ($diff < 2) {
	return $last_rrd_data;
    }

    my $raw;
    eval {
	$raw = &$ipcc_send_rec(CFS_IPC_GET_RRD_DUMP);
    };
    my $err = $@;

    if ($err) {
	warn $err;
	return {};
    }

    my $res = {};

    if ($raw) {
	while ($raw =~ s/^(.*)\n//) {
	    my ($key, @ela) = split(/:/, $1);
	    next if !$key;
	    next if !(scalar(@ela) > 1);
	    $res->{$key} = [ map { $_ eq 'U' ? undef : $_ } @ela ];
	}
    }

    $last_rrd_dump = $ctime;
    $last_rrd_data = $res;

    return $res;
}


# a fast way to read files (avoid fuse overhead)
sub get_config {
    my ($path) = @_;

    return &$ipcc_get_config($path);
}

sub get_cluster_log {
    my ($user, $max) = @_;

    return &$ipcc_get_cluster_log($user, $max);
}

my $file_info = {};

sub cfs_register_file {
    my ($filename, $parser, $writer) = @_;

    $observed->{$filename} || die "unknown file '$filename'";

    die "file '$filename' already registered" if $file_info->{$filename};

    $file_info->{$filename} = {
	parser => $parser,
	writer => $writer,
    };
}

my $ccache_read = sub {
    my ($filename, $parser, $version) = @_;

    $ccache->{$filename} = {} if !$ccache->{$filename};

    my $ci = $ccache->{$filename};

    if (!$ci->{version} || !$version || $ci->{version} != $version) {
	# we always call the parser, even when the file does not exists
	# (in that case $data is undef)
	my $data = get_config($filename);
	$ci->{data} = &$parser("/etc/pve/$filename", $data);
	$ci->{version} = $version;
    }

    my $res = ref($ci->{data}) ? dclone($ci->{data}) : $ci->{data};

    return $res;
};

sub cfs_file_version {
    my ($filename) = @_;

    my $version;
    my $infotag;
    if ($filename =~ m!^nodes/[^/]+/(openvz|lxc|qemu-server)/(\d+)\.conf$!) {
	my ($type, $vmid) = ($1, $2);
	if ($vmlist && $vmlist->{ids} && $vmlist->{ids}->{$vmid}) {
	    $version = $vmlist->{ids}->{$vmid}->{version};
	}
	$infotag = "/$type/";
    } else {
	$infotag = $filename;
	$version = $versions->{$filename};
    }

    my $info = $file_info->{$infotag} ||
	die "unknown file type '$filename'\n";

    return wantarray ? ($version, $info) : $version;
}

sub cfs_read_file {
    my ($filename) = @_;

    my ($version, $info) = cfs_file_version($filename);
    my $parser = $info->{parser};

    return &$ccache_read($filename, $parser, $version);
}

sub cfs_write_file {
    my ($filename, $data) = @_;

    my ($version, $info) = cfs_file_version($filename);

    my $writer = $info->{writer} || die "no writer defined";

    my $fsname = "/etc/pve/$filename";

    my $raw = &$writer($fsname, $data);

    if (my $ci = $ccache->{$filename}) {
	$ci->{version} = undef;
    }

    PVE::Tools::file_set_contents($fsname, $raw);
}

my $cfs_lock = sub {
    my ($lockid, $timeout, $code, @param) = @_;

    my $prev_alarm = alarm(0); # suspend outer alarm early

    my $res;
    my $got_lock = 0;

    # this timeout is for acquire the lock
    $timeout = 10 if !$timeout;

    my $filename = "$lockdir/$lockid";

    eval {

	mkdir $lockdir;

	if (! -d $lockdir) {
	    die "pve cluster filesystem not online.\n";
	}

	my $timeout_err = sub { die "got lock request timeout\n"; };
	local $SIG{ALRM} = $timeout_err;

	while (1) {
	    alarm ($timeout);
	    $got_lock = mkdir($filename);
	    $timeout = alarm(0) - 1; # we'll sleep for 1s, see down below

	    last if $got_lock;

	    $timeout_err->() if $timeout <= 0;

	    print STDERR "trying to acquire cfs lock '$lockid' ...\n";
	    utime (0, 0, $filename); # cfs unlock request
	    sleep(1);
	}

	# fixed command timeout: cfs locks have a timeout of 120
	# using 60 gives us another 60 seconds to abort the task
	local $SIG{ALRM} = sub { die "got lock timeout - aborting command\n"; };
	alarm(60);

	cfs_update(); # make sure we read latest versions inside code()

	$res = &$code(@param);

	alarm(0);
    };

    my $err = $@;

    $err = "no quorum!\n" if !$got_lock && !check_cfs_quorum(1);

    rmdir $filename if $got_lock; # if we held the lock always unlock again

    alarm($prev_alarm);

    if ($err) {
        $@ = "error with cfs lock '$lockid': $err";
        return undef;
    }

    $@ = undef;

    return $res;
};

sub cfs_lock_file {
    my ($filename, $timeout, $code, @param) = @_;

    my $info = $observed->{$filename} || die "unknown file '$filename'";

    my $lockid = "file-$filename";
    $lockid =~ s/[.\/]/_/g;

    &$cfs_lock($lockid, $timeout, $code, @param);
}

sub cfs_lock_storage {
    my ($storeid, $timeout, $code, @param) = @_;

    my $lockid = "storage-$storeid";

    &$cfs_lock($lockid, $timeout, $code, @param);
}

sub cfs_lock_domain {
    my ($domainname, $timeout, $code, @param) = @_;

    my $lockid = "domain-$domainname";

    &$cfs_lock($lockid, $timeout, $code, @param);
}

sub cfs_lock_acme {
    my ($account, $timeout, $code, @param) = @_;

    my $lockid = "acme-$account";

    &$cfs_lock($lockid, $timeout, $code, @param);
}

sub cfs_lock_authkey {
    my ($timeout, $code, @param) = @_;

    $cfs_lock->('authkey', $timeout, $code, @param);
}

my $log_levels = {
    "emerg" => 0,
    "alert" => 1,
    "crit" => 2,
    "critical" => 2,
    "err" => 3,
    "error" => 3,
    "warn" => 4,
    "warning" => 4,
    "notice" => 5,
    "info" => 6,
    "debug" => 7,
};

sub log_msg {
   my ($priority, $ident, $msg) = @_;

   if (my $tmp = $log_levels->{$priority}) {
       $priority = $tmp;
   }

   die "need numeric log priority" if $priority !~ /^\d+$/;

   my $tag = PVE::SafeSyslog::tag();

   $msg = "empty message" if !$msg;

   $ident = "" if !$ident;
   $ident = encode("ascii", $ident,
		   sub { sprintf "\\u%04x", shift });

   my $ascii = encode("ascii", $msg, sub { sprintf "\\u%04x", shift });

   if ($ident) {
       syslog($priority, "<%s> %s", $ident, $ascii);
   } else {
       syslog($priority, "%s", $ascii);
   }

   eval { &$ipcc_log($priority, $ident, $tag, $ascii); };

   syslog("err", "writing cluster log failed: $@") if $@;
}

sub check_vmid_unused {
    my ($vmid, $noerr) = @_;

    my $vmlist = get_vmlist();

    my $d = $vmlist->{ids}->{$vmid};
    return 1 if !defined($d);

    return undef if $noerr;

    my $vmtypestr =  $d->{type} eq 'qemu' ? 'VM' : 'CT';
    die "$vmtypestr $vmid already exists on node '$d->{node}'\n";
}

sub check_node_exists {
    my ($nodename, $noerr) = @_;

    my $nodelist = $clinfo->{nodelist};
    return 1 if $nodelist && $nodelist->{$nodename};

    return undef if $noerr;

    die "no such cluster node '$nodename'\n";
}

# this is also used to get the IP of the local node
sub remote_node_ip {
    my ($nodename, $noerr) = @_;

    my $nodelist = $clinfo->{nodelist};
    if ($nodelist && $nodelist->{$nodename}) {
	if (my $ip = $nodelist->{$nodename}->{ip}) {
	    return $ip if !wantarray;
	    my $family = $nodelist->{$nodename}->{address_family};
	    if (!$family) {
		$nodelist->{$nodename}->{address_family} =
		    $family =
		    PVE::Tools::get_host_address_family($ip);
	    }
	    return wantarray ? ($ip, $family) : $ip;
	}
    }

    # fallback: try to get IP by other means
    return PVE::Network::get_ip_from_hostname($nodename, $noerr);
}

sub get_local_migration_ip {
    my ($migration_network, $noerr) = @_;

    my $cidr = $migration_network;

    if (!defined($cidr)) {
	my $dc_conf = cfs_read_file('datacenter.cfg');
	$cidr = $dc_conf->{migration}->{network}
	  if defined($dc_conf->{migration}->{network});
    }

    if (defined($cidr)) {
	my $ips = PVE::Network::get_local_ip_from_cidr($cidr);

	die "could not get migration ip: no IP address configured on local " .
	    "node for network '$cidr'\n" if !$noerr && (scalar(@$ips) == 0);

	die "could not get migration ip: multiple IP address configured for " .
	    "network '$cidr'\n" if !$noerr && (scalar(@$ips) > 1);

	return @$ips[0];
    }

    return undef;
};


my $migration_format = {
    type => {
	default_key => 1,
	type => 'string',
	enum => ['secure', 'insecure'],
	description => "Migration traffic is encrypted using an SSH tunnel by " .
	  "default. On secure, completely private networks this can be " .
	  "disabled to increase performance.",
	default => 'secure',
    },
    network => {
	optional => 1,
	type => 'string', format => 'CIDR',
	format_description => 'CIDR',
	description => "CIDR of the (sub) network that is used for migration."
    },
};

my $ha_format = {
    shutdown_policy => {
	type => 'string',
	enum => ['freeze', 'failover', 'conditional'],
	description => "The policy for HA services on node shutdown. 'freeze' disables auto-recovery, 'failover' ensures recovery, 'conditional' recovers on poweroff and freezes on reboot. Running HA Services will always get stopped first on shutdown.",
	verbose_description => "Describes the policy for handling HA services on poweroff or reboot of a node. Freeze will always freeze services which are still located on the node on shutdown, those services won't be recovered by the HA manager. Failover will not mark the services as frozen and thus the services will get recovered to other nodes, if the shutdown node does not come up again quickly (< 1min). 'conditional' chooses automatically depending on the type of shutdown, i.e., on a reboot the service will be frozen but on a poweroff the service will stay as is, and thus get recovered after about 2 minutes.",
	default => 'conditional',
    }
};

PVE::JSONSchema::register_format('mac-prefix', \&pve_verify_mac_prefix);
sub pve_verify_mac_prefix {
    my ($mac_prefix, $noerr) = @_;

    if ($mac_prefix !~ m/^[a-f0-9][02468ace](?::[a-f0-9]{2}){0,2}:?$/i) {
	return undef if $noerr;
	die "value is not a valid unicast MAC address prefix\n";
    }
    return $mac_prefix;
}

our $u2f_format = {
    appid => {
	type => 'string',
	description => "U2F AppId URL override. Defaults to the origin.",
	format_description => 'APPID',
	optional => 1,
    },
    origin => {
	type => 'string',
	description => "U2F Origin override. Mostly useful for single nodes with a single URL.",
	format_description => 'URL',
	optional => 1,
    },
};

my $datacenter_schema = {
    type => "object",
    additionalProperties => 0,
    properties => {
	keyboard => {
	    optional => 1,
	    type => 'string',
	    description => "Default keybord layout for vnc server.",
	    enum => PVE::Tools::kvmkeymaplist(),
	},
	language => {
	    optional => 1,
	    type => 'string',
	    description => "Default GUI language.",
	    enum => [
		'ca',
		'da',
		'de',
		'en',
		'es',
		'eu',
		'fa',
		'fr',
		'he',
		'it',
		'ja',
		'nb',
		'nn',
		'pl',
		'pt_BR',
		'ru',
		'sl',
		'sv',
		'tr',
		'zh_CN',
		'zh_TW',
	    ],
	},
	http_proxy => {
	    optional => 1,
	    type => 'string',
	    description => "Specify external http proxy which is used for downloads (example: 'http://username:password\@host:port/')",
	    pattern => "http://.*",
	},
	migration_unsecure => {
	    optional => 1,
	    type => 'boolean',
	    description => "Migration is secure using SSH tunnel by default. " .
	      "For secure private networks you can disable it to speed up " .
	      "migration. Deprecated, use the 'migration' property instead!",
	},
	migration => {
	    optional => 1,
	    type => 'string', format => $migration_format,
	    description => "For cluster wide migration settings.",
	},
	console => {
	    optional => 1,
	    type => 'string',
	    description => "Select the default Console viewer. You can either use the builtin java applet (VNC; deprecated and maps to html5), an external virt-viewer comtatible application (SPICE), an HTML5 based vnc viewer (noVNC), or an HTML5 based console client (xtermjs). If the selected viewer is not available (e.g. SPICE not activated for the VM), the fallback is noVNC.",
	    enum => ['applet', 'vv', 'html5', 'xtermjs'],
	},
	email_from => {
	    optional => 1,
	    type => 'string',
	    format => 'email-opt',
	    description => "Specify email address to send notification from (default is root@\$hostname)",
	},
	max_workers => {
	    optional => 1,
	    type => 'integer',
	    minimum => 1,
	    description => "Defines how many workers (per node) are maximal started ".
	      " on actions like 'stopall VMs' or task from the ha-manager.",
	},
	fencing => {
	    optional => 1,
	    type => 'string',
	    default => 'watchdog',
	    enum => [ 'watchdog', 'hardware', 'both' ],
	    description => "Set the fencing mode of the HA cluster. Hardware mode " .
	      "needs a valid configuration of fence devices in /etc/pve/ha/fence.cfg." .
	      " With both all two modes are used." .
	      "\n\nWARNING: 'hardware' and 'both' are EXPERIMENTAL & WIP",
	},
	ha => {
	    optional => 1,
	    type => 'string', format => $ha_format,
	    description => "Cluster wide HA settings.",
	},
	mac_prefix => {
	    optional => 1,
	    type => 'string',
	    format => 'mac-prefix',
	    description => 'Prefix for autogenerated MAC addresses.',
	},
	bwlimit => PVE::JSONSchema::get_standard_option('bwlimit'),
	u2f => {
	    optional => 1,
	    type => 'string',
	    format => $u2f_format,
	    description => 'u2f',
	},
    },
};

# make schema accessible from outside (for documentation)
sub get_datacenter_schema { return $datacenter_schema };

sub parse_datacenter_config {
    my ($filename, $raw) = @_;

    my $res = PVE::JSONSchema::parse_config($datacenter_schema, $filename, $raw // '');

    if (my $migration = $res->{migration}) {
	$res->{migration} = PVE::JSONSchema::parse_property_string($migration_format, $migration);
    }

    if (my $ha = $res->{ha}) {
	$res->{ha} = PVE::JSONSchema::parse_property_string($ha_format, $ha);
    }

    # for backwards compatibility only, new migration property has precedence
    if (defined($res->{migration_unsecure})) {
	if (defined($res->{migration}->{type})) {
	    warn "deprecated setting 'migration_unsecure' and new 'migration: type' " .
	      "set at same time! Ignore 'migration_unsecure'\n";
	} else {
	    $res->{migration}->{type} = ($res->{migration_unsecure}) ? 'insecure' : 'secure';
	}
    }

    # for backwards compatibility only, applet maps to html5
    if (defined($res->{console}) && $res->{console} eq 'applet') {
	$res->{console} = 'html5';
    }

    return $res;
}

sub write_datacenter_config {
    my ($filename, $cfg) = @_;

    # map deprecated setting to new one
    if (defined($cfg->{migration_unsecure}) && !defined($cfg->{migration})) {
	my $migration_unsecure = delete $cfg->{migration_unsecure};
	$cfg->{migration}->{type} = ($migration_unsecure) ? 'insecure' : 'secure';
    }

    # map deprecated applet setting to html5
    if (defined($cfg->{console}) && $cfg->{console} eq 'applet') {
	$cfg->{console} = 'html5';
    }

    if (ref($cfg->{migration})) {
	my $migration = $cfg->{migration};
	$cfg->{migration} = PVE::JSONSchema::print_property_string($migration, $migration_format);
    }

    if (ref($cfg->{ha})) {
	my $ha = $cfg->{ha};
	$cfg->{ha} = PVE::JSONSchema::print_property_string($ha, $ha_format);
    }

    return PVE::JSONSchema::dump_config($datacenter_schema, $filename, $cfg);
}

cfs_register_file('datacenter.cfg',
		  \&parse_datacenter_config,
		  \&write_datacenter_config);

sub get_node_fingerprint {
    my ($node) = @_;

    my $cert_path = "/etc/pve/nodes/$node/pve-ssl.pem";
    my $custom_cert_path = "/etc/pve/nodes/$node/pveproxy-ssl.pem";

    $cert_path = $custom_cert_path if -f $custom_cert_path;

    return PVE::Certificate::get_certificate_fingerprint($cert_path);
}

# bash completion helpers

sub complete_next_vmid {

    my $vmlist = get_vmlist() || {};
    my $idlist = $vmlist->{ids} || {};

    for (my $i = 100; $i < 10000; $i++) {
	return [$i] if !defined($idlist->{$i});
    }

    return [];
}

sub complete_vmid {

    my $vmlist = get_vmlist();
    my $ids = $vmlist->{ids} || {};

    return [ keys %$ids ];
}

sub complete_local_vmid {

    my $vmlist = get_vmlist();
    my $ids = $vmlist->{ids} || {};

    my $nodename = PVE::INotify::nodename();

    my $res = [];
    foreach my $vmid (keys %$ids) {
	my $d = $ids->{$vmid};
	next if !$d->{node} || $d->{node} ne $nodename;
	push @$res, $vmid;
    }

    return $res;
}

sub complete_migration_target {

    my $res = [];

    my $nodename = PVE::INotify::nodename();

    my $nodelist = get_nodelist();
    foreach my $node (@$nodelist) {
	next if $node eq $nodename;
	push @$res, $node;
    }

    return $res;
}

sub get_ssh_info {
    my ($node, $network_cidr) = @_;

    my $ip;
    if (defined($network_cidr)) {
	# Use mtunnel via to get the remote node's ip inside $network_cidr.
	# This goes over the regular network (iow. uses get_ssh_info() with
	# $network_cidr undefined.
	# FIXME: Use the REST API client for this after creating an API entry
	# for get_migration_ip.
	my $default_remote = get_ssh_info($node, undef);
	my $default_ssh = ssh_info_to_command($default_remote);
	my $cmd =[@$default_ssh, 'pvecm', 'mtunnel',
	    '-migration_network', $network_cidr,
	    '-get_migration_ip'
	];
	PVE::Tools::run_command($cmd, outfunc => sub {
	    my ($line) = @_;
	    chomp $line;
	    die "internal error: unexpected output from mtunnel\n"
		if defined($ip);
	    if ($line =~ /^ip: '(.*)'$/) {
		$ip = $1;
	    } else {
		die "internal error: bad output from mtunnel\n"
		    if defined($ip);
	    }
	});
	die "failed to get ip for node '$node' in network '$network_cidr'\n"
	    if !defined($ip);
    } else {
	$ip = remote_node_ip($node);
    }
 
    return {
	ip => $ip,
	name => $node,
	network => $network_cidr,
    };
}

sub ssh_info_to_command_base {
    my ($info, @extra_options) = @_;
    return [
	'/usr/bin/ssh',
	'-e', 'none',
	'-o', 'BatchMode=yes',
	'-o', 'HostKeyAlias='.$info->{name},
	@extra_options
    ];
}

sub ssh_info_to_command {
    my ($info, @extra_options) = @_;
    my $cmd = ssh_info_to_command_base($info, @extra_options);
    push @$cmd, "root\@$info->{ip}";
    return $cmd;
}

# NOTE: filesystem must be offline here, no DB changes allowed
sub cfs_backup_database {
    mkdir $dbbackupdir;

    my $ctime = time();
    my $backup_fn = "$dbbackupdir/config-$ctime.sql.gz";

    print "backup old database to '$backup_fn'\n";

    my $cmd = [ ['sqlite3', $dbfile, '.dump'], ['gzip', '-', \ ">${backup_fn}"] ];
    run_command($cmd, 'errmsg' => "cannot backup old database\n");

    my $maxfiles = 10; # purge older backup
    my $backups = [ sort { $b cmp $a } <$dbbackupdir/config-*.sql.gz> ];

    if ((my $count = scalar(@$backups)) > $maxfiles) {
	foreach my $f (@$backups[$maxfiles..$count-1]) {
	    next if $f !~ m/^(\S+)$/; # untaint
	    print "delete old backup '$1'\n";
	    unlink $1;
	}
    }

    return $dbfile;
}

1;
