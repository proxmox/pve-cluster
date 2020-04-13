package PVE::Cluster;

use strict;
use warnings;

use Encode;
use File::stat qw();
use File::Path qw(make_path);
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
    'priv/token.cfg' => 1,
    'priv/acme/plugins.cfg' => 1,
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
    'sdn/vnets.cfg' => 1,
    'sdn/zones.cfg' => 1,
    'sdn/controllers.cfg' => 1,
    'virtual-guest/cpu-models.conf' => 1,
};

sub prepare_observed_file_basedirs {

    if (check_cfs_is_mounted(1)) {
	warn "pmxcfs isn't mounted (/etc/pve), chickening out..\n";
	return;
    }

    for my $f (sort keys %$observed) {
	next if $f !~ m!^(.*)/[^/]+$!;
	my $dir = "$basedir/$1";
	next if -e $dir; # can also be a link, so just use -e xist check
	print "creating directory '$dir' for observerd files\n";
	make_path($dir);
    }
}

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

my $ipcc_verify_token = sub {
    my ($full_token) = @_;

    my $bindata = pack "Z*", $full_token;
    my $res = PVE::IPCC::ipcc_send_rec(CFS_IPC_VERIFY_TOKEN, $bindata);

    return 1 if $! == 0;
    return 0 if $! == ENOENT;

    die "$!\n";
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

sub verify_token {
    my ($userid, $token) = @_;

    return &$ipcc_verify_token("$userid $token");
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
	# we always call the parser, even when the file does not exist
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
	if (ref($err) eq 'PVE::Exception') {
	    # re-raise defined exceptions
	    $@ = $err;
	} else {
	    # add lock info for plain errors
	    $@ = "error during cfs-locked '$lockid' operation: $err";
	}
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

sub cfs_lock_firewall {
    my ($scope, $timeout, $code, @param) = @_;

    my $lockid = "firewall-$scope";

    $cfs_lock->($lockid, $timeout, $code, @param);
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
