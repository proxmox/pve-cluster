package PVE::Cluster;

use strict;
use warnings;
use POSIX qw(EEXIST ENOENT);
use File::stat qw();
use Socket;
use Storable qw(dclone);
use IO::File;
use MIME::Base64;
use Digest::SHA;
use Digest::HMAC_SHA1;
use Net::SSLeay;
use PVE::Tools qw(run_command);
use PVE::INotify;
use PVE::IPCC;
use PVE::SafeSyslog;
use PVE::JSONSchema;
use PVE::Network;
use JSON;
use RRDs;
use Encode;
use UUID;
use base 'Exporter';

our @EXPORT_OK = qw(
cfs_read_file
cfs_write_file
cfs_register_file
cfs_lock_file);

use Data::Dumper; # fixme: remove

# x509 certificate utils

my $basedir = "/etc/pve";
my $authdir = "$basedir/priv";
my $lockdir = "/etc/pve/priv/lock";

# cfs and corosync files
my $dbfile = "/var/lib/pve-cluster/config.db";
my $dbbackupdir = "/var/lib/pve-cluster/backup";
my $localclusterdir = "/etc/corosync";
my $localclusterconf = "$localclusterdir/corosync.conf";
my $authfile = "$localclusterdir/authkey";
my $clusterconf = "$basedir/corosync.conf";

my $authprivkeyfn = "$authdir/authkey.key";
my $authpubkeyfn = "$basedir/authkey.pub";
my $pveca_key_fn = "$authdir/pve-root-ca.key";
my $pveca_srl_fn = "$authdir/pve-root-ca.srl";
my $pveca_cert_fn = "$basedir/pve-root-ca.pem";
# this is just a secret accessable by the web browser
# and is used for CSRF prevention
my $pvewww_key_fn = "$basedir/pve-www.key";

# ssh related files
my $ssh_rsa_id_priv = "/root/.ssh/id_rsa";
my $ssh_rsa_id = "/root/.ssh/id_rsa.pub";
my $ssh_host_rsa_id = "/etc/ssh/ssh_host_rsa_key.pub";
my $sshglobalknownhosts = "/etc/ssh/ssh_known_hosts";
my $sshknownhosts = "/etc/pve/priv/known_hosts";
my $sshauthkeys = "/etc/pve/priv/authorized_keys";
my $sshd_config_fn = "/etc/ssh/sshd_config";
my $rootsshauthkeys = "/root/.ssh/authorized_keys";
my $rootsshauthkeysbackup = "${rootsshauthkeys}.org";
my $rootsshconfig = "/root/.ssh/config";

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
    '/qemu-server/' => 1,
    '/openvz/' => 1,
    '/lxc/' => 1,
    'ha/crm_commands' => 1,
    'ha/manager_status' => 1,
    'ha/resources.cfg' => 1,
    'ha/groups.cfg' => 1,
    'ha/fence.cfg' => 1,
    'status.cfg' => 1,
};

# only write output if something fails
sub run_silent_cmd {
    my ($cmd) = @_;

    my $outbuf = '';

    my $record_output = sub {
	$outbuf .= shift;
	$outbuf .= "\n";
    };

    eval {
	PVE::Tools::run_command($cmd, outfunc => $record_output,
				errfunc => $record_output);
    };

    my $err = $@;

    if ($err) {
	print STDERR $outbuf;
	die $err;
    }
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

sub gen_local_dirs {
    my ($nodename) = @_;

    check_cfs_is_mounted();

    my @required_dirs = (
	"$basedir/priv",
	"$basedir/nodes",
	"$basedir/nodes/$nodename",
	"$basedir/nodes/$nodename/lxc",
	"$basedir/nodes/$nodename/qemu-server",
	"$basedir/nodes/$nodename/openvz",
	"$basedir/nodes/$nodename/priv");

    foreach my $dir (@required_dirs) {
	if (! -d $dir) {
	    mkdir($dir) || $! == EEXIST || die "unable to create directory '$dir' - $!\n";
	}
    }
}

sub gen_auth_key {

    return if -f "$authprivkeyfn";

    check_cfs_is_mounted();

    mkdir $authdir || $! == EEXIST || die "unable to create dir '$authdir' - $!\n";

    run_silent_cmd(['openssl', 'genrsa', '-out', $authprivkeyfn, '2048']);

    run_silent_cmd(['openssl', 'rsa', '-in', $authprivkeyfn, '-pubout', '-out', $authpubkeyfn]);
}

sub gen_pveca_key {

    return if -f $pveca_key_fn;

    eval {
	run_silent_cmd(['openssl', 'genrsa', '-out', $pveca_key_fn, '4096']);
    };

    die "unable to generate pve ca key:\n$@" if $@;
}

sub gen_pveca_cert {

    if (-f $pveca_key_fn && -f $pveca_cert_fn) {
	return 0;
    }

    gen_pveca_key();

    # we try to generate an unique 'subject' to avoid browser problems
    # (reused serial numbers, ..)
    my $uuid;
    UUID::generate($uuid);
    my $uuid_str;
    UUID::unparse($uuid, $uuid_str);

    eval {
	# wrap openssl with faketime to prevent bug #904
	run_silent_cmd(['faketime', 'yesterday', 'openssl', 'req', '-batch',
			'-days', '3650', '-new', '-x509', '-nodes', '-key',
			$pveca_key_fn, '-out', $pveca_cert_fn, '-subj',
			"/CN=Proxmox Virtual Environment/OU=$uuid_str/O=PVE Cluster Manager CA/"]);
    };

    die "generating pve root certificate failed:\n$@" if $@;

    return 1;
}

sub gen_pve_ssl_key {
    my ($nodename) = @_;

    die "no node name specified" if !$nodename;

    my $pvessl_key_fn = "$basedir/nodes/$nodename/pve-ssl.key";

    return if -f $pvessl_key_fn;

    eval {
	run_silent_cmd(['openssl', 'genrsa', '-out', $pvessl_key_fn, '2048']);
    };

    die "unable to generate pve ssl key for node '$nodename':\n$@" if $@;
}

sub gen_pve_www_key {

    return if -f $pvewww_key_fn;

    eval {
	run_silent_cmd(['openssl', 'genrsa', '-out', $pvewww_key_fn, '2048']);
    };

    die "unable to generate pve www key:\n$@" if $@;
}

sub update_serial {
    my ($serial) = @_;

    PVE::Tools::file_set_contents($pveca_srl_fn, $serial);
}

sub gen_pve_ssl_cert {
    my ($force, $nodename, $ip) = @_;

    die "no node name specified" if !$nodename;
    die "no IP specified" if !$ip;

    my $pvessl_cert_fn = "$basedir/nodes/$nodename/pve-ssl.pem";

    return if !$force && -f $pvessl_cert_fn;

    my $names = "IP:127.0.0.1,IP:::1,DNS:localhost";

    my $rc = PVE::INotify::read_file('resolvconf');

    $names .= ",IP:$ip";

    my $fqdn = $nodename;

    $names .= ",DNS:$nodename";

    if ($rc && $rc->{search}) {
	$fqdn = $nodename . "." . $rc->{search};
	$names .= ",DNS:$fqdn";
    }

    my $sslconf = <<__EOD;
RANDFILE = /root/.rnd
extensions = v3_req

[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
string_mask = nombstr

[ req_distinguished_name ]
organizationalUnitName = PVE Cluster Node
organizationName = Proxmox Virtual Environment
commonName = $fqdn

[ v3_req ]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth
subjectAltName = $names
__EOD

    my $cfgfn = "/tmp/pvesslconf-$$.tmp";
    my $fh = IO::File->new ($cfgfn, "w");
    print $fh $sslconf;
    close ($fh);

    my $reqfn = "/tmp/pvecertreq-$$.tmp";
    unlink $reqfn;

    my $pvessl_key_fn = "$basedir/nodes/$nodename/pve-ssl.key";
    eval {
	run_silent_cmd(['openssl', 'req', '-batch', '-new', '-config', $cfgfn,
			'-key', $pvessl_key_fn, '-out', $reqfn]);
    };

    if (my $err = $@) {
	unlink $reqfn;
	unlink $cfgfn;
	die "unable to generate pve certificate request:\n$err";
    }

    update_serial("0000000000000000") if ! -f $pveca_srl_fn;

    eval {
	# wrap openssl with faketime to prevent bug #904
	run_silent_cmd(['faketime', 'yesterday', 'openssl', 'x509', '-req',
			'-in', $reqfn, '-days', '3650', '-out', $pvessl_cert_fn,
			'-CAkey', $pveca_key_fn, '-CA', $pveca_cert_fn,
			'-CAserial', $pveca_srl_fn, '-extfile', $cfgfn]);
    };

    if (my $err = $@) {
	unlink $reqfn;
	unlink $cfgfn;
	die "unable to generate pve ssl certificate:\n$err";
    }

    unlink $cfgfn;
    unlink $reqfn;
}

sub gen_pve_node_files {
    my ($nodename, $ip, $opt_force) = @_;

    gen_local_dirs($nodename);

    gen_auth_key();

    # make sure we have a (cluster wide) secret
    # for CSRFR prevention
    gen_pve_www_key();

    # make sure we have a (per node) private key
    gen_pve_ssl_key($nodename);

    # make sure we have a CA
    my $force = gen_pveca_cert();

    $force = 1 if $opt_force;

    gen_pve_ssl_cert($force, $nodename, $ip);
}

my $vzdump_cron_dummy = <<__EOD;
# cluster wide vzdump cron schedule
# Atomatically generated file - do not edit

PATH="/usr/sbin:/usr/bin:/sbin:/bin"

__EOD

sub gen_pve_vzdump_symlink {

    my $filename = "/etc/pve/vzdump.cron";

    my $link_fn = "/etc/cron.d/vzdump";

    if ((-f $filename) && (! -l $link_fn)) {
	rename($link_fn, "/root/etc_cron_vzdump.org"); # make backup if file exists
	symlink($filename, $link_fn);
    }
}

sub gen_pve_vzdump_files {

    my $filename = "/etc/pve/vzdump.cron";

    PVE::Tools::file_set_contents($filename, $vzdump_cron_dummy)
	if ! -f $filename;

    gen_pve_vzdump_symlink();
};

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
    my $res = PVE::IPCC::ipcc_send_rec(6, $bindata);
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
    return PVE::IPCC::ipcc_send_rec(5, $bindata);
};

my $ipcc_update_status = sub {
    my ($name, $data) = @_;

    my $raw = ref($data) ? encode_json($data) : $data;
    # update status
    my $bindata = pack "Z[256]Z*", $name, $raw;

    return &$ipcc_send_rec(4, $bindata);
};

my $ipcc_log = sub {
    my ($priority, $ident, $tag, $msg) = @_;

    my $bindata = pack "CCCZ*Z*Z*", $priority, bytes::length($ident) + 1,
    bytes::length($tag) + 1, $ident, $tag, $msg;

    return &$ipcc_send_rec(7, $bindata);
};

my $ipcc_get_cluster_log = sub {
    my ($user, $max) = @_;

    $max = 0 if !defined($max);

    my $bindata = pack "VVVVZ*", $max, 0, 0, 0, ($user || "");
    return &$ipcc_send_rec(8, $bindata);
};

my $ccache = {};

sub cfs_update {
    my ($fail) = @_;
    eval {
	my $res = &$ipcc_send_rec_json(1);
	#warn "GOT1: " . Dumper($res);
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
	    $clinfo = &$ipcc_send_rec_json(2);
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
	    $vmlist = &$ipcc_send_rec_json(3);
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

    my $result = [];

    my $nodename = PVE::INotify::nodename();

    if (!$nodelist || !$nodelist->{$nodename}) {
	return [ $nodename ];
    }

    return [ keys %$nodelist ];
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
	$raw = &$ipcc_send_rec(10);
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

sub create_rrd_data {
    my ($rrdname, $timeframe, $cf) = @_;

    my $rrddir = "/var/lib/rrdcached/db";

    my $rrd = "$rrddir/$rrdname";

    my $setup = {
	hour =>  [ 60, 70 ],
	day  =>  [ 60*30, 70 ],
	week =>  [ 60*180, 70 ],
	month => [ 60*720, 70 ],
	year =>  [ 60*10080, 70 ],
    };

    my ($reso, $count) = @{$setup->{$timeframe}};
    my $ctime  = $reso*int(time()/$reso);
    my $req_start = $ctime - $reso*$count;

    $cf = "AVERAGE" if !$cf;

    my @args = (
	"-s" => $req_start,
	"-e" => $ctime - 1,
	"-r" => $reso,
	);

    my $socket = "/var/run/rrdcached.sock";
    push @args, "--daemon" => "unix:$socket" if -S $socket;

    my ($start, $step, $names, $data) = RRDs::fetch($rrd, $cf, @args);

    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;

    die "got wrong time resolution ($step != $reso)\n"
	if $step != $reso;

    my $res = [];
    my $fields = scalar(@$names);
    for my $line (@$data) {
	my $entry = { 'time' => $start };
	$start += $step;
	for (my $i = 0; $i < $fields; $i++) {
	    my $name = $names->[$i];
	    if (defined(my $val = $line->[$i])) {
		$entry->{$name} = $val;
	    } else {
		# leave empty fields undefined
		# maybe make this configurable?
	    }
	}
	push @$res, $entry;
    }

    return $res;
}

sub create_rrd_graph {
    my ($rrdname, $timeframe, $ds, $cf) = @_;

    # Using RRD graph is clumsy - maybe it
    # is better to simply fetch the data, and do all display
    # related things with javascript (new extjs html5 graph library).

    my $rrddir = "/var/lib/rrdcached/db";

    my $rrd = "$rrddir/$rrdname";

    my @ids = PVE::Tools::split_list($ds);

    my $ds_txt = join('_', @ids);

    my $filename = "${rrd}_${ds_txt}.png";

    my $setup = {
	hour =>  [ 60, 60 ],
	day  =>  [ 60*30, 70 ],
	week =>  [ 60*180, 70 ],
	month => [ 60*720, 70 ],
	year =>  [ 60*10080, 70 ],
    };

    my ($reso, $count) = @{$setup->{$timeframe}};

    my @args = (
	"--imgformat" => "PNG",
	"--border" => 0,
	"--height" => 200,
	"--width" => 800,
	"--start" => - $reso*$count,
	"--end" => 'now' ,
	"--lower-limit" => 0,
	);

    my $socket = "/var/run/rrdcached.sock";
    push @args, "--daemon" => "unix:$socket" if -S $socket;

    my @coldef = ('#00ddff', '#ff0000');

    $cf = "AVERAGE" if !$cf;

    my $i = 0;
    foreach my $id (@ids) {
	my $col = $coldef[$i++] || die "fixme: no color definition";
	push @args, "DEF:${id}=$rrd:${id}:$cf";
	my $dataid = $id;
	if ($id eq 'cpu' || $id eq 'iowait') {
	    push @args, "CDEF:${id}_per=${id},100,*";
	    $dataid = "${id}_per";
	}
	push @args, "LINE2:${dataid}${col}:${id}";
    }

    push @args, '--full-size-mode';

    # we do not really store data into the file
    my $res = RRDs::graphv('-', @args);

    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;

    return { filename => $filename, image => $res->{image} };
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

    # this timeout is for aquire the lock
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

	    print STDERR "trying to aquire cfs lock '$lockid' ...\n";
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

# ssh related utility functions

sub ssh_merge_keys {
    # remove duplicate keys in $sshauthkeys
    # ssh-copy-id simply add keys, so the file can grow to large

    my $data = '';
    if (-f $sshauthkeys) {
	$data = PVE::Tools::file_get_contents($sshauthkeys, 128*1024);
	chomp($data);
    }

    my $found_backup;
    if (-f $rootsshauthkeysbackup) {
	$data .= "\n";
	$data .= PVE::Tools::file_get_contents($rootsshauthkeysbackup, 128*1024);
	chomp($data);
	$found_backup = 1;
    }

    # always add ourself
    if (-f $ssh_rsa_id) {
	my $pub = PVE::Tools::file_get_contents($ssh_rsa_id);
	chomp($pub);
	$data .= "\n$pub\n";
    }

    my $newdata = "";
    my $vhash = {};
    my @lines = split(/\n/, $data);
    foreach my $line (@lines) {
	if ($line !~ /^#/ && $line =~ m/(^|\s)ssh-(rsa|dsa)\s+(\S+)\s+\S+$/) {
            next if $vhash->{$3}++;
	}
	$newdata .= "$line\n";
    }

    PVE::Tools::file_set_contents($sshauthkeys, $newdata, 0600);

    if ($found_backup && -l $rootsshauthkeys) {
	# everything went well, so we can remove the backup
	unlink $rootsshauthkeysbackup;
    }
}

sub setup_sshd_config {
    my () = @_;

    my $conf = PVE::Tools::file_get_contents($sshd_config_fn);

    return if $conf =~ m/^PermitRootLogin\s+yes\s*$/m;

    if ($conf !~ s/^#?PermitRootLogin.*$/PermitRootLogin yes/m) {
	chomp $conf;
	$conf .= "\nPermitRootLogin yes\n";
    }

    PVE::Tools::file_set_contents($sshd_config_fn, $conf);

    PVE::Tools::run_command(['systemctl', 'reload-or-restart', 'sshd']);
}

sub setup_rootsshconfig {

    # create ssh key if it does not exist
    if (! -f $ssh_rsa_id) {
	mkdir '/root/.ssh/';
	system ("echo|ssh-keygen -t rsa -N '' -b 2048 -f ${ssh_rsa_id_priv}");
    }

    # create ssh config if it does not exist
    if (! -f $rootsshconfig) {
        mkdir '/root/.ssh';
        if (my $fh = IO::File->new($rootsshconfig, O_CREAT|O_WRONLY|O_EXCL, 0640)) {
            # this is the default ciphers list from Debian's OpenSSH package (OpenSSH_7.4p1 Debian-10, OpenSSL 1.0.2k  26 Jan 2017)
	    # changed order to put AES before Chacha20 (most hardware has AESNI)
            print $fh "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm\@openssh.com,aes256-gcm\@openssh.com,chacha20-poly1305\@openssh.com\n";
            close($fh);
        }
    }
}

sub setup_ssh_keys {

    mkdir $authdir;

    my $import_ok;

    if (! -f $sshauthkeys) {
	my $old;
	if (-f $rootsshauthkeys) {
	    $old = PVE::Tools::file_get_contents($rootsshauthkeys, 128*1024);
	}
	if (my $fh = IO::File->new ($sshauthkeys, O_CREAT|O_WRONLY|O_EXCL, 0400)) {
	    PVE::Tools::safe_print($sshauthkeys, $fh, $old) if $old;
	    close($fh);
	    $import_ok = 1;
	}
    }

    warn "can't create shared ssh key database '$sshauthkeys'\n"
	if ! -f $sshauthkeys;

    if (-f $rootsshauthkeys && ! -l $rootsshauthkeys) {
	if (!rename($rootsshauthkeys , $rootsshauthkeysbackup)) {
	    warn "rename $rootsshauthkeys failed - $!\n";
	}
    }

    if (! -l $rootsshauthkeys) {
	symlink $sshauthkeys, $rootsshauthkeys;
    }

    if (! -l $rootsshauthkeys) {
	warn "can't create symlink for ssh keys '$rootsshauthkeys' -> '$sshauthkeys'\n";
    } else {
	unlink $rootsshauthkeysbackup if $import_ok;
    }
}

sub ssh_unmerge_known_hosts {
    return if ! -l $sshglobalknownhosts;

    my $old = '';
    $old = PVE::Tools::file_get_contents($sshknownhosts, 128*1024)
	if -f $sshknownhosts;

    PVE::Tools::file_set_contents($sshglobalknownhosts, $old);
}

sub ssh_merge_known_hosts {
    my ($nodename, $ip_address, $createLink) = @_;

    die "no node name specified" if !$nodename;
    die "no ip address specified" if !$ip_address;

    # ssh lowercases hostnames (aliases) before comparision, so we need too
    $nodename = lc($nodename);
    $ip_address = lc($ip_address);

    mkdir $authdir;

    if (! -f $sshknownhosts) {
	if (my $fh = IO::File->new($sshknownhosts, O_CREAT|O_WRONLY|O_EXCL, 0600)) {
	    close($fh);
	}
    }

    my $old = PVE::Tools::file_get_contents($sshknownhosts, 128*1024);

    my $new = '';

    if ((! -l $sshglobalknownhosts) && (-f $sshglobalknownhosts)) {
	$new = PVE::Tools::file_get_contents($sshglobalknownhosts, 128*1024);
    }

    my $hostkey = PVE::Tools::file_get_contents($ssh_host_rsa_id);
    # Note: file sometimes containe emty lines at start, so we use multiline match
    die "can't parse $ssh_host_rsa_id" if $hostkey !~ m/^(ssh-rsa\s\S+)(\s.*)?$/m;
    $hostkey = $1;

    my $data = '';
    my $vhash = {};

    my $found_nodename;
    my $found_local_ip;

    my $merge_line = sub {
	my ($line, $all) = @_;

	return if $line =~ m/^\s*$/; # skip empty lines
	return if $line =~ m/^#/; # skip comments

	if ($line =~ m/^(\S+)\s(ssh-rsa\s\S+)(\s.*)?$/) {
	    my $key = $1;
	    my $rsakey = $2;
	    if (!$vhash->{$key}) {
		$vhash->{$key} = 1;
		if ($key =~ m/\|1\|([^\|\s]+)\|([^\|\s]+)$/) {
		    my $salt = decode_base64($1);
		    my $digest = $2;
		    my $hmac = Digest::HMAC_SHA1->new($salt);
		    $hmac->add($nodename);
		    my $hd = $hmac->b64digest . '=';
		    if ($digest eq $hd) {
			if ($rsakey eq $hostkey) {
			    $found_nodename = 1;
			    $data .= $line;
			}
			return;
		    }
		    $hmac = Digest::HMAC_SHA1->new($salt);
		    $hmac->add($ip_address);
		    $hd = $hmac->b64digest . '=';
		    if ($digest eq $hd) {
			if ($rsakey eq $hostkey) {
			    $found_local_ip = 1;
			    $data .= $line;
			}
			return;
		    }
		} else {
		    $key = lc($key); # avoid duplicate entries, ssh compares lowercased
		    if ($key eq $ip_address) {
			$found_local_ip = 1 if $rsakey eq $hostkey;
		    } elsif ($key eq $nodename) {
			$found_nodename = 1 if $rsakey eq $hostkey;
		    }
		}
		$data .= $line;
	    }
	} elsif ($all) {
	    $data .= $line;
	}
    };

    while ($old && $old =~ s/^((.*?)(\n|$))//) {
	my $line = "$2\n";
	&$merge_line($line, 1);
    }

    while ($new && $new =~ s/^((.*?)(\n|$))//) {
	my $line = "$2\n";
	&$merge_line($line);
    }

    # add our own key if not already there
    $data .= "$nodename $hostkey\n" if !$found_nodename;
    $data .= "$ip_address $hostkey\n" if !$found_local_ip;

    PVE::Tools::file_set_contents($sshknownhosts, $data);

    return if !$createLink;

    unlink $sshglobalknownhosts;
    symlink $sshknownhosts, $sshglobalknownhosts;

    warn "can't create symlink for ssh known hosts '$sshglobalknownhosts' -> '$sshknownhosts'\n"
	if ! -l $sshglobalknownhosts;

}

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
	    enum => [ 'en', 'de' ],
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
	mac_prefix => {
	    optional => 1,
	    type => 'string',
	    pattern => qr/[a-f0-9]{2}(?::[a-f0-9]{2}){0,2}:?/i,
	    description => 'Prefix for autogenerated MAC addresses.',
	},
	bwlimit => PVE::JSONSchema::get_standard_option('bwlimit'),
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

    if (my $migration = $cfg->{migration}) {
	$cfg->{migration} = PVE::JSONSchema::print_property_string($migration, $migration_format);
    }

    return PVE::JSONSchema::dump_config($datacenter_schema, $filename, $cfg);
}

cfs_register_file('datacenter.cfg',
		  \&parse_datacenter_config,
		  \&write_datacenter_config);

# X509 Certificate cache helper

my $cert_cache_nodes = {};
my $cert_cache_timestamp = time();
my $cert_cache_fingerprints = {};

sub update_cert_cache {
    my ($update_node, $clear) = @_;

    syslog('info', "Clearing outdated entries from certificate cache")
	if $clear;

    $cert_cache_timestamp = time() if !defined($update_node);

    my $node_list = defined($update_node) ?
	[ $update_node ] : [ keys %$cert_cache_nodes ];

    foreach my $node (@$node_list) {
	my $clear_old = sub {
	    if (my $old_fp = $cert_cache_nodes->{$node}) {
		# distrust old fingerprint
		delete $cert_cache_fingerprints->{$old_fp};
		# ensure reload on next proxied request
		delete $cert_cache_nodes->{$node};
	    }
	};

	my $fp = eval { get_node_fingerprint($node) };
	if (my $err = $@) {
	    warn "$err\n";
	    &$clear_old() if $clear;
	    next;
	}

	my $old_fp = $cert_cache_nodes->{$node};
	$cert_cache_fingerprints->{$fp} = 1;
	$cert_cache_nodes->{$node} = $fp;

	if (defined($old_fp) && $fp ne $old_fp) {
	    delete $cert_cache_fingerprints->{$old_fp};
	}
    }
}

# load and cache cert fingerprint once
sub initialize_cert_cache {
    my ($node) = @_;

    update_cert_cache($node)
	if defined($node) && !defined($cert_cache_nodes->{$node});
}

sub read_ssl_cert_fingerprint {
    my ($cert_path) = @_;

    my $bio = Net::SSLeay::BIO_new_file($cert_path, 'r')
	or die "unable to read '$cert_path' - $!\n";

    my $cert = Net::SSLeay::PEM_read_bio_X509($bio);
    if (!$cert) {
	Net::SSLeay::BIO_free($bio);
	die "unable to read certificate from '$cert_path'\n";
    }

    my $fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    Net::SSLeay::X509_free($cert);

    die "unable to get fingerprint for '$cert_path' - got empty value\n"
	if !defined($fp) || $fp eq '';

    return $fp;
}

sub get_node_fingerprint {
    my ($node) = @_;

    my $cert_path = "/etc/pve/nodes/$node/pve-ssl.pem";
    my $custom_cert_path = "/etc/pve/nodes/$node/pveproxy-ssl.pem";

    $cert_path = $custom_cert_path if -f $custom_cert_path;

    return read_ssl_cert_fingerprint($cert_path);
}


sub check_cert_fingerprint {
    my ($cert) = @_;

    # clear cache every 30 minutes at least
    update_cert_cache(undef, 1) if time() - $cert_cache_timestamp >= 60*30;

    # get fingerprint of server certificate
    my $fp = Net::SSLeay::X509_get_fingerprint($cert, 'sha256');
    return 0 if !defined($fp) || $fp eq ''; # error

    my $check = sub {
	for my $expected (keys %$cert_cache_fingerprints) {
	    return 1 if $fp eq $expected;
	}
	return 0;
    };

    return 1 if &$check();

    # clear cache and retry at most once every minute
    if (time() - $cert_cache_timestamp >= 60) {
	syslog ('info', "Could not verify remote node certificate '$fp' with list of pinned certificates, refreshing cache");
	update_cert_cache();
	return &$check();
    }

    return 0;
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

sub assert_joinable {
    my ($ring0_addr, $ring1_addr, $force) = @_;

    my $errors = '';
    my $error = sub { $errors .= "* $_[0]\n"; };

    if (-f $authfile) {
	$error->("authentication key '$authfile' already exists");
    }

    if (-f $clusterconf)  {
	$error->("cluster config '$clusterconf' already exists");
    }

    my $vmlist = get_vmlist();
    if ($vmlist && $vmlist->{ids} && scalar(keys %{$vmlist->{ids}})) {
	$error->("this host already contains virtual guests");
    }

    if (run_command(['corosync-quorumtool', '-l'], noerr => 1, quiet => 1) == 0) {
	$error->("corosync is already running, is this node already in a cluster?!");
    }

    # check if corosync ring IPs are configured on the current nodes interfaces
    my $check_ip = sub {
	my $ip = shift // return;
	if (!PVE::JSONSchema::pve_verify_ip($ip, 1)) {
	    my $host = $ip;
	    eval { $ip = PVE::Network::get_ip_from_hostname($host); };
	    if ($@) {
		$error->("cannot use '$host': $@\n") ;
		return;
	    }
	}

	my $cidr = (Net::IP::ip_is_ipv6($ip)) ? "$ip/128" : "$ip/32";
	my $configured_ips = PVE::Network::get_local_ip_from_cidr($cidr);

	$error->("cannot use IP '$ip', it must be configured exactly once on local node!\n")
	    if (scalar(@$configured_ips) != 1);
    };

    $check_ip->($ring0_addr);
    $check_ip->($ring1_addr);

    if ($errors) {
	warn "detected the following error(s):\n$errors";
	die "Check if node may join a cluster failed!\n" if !$force;
    }
}

# NOTE: filesystem must be offline here, no DB changes allowed
my $backup_cfs_database = sub {
    my ($dbfile) = @_;

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
};

sub join {
    my ($param) = @_;

    my $nodename = PVE::INotify::nodename();

    setup_sshd_config();
    setup_rootsshconfig();
    setup_ssh_keys();

    # check if we can join with the given parameters and current node state
    my ($ring0_addr, $ring1_addr) = $param->@{'ring0_addr', 'ring1_addr'};
    assert_joinable($ring0_addr, $ring1_addr, $param->{force});

    # make sure known_hosts is on local filesystem
    ssh_unmerge_known_hosts();

    my $host = $param->{hostname};
    my $local_ip_address = remote_node_ip($nodename);

    my $conn_args = {
	username => 'root@pam',
	password => $param->{password},
	cookie_name => 'PVEAuthCookie',
	protocol => 'https',
	host => $host,
	port => 8006,
    };

    if (my $fp = $param->{fingerprint}) {
	$conn_args->{cached_fingerprints} = { uc($fp) => 1 };
    } else {
	# API schema ensures that we can only get here from CLI handler
	$conn_args->{manual_verification} = 1;
    }

    print "Etablishing API connection with host '$host'\n";

    my $conn = PVE::APIClient::LWP->new(%$conn_args);
    $conn->login();

    # login raises an exception on failure, so if we get here we're good
    print "Login succeeded.\n";

    my $args = {};
    $args->{force} = $param->{force} if defined($param->{force});
    $args->{nodeid} = $param->{nodeid} if $param->{nodeid};
    $args->{votes} = $param->{votes} if defined($param->{votes});
    $args->{ring0_addr} = $ring0_addr // $local_ip_address;
    $args->{ring1_addr} = $ring1_addr if defined($ring1_addr);

    print "Request addition of this node\n";
    my $res = $conn->post("/cluster/config/nodes/$nodename", $args);

    print "Join request OK, finishing setup locally\n";

    # added successfuly - now prepare local node
    finish_join($nodename, $res->{corosync_conf}, $res->{corosync_authkey});
}

sub finish_join {
    my ($nodename, $corosync_conf, $corosync_authkey) = @_;

    mkdir "$localclusterdir";
    PVE::Tools::file_set_contents($authfile, $corosync_authkey);
    PVE::Tools::file_set_contents($localclusterconf, $corosync_conf);

    print "stopping pve-cluster service\n";
    my $cmd = ['systemctl', 'stop', 'pve-cluster'];
    run_command($cmd, errmsg => "can't stop pve-cluster service");

    $backup_cfs_database->($dbfile);
    unlink $dbfile;

    $cmd = ['systemctl', 'start', 'corosync', 'pve-cluster'];
    run_command($cmd, errmsg => "starting pve-cluster failed");

    # wait for quorum
    my $printqmsg = 1;
    while (!check_cfs_quorum(1)) {
	if ($printqmsg) {
	    print "waiting for quorum...";
	    STDOUT->flush();
	    $printqmsg = 0;
	}
	sleep(1);
    }
    print "OK\n" if !$printqmsg;

    updatecerts_and_ssh(1);

    print "generated new node certificate, restart pveproxy and pvedaemon services\n";
    run_command(['systemctl', 'reload-or-restart', 'pvedaemon', 'pveproxy']);

    print "successfully added node '$nodename' to cluster.\n";
}

sub updatecerts_and_ssh {
    my ($force_new_cert, $silent) = @_;

    my $p = sub { print "$_[0]\n" if !$silent };

    setup_rootsshconfig();

    gen_pve_vzdump_symlink();

    if (!check_cfs_quorum(1)) {
	return undef if $silent;
	die "no quorum - unable to update files\n";
    }

    setup_ssh_keys();

    my $nodename = PVE::INotify::nodename();
    my $local_ip_address = remote_node_ip($nodename);

    $p->("(re)generate node files");
    $p->("generate new node certificate") if $force_new_cert;
    gen_pve_node_files($nodename, $local_ip_address, $force_new_cert);

    $p->("merge authorized SSH keys and known hosts");
    ssh_merge_keys();
    ssh_merge_known_hosts($nodename, $local_ip_address, 1);
    gen_pve_vzdump_files();
}

1;
