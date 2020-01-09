package PVE::Cluster::Setup;

use strict;
use warnings;

use Digest::HMAC_SHA1;
use Digest::SHA;
use IO::File;
use MIME::Base64;
use Net::IP;
use UUID;
use POSIX qw(EEXIST);

use PVE::APIClient::LWP;
use PVE::Cluster;
use PVE::Corosync;
use PVE::INotify;
use PVE::JSONSchema;
use PVE::Network;
use PVE::Tools;
use PVE::Certificate;

my $pmxcfs_base_dir = PVE::Cluster::base_dir();
my $pmxcfs_auth_dir = PVE::Cluster::auth_dir();

# only write output if something fails
sub run_silent_cmd {
    my ($cmd) = @_;

    my $outbuf = '';
    my $record = sub { $outbuf .= shift . "\n"; };

    eval { PVE::Tools::run_command($cmd, outfunc => $record, errfunc => $record) };

    if (my $err = $@) {
	print STDERR $outbuf;
	die $err;
    }
}

# Corosync related files
my $localclusterdir = "/etc/corosync";
my $localclusterconf = "$localclusterdir/corosync.conf";
my $authfile = "$localclusterdir/authkey";
my $clusterconf = "$pmxcfs_base_dir/corosync.conf";

# CA/certificate related files
my $pveca_key_fn = "$pmxcfs_auth_dir/pve-root-ca.key";
my $pveca_srl_fn = "$pmxcfs_auth_dir/pve-root-ca.srl";
my $pveca_cert_fn = "$pmxcfs_base_dir/pve-root-ca.pem";
# this is just a secret accessable by the web browser
# and is used for CSRF prevention
my $pvewww_key_fn = "$pmxcfs_base_dir/pve-www.key";

# ssh related files
my $ssh_rsa_id_priv = "/root/.ssh/id_rsa";
my $ssh_rsa_id = "/root/.ssh/id_rsa.pub";
my $ssh_host_rsa_id = "/etc/ssh/ssh_host_rsa_key.pub";
my $sshglobalknownhosts = "/etc/ssh/ssh_known_hosts";
my $sshknownhosts = "$pmxcfs_auth_dir/known_hosts";
my $sshauthkeys = "$pmxcfs_auth_dir/authorized_keys";
my $sshd_config_fn = "/etc/ssh/sshd_config";
my $rootsshauthkeys = "/root/.ssh/authorized_keys";
my $rootsshauthkeysbackup = "${rootsshauthkeys}.org";
my $rootsshconfig = "/root/.ssh/config";

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

    mkdir $pmxcfs_auth_dir;

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

    mkdir $pmxcfs_auth_dir;

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

# directory and file creation

sub gen_local_dirs {
    my ($nodename) = @_;

    PVE::Cluster::check_cfs_is_mounted();

    my @required_dirs = (
	"$pmxcfs_base_dir/priv",
	"$pmxcfs_base_dir/nodes",
	"$pmxcfs_base_dir/nodes/$nodename",
	"$pmxcfs_base_dir/nodes/$nodename/lxc",
	"$pmxcfs_base_dir/nodes/$nodename/qemu-server",
	"$pmxcfs_base_dir/nodes/$nodename/openvz",
	"$pmxcfs_base_dir/nodes/$nodename/priv");

    foreach my $dir (@required_dirs) {
	if (! -d $dir) {
	    mkdir($dir) || $! == EEXIST || die "unable to create directory '$dir' - $!\n";
	}
    }
}

sub gen_auth_key {
    my $authprivkeyfn = "$pmxcfs_auth_dir/authkey.key";
    my $authpubkeyfn = "$pmxcfs_base_dir/authkey.pub";

    return if -f "$authprivkeyfn";

    PVE::Cluster::check_cfs_is_mounted();

    PVE::Cluster::cfs_lock_authkey(undef, sub {
	mkdir $pmxcfs_auth_dir || $! == EEXIST || die "unable to create dir '$pmxcfs_auth_dir' - $!\n";

	run_silent_cmd(['openssl', 'genrsa', '-out', $authprivkeyfn, '2048']);

	run_silent_cmd(['openssl', 'rsa', '-in', $authprivkeyfn, '-pubout', '-out', $authpubkeyfn]);
    });

    die "$@\n" if $@;
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

    my $pvessl_key_fn = "$pmxcfs_base_dir/nodes/$nodename/pve-ssl.key";

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

    my $pvessl_cert_fn = "$pmxcfs_base_dir/nodes/$nodename/pve-ssl.pem";

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

    my $pvessl_key_fn = "$pmxcfs_base_dir/nodes/$nodename/pve-ssl.key";
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

    # get ca expiry
    my $cainfo = PVE::Certificate::get_certificate_info($pveca_cert_fn);
    my $daysleft = int(($cainfo->{notafter} - time())/(24*60*60));

    if ($daysleft < 14) {
	die "CA expires in less than 2 weeks, unable to generate certificate.\n";
    }

    # let the certificate expire a little sooner that the ca, so subtract 2 days
    $daysleft -= 2;

    # we want the certificates to only last 2 years, since some browsers
    # do not accept certificates with very long expiry time
    if ($daysleft >= 2*365) {
	$daysleft = 2*365;
    }

    eval {
	# wrap openssl with faketime to prevent bug #904
	run_silent_cmd(['faketime', 'yesterday', 'openssl', 'x509', '-req',
			'-in', $reqfn, '-days', $daysleft, '-out', $pvessl_cert_fn,
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

# join helpers

sub assert_joinable {
    my ($local_addr, $links, $force) = @_;

    my $errors = '';
    my $error = sub { $errors .= "* $_[0]\n"; };

    if (-f $authfile) {
	$error->("authentication key '$authfile' already exists");
    }

    if (-f $clusterconf)  {
	$error->("cluster config '$clusterconf' already exists");
    }

    my $vmlist = PVE::Cluster::get_vmlist();
    if ($vmlist && $vmlist->{ids} && scalar(keys %{$vmlist->{ids}})) {
	$error->("this host already contains virtual guests");
    }

    if (PVE::Tools::run_command(['corosync-quorumtool', '-l'], noerr => 1, quiet => 1) == 0) {
	$error->("corosync is already running, is this node already in a cluster?!");
    }

    # check if corosync ring IPs are configured on the current nodes interfaces
    my $check_ip = sub {
	my $ip = shift // return;
	my $logid = shift;
	if (!PVE::JSONSchema::pve_verify_ip($ip, 1)) {
	    my $host = $ip;
	    eval { $ip = PVE::Network::get_ip_from_hostname($host); };
	    if ($@) {
		$error->("$logid: cannot use '$host': $@\n") ;
		return;
	    }
	}

	my $cidr = (Net::IP::ip_is_ipv6($ip)) ? "$ip/128" : "$ip/32";
	my $configured_ips = PVE::Network::get_local_ip_from_cidr($cidr);

	$error->("$logid: cannot use IP '$ip', not found on local node!\n")
	    if scalar(@$configured_ips) < 1;
    };

    $check_ip->($local_addr, 'local node address');

    foreach my $link (keys %$links) {
	$check_ip->($links->{$link}->{address}, "link$link");
    }

    if ($errors) {
	warn "detected the following error(s):\n$errors";
	die "Check if node may join a cluster failed!\n" if !$force;
    }
}

sub join {
    my ($param) = @_;

    my $nodename = PVE::INotify::nodename();
    my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);

    my $links = PVE::Corosync::extract_corosync_link_args($param);

    # check if we can join with the given parameters and current node state
    assert_joinable($local_ip_address, $links, $param->{force});

    setup_sshd_config();
    setup_rootsshconfig();
    setup_ssh_keys();

    # make sure known_hosts is on local filesystem
    ssh_unmerge_known_hosts();

    my $host = $param->{hostname};
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

    print "Establishing API connection with host '$host'\n";

    my $conn = PVE::APIClient::LWP->new(%$conn_args);
    $conn->login();

    # login raises an exception on failure, so if we get here we're good
    print "Login succeeded.\n";

    my $args = {};
    $args->{force} = $param->{force} if defined($param->{force});
    $args->{nodeid} = $param->{nodeid} if $param->{nodeid};
    $args->{votes} = $param->{votes} if defined($param->{votes});
    foreach my $link (keys %$links) {
	$args->{"link$link"} = PVE::Corosync::print_corosync_link($links->{$link});
    }

    print "Request addition of this node\n";
    my $res = eval { $conn->post("/cluster/config/nodes/$nodename", $args); };
    if (my $err = $@) {
	if (ref($err) && $err->isa('PVE::APIClient::Exception')) {
	    # we received additional info about the error, show the user
	    chomp $err->{msg};
	    warn "An error occured on the cluster node: $err->{msg}\n";
	    foreach my $key (sort keys %{$err->{errors}}) {
		my $symbol = ($key =~ m/^warning/) ? '*' : '!';
		warn "$symbol $err->{errors}->{$key}\n";
	    }

	    die "Cluster join aborted!\n";
	}

	die $@;
    }

    if (defined($res->{warnings})) {
	foreach my $warn (@{$res->{warnings}}) {
	    warn "cluster: $warn\n";
	}
    }

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
    PVE::Tools::run_command($cmd, errmsg => "can't stop pve-cluster service");

    my $dbfile = PVE::Cluster::cfs_backup_database();
    unlink $dbfile;

    $cmd = ['systemctl', 'start', 'corosync', 'pve-cluster'];
    PVE::Tools::run_command($cmd, errmsg => "starting pve-cluster failed");

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

    updatecerts_and_ssh(1);

    print "generated new node certificate, restart pveproxy and pvedaemon services\n";
    PVE::Tools::run_command(['systemctl', 'reload-or-restart', 'pvedaemon', 'pveproxy']);

    print "successfully added node '$nodename' to cluster.\n";
}

sub updatecerts_and_ssh {
    my ($force_new_cert, $silent) = @_;

    my $p = sub { print "$_[0]\n" if !$silent };

    setup_rootsshconfig();

    gen_pve_vzdump_symlink();

    if (!PVE::Cluster::check_cfs_quorum(1)) {
	return undef if $silent;
	die "no quorum - unable to update files\n";
    }

    setup_ssh_keys();

    my $nodename = PVE::INotify::nodename();
    my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);

    $p->("(re)generate node files");
    $p->("generate new node certificate") if $force_new_cert;
    gen_pve_node_files($nodename, $local_ip_address, $force_new_cert);

    $p->("merge authorized SSH keys and known hosts");
    ssh_merge_keys();
    ssh_merge_known_hosts($nodename, $local_ip_address, 1);
    gen_pve_vzdump_files();
}

1;
