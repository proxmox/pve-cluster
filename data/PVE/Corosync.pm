package PVE::Corosync;

use strict;
use warnings;

use Digest::SHA;
use Clone 'clone';
use Net::IP qw(ip_is_ipv6);

use PVE::Cluster;

my $basedir = "/etc/pve";

my $conf_array_sections = {
    node => 1,
    interface => 1,
};

# a very simply parser ...
sub parse_conf {
    my ($filename, $raw) = @_;

    return {} if !$raw;

    my $digest = Digest::SHA::sha1_hex(defined($raw) ? $raw : '');

    $raw =~ s/#.*$//mg;
    $raw =~ s/\r?\n/ /g;
    $raw =~ s/\s+/ /g;
    $raw =~ s/^\s+//;
    $raw =~ s/\s*$//;

    my @tokens = split(/\s/, $raw);

    my $conf = { 'main' => {} };

    my $stack = [];
    my $section = $conf->{main};

    while (defined(my $token = shift @tokens)) {
	my $nexttok = $tokens[0];

	if ($nexttok && ($nexttok eq '{')) {
	    shift @tokens; # skip '{'
	    my $new_section = {};
	    if ($conf_array_sections->{$token}) {
		$section->{$token} = [] if !defined($section->{$token});
		push @{$section->{$token}}, $new_section;
	    } elsif (!defined($section->{$token})) {
		$section->{$token} = $new_section;
	    } else {
		die "section '$token' already exists and not marked as array!\n";
	    }
	    push @$stack, $section;
	    $section = $new_section;
	    next;
	}

	if ($token eq '}') {
	    $section = pop @$stack;
	    die "parse error - uncexpected '}'\n" if !$section;
	    next;
	}

	my $key = $token;
	die "missing ':' after key '$key'\n" if ! ($key =~ s/:$//);

	die "parse error - no value for '$key'\n" if !defined($nexttok);
	my $value = shift @tokens;

	$section->{$key} = $value;
    }

    # make working with the config way easier
    my ($totem, $nodelist) = $conf->{main}->@{"totem", "nodelist"};
    $nodelist->{node} = { map { $_->{name} // $_->{ring0_addr} => $_ } @{$nodelist->{node}} };
    $totem->{interface} = { map { $_->{ringnumber} => $_ } @{$totem->{interface}} };

    $conf->{digest} = $digest;

    return $conf;
}

my $dump_section;
$dump_section = sub {
    my ($section, $prefix) = @_;

    my $raw = '';

    foreach my $k (sort keys %$section) {
	my $v = $section->{$k};
	if (ref($v) eq 'HASH') {
	    $raw .= $prefix . "$k {\n";
	    $raw .= &$dump_section($v, "$prefix  ");
	    $raw .=  $prefix . "}\n";
	    $raw .= "\n" if !$prefix; # add extra newline at 1st level only
	} elsif (ref($v) eq 'ARRAY') {
	    foreach my $child (@$v) {
		$raw .= $prefix . "$k {\n";
		$raw .= &$dump_section($child, "$prefix  ");
		$raw .=  $prefix . "}\n";
	    }
	} elsif (!ref($v)) {
	    $raw .= $prefix . "$k: $v\n";
	} else {
	    die "unexpected reference in config hash: $k => ". ref($v) ."\n";
	}
    }

    return $raw;
};

sub write_conf {
    my ($filename, $conf) = @_;

    my $c = clone($conf->{main}) // die "no main section";

    # retransform back for easier dumping
    my $hash_to_array = sub {
	my ($hash) = @_;
	return [ $hash->@{sort keys %$hash} ];
    };

    $c->{nodelist}->{node} = &$hash_to_array($c->{nodelist}->{node});
    $c->{totem}->{interface} = &$hash_to_array($c->{totem}->{interface});

    my $raw = &$dump_section($c, '');

    return $raw;
}

# read only - use atomic_write_conf method to write
PVE::Cluster::cfs_register_file('corosync.conf', \&parse_conf);
# this is read/write
PVE::Cluster::cfs_register_file('corosync.conf.new', \&parse_conf,
				\&write_conf);

sub check_conf_exists {
    my ($silent) = @_;

    $silent = $silent // 0;

    my $exists = -f "$basedir/corosync.conf";

    warn "Corosync config '$basedir/corosync.conf' does not exist - is this node part of a cluster?\n"
	if !$silent && !$exists;

    return $exists;
}

sub update_nodelist {
    my ($conf, $nodelist) = @_;

    $conf->{main}->{nodelist}->{node} = $nodelist;

    atomic_write_conf($conf);
}

sub nodelist {
    my ($conf) = @_;
    return clone($conf->{main}->{nodelist}->{node});
}

sub totem_config {
    my ($conf) = @_;
    return clone($conf->{main}->{totem});
}

# caller must hold corosync.conf cfs lock if used in read-modify-write cycle
sub atomic_write_conf {
    my ($conf, $no_increase_version) = @_;

    if (!$no_increase_version) {
	die "invalid corosync config: unable to read config version\n"
	    if !defined($conf->{main}->{totem}->{config_version});
	$conf->{main}->{totem}->{config_version}++;
    }

    PVE::Cluster::cfs_write_file("corosync.conf.new", $conf);

    rename("/etc/pve/corosync.conf.new", "/etc/pve/corosync.conf")
	|| die "activating corosync.conf.new failed - $!\n";
}

# for creating a new cluster with the current node
# params are those from the API/CLI cluster create call
sub create_conf {
    my ($nodename, %param) = @_;

    my $clustername = $param{clustername};
    my $nodeid = $param{nodeid} || 1;
    my $votes = $param{votes} || 1;

    my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);
    my $ring0_addr = $param{ring0_addr} // $local_ip_address;
    my $bindnet0_addr = $param{bindnet0_addr} // $ring0_addr;

    my $use_ipv6 = ip_is_ipv6($ring0_addr);
    die "ring 0 addresses must be from same IP family!\n"
	if $use_ipv6 != ip_is_ipv6($bindnet0_addr);

    my $conf = {
	totem => {
	    version => 2, # protocol version
	    secauth => 'on',
	    cluster_name => $clustername,
	    config_version => 0,
	    ip_version => $use_ipv6 ? 'ipv6' : 'ipv4',
	    interface => {
		0 => {
		    bindnetaddr => $bindnet0_addr,
		    ringnumber => 0,
		},
	    },
	},
	nodelist => {
	    node => {
		$nodename => {
		    name => $nodename,
		    nodeid => $nodeid,
		    quorum_votes => $votes,
		    ring0_addr => $ring0_addr,
		},
	    },
	},
	quorum => {
	    provider => 'corosync_votequorum',
	},
	logging => {
	    to_syslog => 'yes',
	    debug => 'off',
	},
    };

    die "Param bindnet1_addr set but ring1_addr not specified!\n"
	if (defined($param{bindnet1_addr}) && !defined($param{ring1_addr}));

    my $ring1_addr = $param{ring1_addr};
    my $bindnet1_addr = $param{bindnet1_addr} // $param{ring1_addr};

    if ($bindnet1_addr) {
	die "ring 1 addresses must be from same IP family as ring 0!\n"
	    if $use_ipv6 != ip_is_ipv6($bindnet1_addr) ||
	       $use_ipv6 != ip_is_ipv6($ring1_addr);

	$conf->{totem}->{interface}->{1} = {
	    bindnetaddr => $bindnet1_addr,
	    ringnumber => 1,
	};
	$conf->{totem}->{rrp_mode} = 'passive';
	$conf->{nodelist}->{node}->{$nodename}->{ring1_addr} = $ring1_addr;
    }

    return { main => $conf };
}

1;
