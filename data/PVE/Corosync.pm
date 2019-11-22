package PVE::Corosync;

use strict;
use warnings;

use Clone 'clone';
use Digest::SHA;
use Net::IP qw(ip_is_ipv6);
use Scalar::Util qw(weaken);
use Socket qw(AF_INET AF_INET6 inet_ntop);

use PVE::Cluster;
use PVE::JSONSchema;
use PVE::Tools;
use PVE::Tools qw($IPV4RE $IPV6RE);

my $basedir = "/etc/pve";

my $conf_array_sections = {
    node => 1,
    interface => 1,
};

my $corosync_link_format = {
    address => {
	default_key => 1,
	type => 'string', format => 'address',
	format_description => 'IP',
	description => "Hostname (or IP) of this corosync link address.",
    },
    priority => {
	optional => 1,
	type => 'integer',
	minimum => 0,
	maximum => 255,
	default => 0,
	description => "The priority for the link when knet is used in 'passive' mode. Lower value means higher priority.",
    },
};
my $corosync_link_desc = {
    type => 'string', format => $corosync_link_format,
    description => "Address and priority information of a single corosync link.",
    optional => 1,
};
PVE::JSONSchema::register_standard_option("corosync-link", $corosync_link_desc);

sub parse_corosync_link {
    my ($value) = @_;

    return undef if !defined($value);

    return PVE::JSONSchema::parse_property_string($corosync_link_format, $value);
}

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

    $nodelist->{node} = {
	map {
	    $_->{name} // $_->{ring0_addr} => $_
	} @{$nodelist->{node}}
    };
    $totem->{interface} = {
	map {
	    $_->{linknumber} // $_->{ringnumber} => $_
	} @{$totem->{interface}}
    };

    $conf->{digest} = $digest;

    return $conf;
}

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

    my $dump_section_weak;
    $dump_section_weak = sub {
	my ($section, $prefix) = @_;

	my $raw = '';

	foreach my $k (sort keys %$section) {
	    my $v = $section->{$k};
	    if (ref($v) eq 'HASH') {
		$raw .= $prefix . "$k {\n";
		$raw .= $dump_section_weak->($v, "$prefix  ");
		$raw .=  $prefix . "}\n";
		$raw .= "\n" if !$prefix; # add extra newline at 1st level only
	    } elsif (ref($v) eq 'ARRAY') {
		foreach my $child (@$v) {
		    $raw .= $prefix . "$k {\n";
		    $raw .= $dump_section_weak->($child, "$prefix  ");
		    $raw .=  $prefix . "}\n";
		}
	    } elsif (!ref($v)) {
		die "got undefined value for key '$k'!\n" if !defined($v);
		$raw .= $prefix . "$k: $v\n";
	    } else {
		die "unexpected reference in config hash: $k => ". ref($v) ."\n";
	    }
	}

	return $raw;
    };
    my $dump_section = $dump_section_weak;
    weaken($dump_section_weak);

    my $raw = $dump_section->($c, '');

    return $raw;
}

# read only - use atomic_write_conf method to write
PVE::Cluster::cfs_register_file('corosync.conf', \&parse_conf);
# this is read/write
PVE::Cluster::cfs_register_file('corosync.conf.new', \&parse_conf,
				\&write_conf);

sub check_conf_exists {
    my ($noerr) = @_;

    my $exists = -f "$basedir/corosync.conf";

    die "Error: Corosync config '$basedir/corosync.conf' does not exist - is this node part of a cluster?\n"
	if !$noerr && !$exists;

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

    my $link0 = parse_corosync_link($param{link0});
    $link0->{address} //= $local_ip_address;

    my $conf = {
	totem => {
	    version => 2, # protocol version
	    secauth => 'on',
	    cluster_name => $clustername,
	    config_version => 0,
	    ip_version => 'ipv4-6',
	    interface => {
		0 => {
		    linknumber => 0,
		},
	    },
	},
	nodelist => {
	    node => {
		$nodename => {
		    name => $nodename,
		    nodeid => $nodeid,
		    quorum_votes => $votes,
		    ring0_addr => $link0->{address},
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
    my $totem = $conf->{totem};

    $totem->{interface}->{0}->{knet_link_priority} = $link0->{priority}
	if defined($link0->{priority});

    my $link1 = parse_corosync_link($param{link1});
    if ($link1->{address}) {
	$conf->{totem}->{interface}->{1} = {
	    linknumber => 1,
	};
	$totem->{link_mode} = 'passive';
	$totem->{interface}->{1}->{knet_link_priority} = $link1->{priority}
	    if defined($link1->{priority});
	$conf->{nodelist}->{node}->{$nodename}->{ring1_addr} = $link1->{address};
    }

    return { main => $conf };
}

sub for_all_corosync_addresses {
    my ($corosync_conf, $ip_version, $func) = @_;

    my $nodelist = nodelist($corosync_conf);
    return if !defined($nodelist);

    # iterate sorted to make rules deterministic (for change detection)
    foreach my $node_name (sort keys %$nodelist) {
	my $node_config = $nodelist->{$node_name};
	foreach my $node_key (sort keys %$node_config) {
	    if ($node_key =~ /^(ring|link)\d+_addr$/) {
		my $node_address = $node_config->{$node_key};

		my($ip, $version) = resolve_hostname_like_corosync($node_address, $corosync_conf);
		next if !defined($ip);
		next if defined($version) && defined($ip_version) && $version != $ip_version;

		$func->($node_name, $ip, $version, $node_key);
	    }
	}
    }
}

# NOTE: Corosync actually only resolves on startup or config change, but we
# currently do not have an easy way to synchronize our behaviour to that.
sub resolve_hostname_like_corosync {
    my ($hostname, $corosync_conf) = @_;

    my $corosync_strategy = $corosync_conf->{main}->{totem}->{ip_version};
    $corosync_strategy = lc ($corosync_strategy // "ipv6-4");

    my $match_ip_and_version = sub {
	my ($addr) = @_;

	return undef if !defined($addr);

	if ($addr =~ m/^$IPV4RE$/) {
	    return ($addr, 4);
	} elsif ($addr =~ m/^$IPV6RE$/) {
	    return ($addr, 6);
	}

	return undef;
    };

    my ($resolved_ip, $ip_version) = $match_ip_and_version->($hostname);

    return ($resolved_ip, $ip_version) if defined($resolved_ip);

    my $resolved_ip4;
    my $resolved_ip6;

    my @resolved_raw;
    eval { @resolved_raw = PVE::Tools::getaddrinfo_all($hostname); };

    return undef if ($@ || !@resolved_raw);

    foreach my $socket_info (@resolved_raw) {
	next if !$socket_info->{addr};

	my ($family, undef, $host) = PVE::Tools::unpack_sockaddr_in46($socket_info->{addr});

	if ($family == AF_INET && !defined($resolved_ip4)) {
	    $resolved_ip4 = inet_ntop(AF_INET, $host);
	} elsif ($family == AF_INET6 && !defined($resolved_ip6)) {
	    $resolved_ip6 = inet_ntop(AF_INET6, $host);
	}

	last if defined($resolved_ip4) && defined($resolved_ip6);
    }

    # corosync_strategy specifies the order in which IP addresses are resolved
    # by corosync. We need to match that order, to ensure we create firewall
    # rules for the correct address family.
    if ($corosync_strategy eq "ipv4") {
	$resolved_ip = $resolved_ip4;
    } elsif ($corosync_strategy eq "ipv6") {
	$resolved_ip = $resolved_ip6;
    } elsif ($corosync_strategy eq "ipv6-4") {
	$resolved_ip = $resolved_ip6 // $resolved_ip4;
    } elsif ($corosync_strategy eq "ipv4-6") {
	$resolved_ip = $resolved_ip4 // $resolved_ip6;
    }

    return $match_ip_and_version->($resolved_ip);
}

1;
