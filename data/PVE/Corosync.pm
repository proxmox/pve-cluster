package PVE::Corosync;

use strict;
use warnings;

use Digest::SHA;
use Clone 'clone';

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

    die "no main section" if !defined($conf->{main});

    my $raw = &$dump_section($conf->{main}, '');

    return $raw;
}

sub conf_version {
    my ($conf, $noerr, $new_value) = @_;

    my $totem = $conf->{main}->{totem};
    if (defined($totem) && defined($totem->{config_version})) {
	$totem->{config_version} = $new_value if $new_value;
	return $totem->{config_version};
    }

    return undef if $noerr;

    die "invalid corosync config - unable to read version\n";
}

# read only - use "rename corosync.conf.new corosync.conf" to write
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

    delete $conf->{digest};

    my $version = conf_version($conf);
    conf_version($conf, undef, $version + 1);

    $conf->{main}->{nodelist}->{node} = [values %$nodelist];

    PVE::Cluster::cfs_write_file("corosync.conf.new", $conf);

    rename("/etc/pve/corosync.conf.new", "/etc/pve/corosync.conf")
	|| die "activate  corosync.conf.new failed - $!\n";
}

sub nodelist {
    my ($conf) = @_;

    my $nodelist = {};

    my $nodes = $conf->{main}->{nodelist}->{node};

    foreach my $node (@$nodes) {
	# use 'name' over 'ring0_addr' if set
	my $name = $node->{name} // $node->{ring0_addr};
	if ($name) {
	    $nodelist->{$name} = $node;
	}
    }

    return $nodelist;
}

sub totem_config {
    my ($conf) = @_;

    # we reorder elements from totem->interface and don't want to change $conf
    my $totem = clone($conf->{main}->{totem});
    my $ifs = $totem->{interface};

    $totem->{interface} = {};
    foreach my $if (@$ifs) {
	$totem->{interface}->{$if->{ringnumber}} = $if;
    }

    return $totem;
}

1;
