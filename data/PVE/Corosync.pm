package PVE::Corosync;

use strict;
use warnings;

use Digest::SHA;

use PVE::Cluster;

my $basedir = "/etc/pve";

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

    my $conf = { section => 'main', children => [] };

    my $stack = [];
    my $section = $conf;

    while (defined(my $token = shift @tokens)) {
	my $nexttok = $tokens[0];

	if ($nexttok && ($nexttok eq '{')) {
	    shift @tokens; # skip '{'
	    my $new_section = {
		section => $token,
		children => [],
	    };
	    push @{$section->{children}}, $new_section;
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

	push @{$section->{children}}, { key => $key, value => $value };
    }

    $conf->{digest} = $digest;

    return $conf;
}

my $dump_section;
$dump_section = sub {
    my ($section, $prefix) = @_;

    my $raw = $prefix . $section->{section} . " {\n";

    my @list = grep { defined($_->{key}) } @{$section->{children}};
    foreach my $child (sort {$a->{key} cmp $b->{key}} @list) {
	$raw .= $prefix . "  $child->{key}: $child->{value}\n";
    }

    @list = grep { defined($_->{section}) } @{$section->{children}};
    foreach my $child (sort {$a->{section} cmp $b->{section}} @list) {
	$raw .= &$dump_section($child, "$prefix  ");
    }

    $raw .= $prefix . "}\n\n";

    return $raw;

};

sub write_conf {
    my ($filename, $conf) = @_;

    my $raw = '';

    my $prefix = '';

    die "no main section" if $conf->{section} ne 'main';

    my @list = grep { defined($_->{key}) } @{$conf->{children}};
    foreach my $child (sort {$a->{key} cmp $b->{key}} @list) {
	$raw .= "$child->{key}: $child->{value}\n";
    }

    @list = grep { defined($_->{section}) } @{$conf->{children}};
    foreach my $child (sort {$a->{section} cmp $b->{section}} @list) {
	$raw .= &$dump_section($child, $prefix);
    }

    return $raw;
}

sub conf_version {
    my ($conf, $noerr, $new_value) = @_;

    foreach my $child (@{$conf->{children}}) {
	next if !defined($child->{section});
	if ($child->{section} eq 'totem') {
	    foreach my $e (@{$child->{children}}) {
		next if !defined($e->{key});
		if ($e->{key} eq 'config_version') {
		    if ($new_value) {
			$e->{value} = $new_value;
			return $new_value;
		    } elsif (my $version = int($e->{value})) {
			return $version;
		    }
		    last;
		}
	    }
	}
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

sub nodelist {
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
sub totem_config {
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

1;
