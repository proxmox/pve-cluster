#!/usr/bin/perl

use lib '..';

use strict;
use warnings;

use Test::MockModule;
use Test::More;

use PVE::Corosync;

my $known_hosts = {
    "prox1" => "127.0.1.1",
    "prox1-ring1" => "127.0.2.1",
    "prox2" => "127.0.1.2",
    "prox2-ring1" => "127.0.2.2",
    "prox3" => "127.0.1.3",
    "prox3-ring1" => "127.0.2.3",
    "prox4" => "127.0.1.4",
    "prox4-ring1" => "127.0.2.4",
};

sub mocked_resolve {
    my ($hostname) = @_;

    foreach my $host (keys %$known_hosts) {
	return $known_hosts->{$host} if $hostname eq $host;
    }

    die "got unknown hostname '$hostname' during mocked resolve_hostname_like_corosync";
}

my $mocked_corosync_module = new Test::MockModule('PVE::Corosync');
$mocked_corosync_module->mock('resolve_hostname_like_corosync', \&mocked_resolve);

sub parser_self_check {
    my $cfg_fn = shift;

    my $outfile = "$cfg_fn.write";
    my ($config1, $config2, $raw1, $raw2);

    eval {
	# read first time
	$raw1 = PVE::Tools::file_get_contents($cfg_fn);
	$config1 = PVE::Corosync::parse_conf($cfg_fn, $raw1);

	# write config
	$raw2 = PVE::Corosync::write_conf(undef, $config1);
	# do not actually write cfg, but you can outcomment to do so, e.g. if
	# you want to use diff for easy comparision
	#PVE::Tools::file_set_contents($outfile, $raw2);

	# reparse written config (must be the same as config1)
	$config2 = PVE::Corosync::parse_conf(undef, $raw2);
    }; warn $@ if $@;

    # test verify_config
    my ($err, $warn) = PVE::Corosync::verify_conf($config1);
    die "verify_conf failed: " . join(" ++ ", @$err) if scalar(@$err);

    # do not care for whitespace differences
    delete $config1->{digest};
    delete $config2->{digest};

    is_deeply($config1, $config2, "self check hash: $cfg_fn");

    # do not care about extra new lines
    $raw1 =~ s/^\s*\n+//mg;
    $raw2 =~ s/^\s*\n+//mg;

    is($raw1, $raw2, "self check raw: $cfg_fn");
}

# exec tests
if (my $file = shift) {
    parser_self_check($file);
} else {
    foreach my $file (<corosync_configs/*.conf>) {
	parser_self_check($file);
    }
}

done_testing();
