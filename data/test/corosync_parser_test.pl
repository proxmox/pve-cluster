#!/usr/bin/perl

use lib '..';

use strict;
use warnings;

use Test::More;

use PVE::Corosync;

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
