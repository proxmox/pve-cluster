#!/usr/bin/perl -w

use strict;

use PVE::IPCC;

if (defined(my $res = PVE::IPCC::ipcc_send_rec(2))) {
    print "GOT: $res\n";
} else {
    die "ipcc_send_rec failed: $!\n";
}
exit 0;

my $i = 0;
    

for($i = 0; $i < 10000; $i++) {
    print "t1\n";
    print "c1: " . PVE::IPCC::ipcc_send_rec(1, "adas\0defg") . "\n";
    print "t1\n";
}

