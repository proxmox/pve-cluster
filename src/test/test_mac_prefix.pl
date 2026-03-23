use strict;
use warnings;

use Test::More;

use lib ('.', '..');

use PVE::DataCenterConfig;

my $longest_prefix_len = 10;
my $prefix = "00:00:00:00:00:00";

# test that all sub-strings of $prefix longer than "00" and strictly shorter than
# "00:00:00:00" are OK
for (my $i = 0; $i <= length($prefix); $i++) {
    my $sub_prefix = substr($prefix, 0, $i);
    if (2 <= $i && $i <= $longest_prefix_len) {
        ok(
            PVE::DataCenterConfig::pve_verify_mac_prefix($sub_prefix),
            "$sub_prefix is a valid mac prefix",
        );
    } else {
        is(
            PVE::DataCenterConfig::pve_verify_mac_prefix($sub_prefix, 1),
            undef,
            "$sub_prefix is not valid mac prefix",
        );
    }
}

done_testing();
