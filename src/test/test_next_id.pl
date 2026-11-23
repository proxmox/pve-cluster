use v5.36;

use Test::More;

use lib ('.', '..');

use PVE::DataCenterConfig;

# the upper boundary is exclusive, so a range is only usable if upper is above lower, also when
# one side is left at its default (lower 100, upper 1000000)

my $write = sub($next_id) {
    return PVE::DataCenterConfig::write_datacenter_config('datacenter.cfg',
        { 'next-id' => $next_id });
};

for my $empty ('lower=300,upper=300', 'lower=400,upper=300', 'upper=100', 'lower=1000000') {
    eval { $write->($empty) };
    like($@, qr/^next-id: upper boundary/, "empty range '$empty' is rejected");
}

for my $valid ('lower=300,upper=301', 'upper=101', 'lower=999999', 'lower=300,upper=400,unique=1') {
    my $raw = eval { $write->($valid) };
    is($@, '', "range '$valid' is accepted");
    my $parsed = PVE::DataCenterConfig::parse_datacenter_config('datacenter.cfg', $raw // '');
    my $expected = { map { split(/=/, $_, 2) } split(/,/, $valid) };
    is_deeply(
        $parsed->{'next-id'},
        $expected,
        "range '$valid' survives a write and parse round trip",
    );
}

done_testing();
