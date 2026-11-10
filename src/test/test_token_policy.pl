use v5.36;

use Test::More;

use lib ('.', '..');

use PVE::DataCenterConfig;

# the policy is a property string, so it has to survive a parse and write round trip and it must
# not accept values that the enforcing side would not be able to interpret

my $parse = sub($value) {
    my $raw = (defined($value) ? "token-policy: $value\n" : '') . "keyboard: en-us\n";
    return PVE::DataCenterConfig::parse_datacenter_config('datacenter.cfg', $raw);
};

my $policy = $parse->('require-expiry=1,max-lifetime=86400')->{'token-policy'};
is($policy->{'require-expiry'}, 1, 'require-expiry is parsed');
is($policy->{'max-lifetime'}, 86400, 'max-lifetime is parsed');

$policy = $parse->('disallow-expiry-extension=1,require-privilege-separation=1')->{'token-policy'};
is($policy->{'disallow-expiry-extension'}, 1, 'disallow-expiry-extension is parsed');
is($policy->{'require-privilege-separation'}, 1, 'require-privilege-separation is parsed');

$policy = $parse->('max-lifetime=86400,default-to-max-lifetime=1')->{'token-policy'};
is($policy->{'default-to-max-lifetime'}, 1, 'default-to-max-lifetime is parsed');

is($parse->(undef)->{'token-policy'}, undef, 'an absent token-policy is not invented');

# an unusable policy has to be dropped, never half applied, and must not take the rest of the
# configuration down with it
for my $invalid (
    'max-lifetime=0',
    'max-lifetime=-1',
    'max-lifetime=forever',
    'require-expiry=maybe',
    'unknown-key=1',
) {
    my $cfg;
    {
        local $SIG{__WARN__} = sub { };
        $cfg = $parse->($invalid);
    }
    is($cfg->{'token-policy'}, undef, "'$invalid' does not yield a policy");
    is($cfg->{keyboard}, 'en-us', "'$invalid' does not break the rest of the config");
}

# writing has to turn the parsed hash back into the property string
my $raw = PVE::DataCenterConfig::write_datacenter_config(
    'datacenter.cfg',
    {
        'token-policy' => {
            'require-expiry' => 1,
            'max-lifetime' => 86400,
        },
    },
);
like(
    $raw,
    qr/^token-policy:\s*(require-expiry=1,max-lifetime=86400|max-lifetime=86400,require-expiry=1)$/m,
    'the policy is written back as a property string',
);

my $round_tripped = PVE::DataCenterConfig::parse_datacenter_config('datacenter.cfg', $raw);
is_deeply(
    $round_tripped->{'token-policy'},
    { 'require-expiry' => 1, 'max-lifetime' => 86400 },
    'the policy survives a write and parse round trip',
);

done_testing();
