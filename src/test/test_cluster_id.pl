use v5.36;

use Test::MockModule;
use Test::More;

use lib ('.', '..');

use PVE::Cluster;

my $raw;
my $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->mock(
    get_config => sub {
        my ($path) = @_;
        die "unexpected path '$path'\n" if $path ne 'cluster-id';
        return $raw;
    },
);

my $cases = [
    ["abcdefghijklmnopqrst\n", 'abcdefghijklmnopqrst', 'valid ID'],
    ["uvwxyz234567abcdefgh\n", 'uvwxyz234567abcdefgh', 'valid ID with digits'],
    ['abcdefghijklmnopqrst', 'abcdefghijklmnopqrst', 'valid ID without newline'],
    [undef, undef, 'missing file'],
    ['', undef, 'empty file'],
    ["\n", undef, 'only a newline'],
    ["abcdefghijklmnopqrst\n\n", undef, 'trailing empty line'],
    ["abcdefghijklmnopqrst \n", undef, 'trailing space'],
    [" abcdefghijklmnopqrst\n", undef, 'leading space'],
    ["abcdefghijklmnopqrs\n", undef, 'too short'],
    ["abcdefghijklmnop\n", undef, '16 characters'],
    ["abcdefghijklmnopqrstu\n", undef, 'too long'],
    ['abcdefghijklmnopqrstu', undef, 'too long without newline'],
    ["ABCDEFGHIJKLMNOPQRST\n", undef, 'uppercase'],
    ["abcdefghijklmnopqr01\n", undef, 'digits outside the base32 alphabet'],
    ["abcdefghijklmnopqr89\n", undef, 'more digits outside the base32 alphabet'],
    ["abcdefgh\njklmnopqrst\n", undef, 'embedded newline'],
];

for my $case ($cases->@*) {
    my ($content, $expected, $name) = $case->@*;
    $raw = $content;
    is(PVE::Cluster::get_cluster_id(), $expected, $name);
}

done_testing();
