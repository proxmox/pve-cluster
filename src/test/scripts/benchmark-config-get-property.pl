#!/usr/bin/perl

use lib '../../';

use strict;
use warnings;

#use Data::Dumper;
use Time::HiRes qw( gettimeofday tv_interval );

use PVE::Tools;
use PVE::Cluster;
use PVE::QemuConfig;
use PVE::LXC::Config;

sub sec_to_unit {
    my $sec = shift;

    my $unit_index = 0;
    while ($sec < 1) {
        $sec *= 1000;
        $unit_index++;
    }

    my $unit = @{ ['s', 'ms', 'us', 'ns', 'ps'] }[$unit_index];

    return wantarray ? ($sec, $unit) : "$sec $unit";

}

my $results = {};

sub perf {
    my ($name, $loops, $code) = @_;

    return if !defined($loops) || $loops <= 0;

    my $loop = 0;
    eval {
        my $t0 = [gettimeofday];

        for (my $i = 0; $i < $loops; $i++) {
            $code->();
        }

        my $elapsed = tv_interval($t0, [gettimeofday]);

        my $total = sec_to_unit($elapsed);
        my $per_loop = $elapsed / $loops;
        $loop = sec_to_unit($per_loop);

        $results->{$name} = [$elapsed * 1000, $per_loop * 1000];

        print STDERR "elapsed['$name' x $loops]: $total => $loop/loop\n";
    };
    warn $@ if $@;

    return $loop;
}

my $loops = shift // 3;
my $vmid = shift // 0;
my $prop = shift // 'lock';

perf(
    'cfg-get-prop',
    $loops,
    sub {
        my $res = PVE::Cluster::get_guest_config_property($prop, $vmid);
    },
);

PVE::Cluster::cfs_update();
perf(
    'perl-manual',
    $loops,
    sub {
        my $res = {};

        # modeled after the manager API cluster/resource call
        my $vmlist = PVE::Cluster::get_vmlist() || {};
        my $idlist = $vmlist->{ids} || {};
        foreach my $vmid (keys %$idlist) {

            my $data = $idlist->{$vmid};
            my $typedir = $data->{type} eq 'qemu' ? 'qemu-server' : 'lxc';

            my $conf = PVE::Cluster::cfs_read_file("nodes/$data->{node}/$typedir/$vmid.conf");

            my $v = $conf->{$prop};
            $res->{$vmid} = { $prop => $v } if defined($v);
        }
    },
);
#PVE::Cluster::get_tasklist('dev5');

my $a = $results->{'cfg-get-prop'};
my $b = $results->{'perl-manual'};
printf("$loops\t%.2f\t%.2f\t%.2f\t%.2f\n", $a->[0], $a->[1], $b->[0], $b->[1]);

#print "res: " . Dumper($res) ."\n";
