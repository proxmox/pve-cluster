#!/usr/bin/perl -w -T

use strict;

use PVE::Cluster;
use PVE::INotify;
use PVE::AccessControl;
use Data::Dumper;

my $nodename = PVE::INotify::nodename();
PVE::Cluster::log_msg(1, "ident2", "msg1 öäü");
PVE::Cluster::log_msg(1, "root\@pam", "msg1 öäü");
#print PVE::Cluster::get_system_log(undef, 0);
exit 0;

#print PVE::Cluster::get_system_log(undef, 0);

#PVE::Cluster::cfs_update();

#my $res = PVE::Cluster::get_vmlist();
#print "TEST1: " . Dumper($res->{ids});

#exit 0;

while (1) {

    print "update start\n";
    PVE::Cluster::cfs_update();
    print "update end\n";

    my $res = PVE::Cluster::rrd_dump();
    print "RRDDATA:" . Dumper($res);

    #my $res = PVE::Cluster::cfs_file_version('user.cfg');
    #print "VER $res\n";

    sleep(1);
}
exit 0;

my $loopcount = 0;

while (1) {

    PVE::Cluster::update();

    PVE::Cluster::broadcast_vminfo({ count => $loopcount });

    my $res = PVE::Cluster::get_vminfo($nodename);
    print "TEST1: " . Dumper($res);

    if (defined($res = PVE::Cluster::get_config("cluster.conf"))) {
        print "TEST2: " . Dumper($res);
    } else {
        warn "get_config failed: $!\n";
    }

    $loopcount++;

    sleep(2);
}

