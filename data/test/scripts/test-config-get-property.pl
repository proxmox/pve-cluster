#!/usr/bin/perl

use lib '../../';

use strict;
use warnings;

use JSON;

use PVE::Tools;
use PVE::Cluster;

## for quick test do:
# echo 'lock: test' >> /etc/pve/lxc/104.conf

my $vmid = shift // 104;
my $prop = shift // 'lock';

my $res = PVE::Cluster::get_guest_config_property($prop, $vmid);

print "res: " . to_json($res, {utf8 => 1, pretty => 1}) ."\n";
