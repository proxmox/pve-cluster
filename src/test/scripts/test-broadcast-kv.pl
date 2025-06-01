#!/usr/bin/perl

use lib '../../';

use strict;
use warnings;

use JSON;

use PVE::Tools;
use PVE::Cluster;

## first broadcast a value for a key then you can check if you get it back by
# omitting the value, or directly querys an already exisitng value (e.g., ceph
# stats)

my $k = shift // die "no key";
my $v = shift;

if (defined $v) {
    print "broadcasting kv pair ($k, $v)\n";
    PVE::Cluster::broadcast_node_kv($k, $v);
}

print "querying value for key: $k\n";
my $res = PVE::Cluster::get_node_kv($k);

print "res: " . to_json($res, { utf8 => 1, pretty => 1 }) . "\n";
