#!/usr/bin/perl

use lib '../../';

use strict;
use warnings;

use Data::Dumper;

use PVE::Tools;
use PVE::Cluster;

## For quick test you can add arbitrary fake tokens to token.cfg:
# echo 'root@pam 1234512345XXXXX' >> /etc/pve/priv/token.cfg

my $token = shift // '1234512345XXXXX';
my $userid = shift // 'root@pam';

my $res = PVE::Cluster::verify_token($userid, $token);

print "token '$userid $token' " . ($res ? '' : "not ") . "found\n";
