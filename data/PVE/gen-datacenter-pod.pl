#!/usr/bin/perl -w

package main;

use strict;
use PVE::Tools;
use PVE::Cluster;
use PVE::PodParser;

my $schema = PVE::Cluster::get_datacenter_schema();

my $format = PVE::PodParser::dump_properties($schema->{properties});

my $parser = PVE::PodParser->new();
$parser->{include}->{format} = $format;
$parser->parse_from_file($0);

exit 0;

__END__

=head1 NAME

datacenter.cfg - Proxmox VE datacenter configuration file

=head1 SYNOPSYS

The /etc/pve/datacenter.cfg file is a configuration file for Proxmox
VE. It contains cluster wide default values used by all nodes.

=head1 FILE FORMAT

The file uses a simple colon separated key/value format. Each line has
the following format:

 OPTION: value

Blank lines in the file are ignored, and lines starting with a C<#>
character are treated as comments and are also ignored.

=head1 OPTIONS

=include format

=include pve_copyright
