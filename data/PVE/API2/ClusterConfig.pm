package PVE::API2::ClusterConfig;

use strict;
use warnings;
use PVE::Tools;
use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $result = [
	    { name => 'nodes' },
	    { name => 'totem' },
	    ];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'nodes',
    path => 'nodes',
    method => 'GET',
    description => "Corosync node list.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		node => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{node}" } ],
    },
    code => sub {
	my ($param) = @_;


	my $conf = PVE::Cluster::cfs_read_file('corosync.conf');
	my $nodelist = PVE::Cluster::corosync_nodelist($conf);

	return PVE::RESTHandler::hash_to_array($nodelist, 'node');
    }});

__PACKAGE__->register_method({
    name => 'totem',
    path => 'totem',
    method => 'GET',
    description => "Get corosync totem protocol settings.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => "object",
	properties => {},
    },
    code => sub {
	my ($param) = @_;


	my $conf = PVE::Cluster::cfs_read_file('corosync.conf');

	return PVE::Cluster::corosync_totem_config($conf);
    }});

1;
