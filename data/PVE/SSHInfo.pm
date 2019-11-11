package PVE::SSHInfo;

use strict;
use warnings;

use PVE::Cluster;
use PVE::Tools;

sub get_ssh_info {
    my ($node, $network_cidr) = @_;

    my $ip;
    if (defined($network_cidr)) {
	# Use mtunnel via to get the remote node's ip inside $network_cidr.
	# This goes over the regular network (iow. uses get_ssh_info() with
	# $network_cidr undefined.
	# FIXME: Use the REST API client for this after creating an API entry
	# for get_migration_ip.
	my $default_remote = get_ssh_info($node, undef);
	my $default_ssh = ssh_info_to_command($default_remote);
	my $cmd =[@$default_ssh, 'pvecm', 'mtunnel',
	    '-migration_network', $network_cidr,
	    '-get_migration_ip'
	];
	PVE::Tools::run_command($cmd, outfunc => sub {
	    my ($line) = @_;
	    chomp $line;
	    die "internal error: unexpected output from mtunnel\n"
		if defined($ip);
	    if ($line =~ /^ip: '(.*)'$/) {
		$ip = $1;
	    } else {
		die "internal error: bad output from mtunnel\n"
		    if defined($ip);
	    }
	});
	die "failed to get ip for node '$node' in network '$network_cidr'\n"
	    if !defined($ip);
    } else {
	$ip = PVE::Cluster::remote_node_ip($node);
    }

    return {
	ip => $ip,
	name => $node,
	network => $network_cidr,
    };
}

sub ssh_info_to_command_base {
    my ($info, @extra_options) = @_;
    return [
	'/usr/bin/ssh',
	'-e', 'none',
	'-o', 'BatchMode=yes',
	'-o', 'HostKeyAlias='.$info->{name},
	@extra_options
    ];
}

sub ssh_info_to_command {
    my ($info, @extra_options) = @_;
    my $cmd = ssh_info_to_command_base($info, @extra_options);
    push @$cmd, "root\@$info->{ip}";
    return $cmd;
}

1;
