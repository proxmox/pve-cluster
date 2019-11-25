package PVE::DataCenterConfig;

use strict;
use warnings;

use PVE::JSONSchema;
use PVE::Tools;
use PVE::Cluster;

my $migration_format = {
    type => {
	default_key => 1,
	type => 'string',
	enum => ['secure', 'insecure'],
	description => "Migration traffic is encrypted using an SSH tunnel by " .
	  "default. On secure, completely private networks this can be " .
	  "disabled to increase performance.",
	default => 'secure',
    },
    network => {
	optional => 1,
	type => 'string', format => 'CIDR',
	format_description => 'CIDR',
	description => "CIDR of the (sub) network that is used for migration."
    },
};

my $ha_format = {
    shutdown_policy => {
	type => 'string',
	enum => ['freeze', 'failover', 'conditional', 'migrate'],
	description => "The policy for HA services on node shutdown. 'freeze' disables ".
	    "auto-recovery, 'failover' ensures recovery, 'conditional' recovers on ".
	    "poweroff and freezes on reboot. 'migrate' will migrate running services ".
	    "to other nodes, if possible. With 'freeze' or 'failover', HA Services will ".
	    "always get stopped first on shutdown.",
	verbose_description => "Describes the policy for handling HA services on poweroff ".
	    "or reboot of a node. Freeze will always freeze services which are still located ".
	    "on the node on shutdown, those services won't be recovered by the HA manager. ".
	    "Failover will not mark the services as frozen and thus the services will get ".
	    "recovered to other nodes, if the shutdown node does not come up again quickly ".
	    "(< 1min). 'conditional' chooses automatically depending on the type of shutdown, ".
	    "i.e., on a reboot the service will be frozen but on a poweroff the service will ".
	    "stay as is, and thus get recovered after about 2 minutes.",
	default => 'conditional',
    }
};

my $u2f_format = {
    appid => {
	type => 'string',
	description => "U2F AppId URL override. Defaults to the origin.",
	format_description => 'APPID',
	optional => 1,
    },
    origin => {
	type => 'string',
	description => "U2F Origin override. Mostly useful for single nodes with a single URL.",
	format_description => 'URL',
	optional => 1,
    },
};


PVE::JSONSchema::register_format('mac-prefix', \&pve_verify_mac_prefix);
sub pve_verify_mac_prefix {
    my ($mac_prefix, $noerr) = @_;

    if ($mac_prefix !~ m/^[a-f0-9][02468ace](?::[a-f0-9]{2}){0,2}:?$/i) {
	return undef if $noerr;
	die "value is not a valid unicast MAC address prefix\n";
    }
    return $mac_prefix;
}

my $datacenter_schema = {
    type => "object",
    additionalProperties => 0,
    properties => {
	keyboard => {
	    optional => 1,
	    type => 'string',
	    description => "Default keybord layout for vnc server.",
	    enum => PVE::Tools::kvmkeymaplist(),
	},
	language => {
	    optional => 1,
	    type => 'string',
	    description => "Default GUI language.",
	    enum => [
		'ca',
		'da',
		'de',
		'en',
		'es',
		'eu',
		'fa',
		'fr',
		'he',
		'it',
		'ja',
		'nb',
		'nn',
		'pl',
		'pt_BR',
		'ru',
		'sl',
		'sv',
		'tr',
		'zh_CN',
		'zh_TW',
	    ],
	},
	http_proxy => {
	    optional => 1,
	    type => 'string',
	    description => "Specify external http proxy which is used for downloads (example: 'http://username:password\@host:port/')",
	    pattern => "http://.*",
	},
	migration_unsecure => {
	    optional => 1,
	    type => 'boolean',
	    description => "Migration is secure using SSH tunnel by default. " .
	      "For secure private networks you can disable it to speed up " .
	      "migration. Deprecated, use the 'migration' property instead!",
	},
	migration => {
	    optional => 1,
	    type => 'string', format => $migration_format,
	    description => "For cluster wide migration settings.",
	},
	console => {
	    optional => 1,
	    type => 'string',
	    description => "Select the default Console viewer. You can either use the builtin java applet (VNC; deprecated and maps to html5), an external virt-viewer comtatible application (SPICE), an HTML5 based vnc viewer (noVNC), or an HTML5 based console client (xtermjs). If the selected viewer is not available (e.g. SPICE not activated for the VM), the fallback is noVNC.",
	    enum => ['applet', 'vv', 'html5', 'xtermjs'],
	},
	email_from => {
	    optional => 1,
	    type => 'string',
	    format => 'email-opt',
	    description => "Specify email address to send notification from (default is root@\$hostname)",
	},
	max_workers => {
	    optional => 1,
	    type => 'integer',
	    minimum => 1,
	    description => "Defines how many workers (per node) are maximal started ".
	      " on actions like 'stopall VMs' or task from the ha-manager.",
	},
	fencing => {
	    optional => 1,
	    type => 'string',
	    default => 'watchdog',
	    enum => [ 'watchdog', 'hardware', 'both' ],
	    description => "Set the fencing mode of the HA cluster. Hardware mode " .
	      "needs a valid configuration of fence devices in /etc/pve/ha/fence.cfg." .
	      " With both all two modes are used." .
	      "\n\nWARNING: 'hardware' and 'both' are EXPERIMENTAL & WIP",
	},
	ha => {
	    optional => 1,
	    type => 'string', format => $ha_format,
	    description => "Cluster wide HA settings.",
	},
	mac_prefix => {
	    optional => 1,
	    type => 'string',
	    format => 'mac-prefix',
	    description => 'Prefix for autogenerated MAC addresses.',
	},
	bwlimit => PVE::JSONSchema::get_standard_option('bwlimit'),
	u2f => {
	    optional => 1,
	    type => 'string',
	    format => $u2f_format,
	    description => 'u2f',
	},
    },
};

# make schema accessible from outside (for documentation)
sub get_datacenter_schema { return $datacenter_schema };

sub parse_datacenter_config {
    my ($filename, $raw) = @_;

    my $res = PVE::JSONSchema::parse_config($datacenter_schema, $filename, $raw // '');

    if (my $migration = $res->{migration}) {
	$res->{migration} = PVE::JSONSchema::parse_property_string($migration_format, $migration);
    }

    if (my $ha = $res->{ha}) {
	$res->{ha} = PVE::JSONSchema::parse_property_string($ha_format, $ha);
    }

    if (my $u2f = $res->{u2f}) {
	$res->{u2f} = PVE::JSONSchema::parse_property_string($u2f_format, $u2f);
    }

    # for backwards compatibility only, new migration property has precedence
    if (defined($res->{migration_unsecure})) {
	if (defined($res->{migration}->{type})) {
	    warn "deprecated setting 'migration_unsecure' and new 'migration: type' " .
	      "set at same time! Ignore 'migration_unsecure'\n";
	} else {
	    $res->{migration}->{type} = ($res->{migration_unsecure}) ? 'insecure' : 'secure';
	}
    }

    # for backwards compatibility only, applet maps to html5
    if (defined($res->{console}) && $res->{console} eq 'applet') {
	$res->{console} = 'html5';
    }

    return $res;
}

sub write_datacenter_config {
    my ($filename, $cfg) = @_;

    # map deprecated setting to new one
    if (defined($cfg->{migration_unsecure}) && !defined($cfg->{migration})) {
	my $migration_unsecure = delete $cfg->{migration_unsecure};
	$cfg->{migration}->{type} = ($migration_unsecure) ? 'insecure' : 'secure';
    }

    # map deprecated applet setting to html5
    if (defined($cfg->{console}) && $cfg->{console} eq 'applet') {
	$cfg->{console} = 'html5';
    }

    if (ref($cfg->{migration})) {
	my $migration = $cfg->{migration};
	$cfg->{migration} = PVE::JSONSchema::print_property_string($migration, $migration_format);
    }

    if (ref($cfg->{ha})) {
	my $ha = $cfg->{ha};
	$cfg->{ha} = PVE::JSONSchema::print_property_string($ha, $ha_format);
    }

    if (ref($cfg->{u2f})) {
	my $u2f = $cfg->{u2f};
	$cfg->{u2f} = PVE::JSONSchema::print_property_string($u2f, $u2f_format);
    }

    return PVE::JSONSchema::dump_config($datacenter_schema, $filename, $cfg);
}

PVE::Cluster::cfs_register_file('datacenter.cfg',
		  \&parse_datacenter_config,
		  \&write_datacenter_config);

1;
