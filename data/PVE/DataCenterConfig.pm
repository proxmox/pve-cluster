package PVE::DataCenterConfig;

use strict;
use warnings;

use PVE::JSONSchema qw(parse_property_string);
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
	    "stay as is, and thus get recovered after about 2 minutes. ".
	    "Migrate will try to move all running services to another node when a reboot or ".
	    "shutdown was triggered. The poweroff process will only continue once no running services ".
	    "are located on the node anymore. If the node comes up again, the service will ".
	    "be moved back to the previously powered-off node, at least if no other migration, ".
	    "reloaction or recovery took place.",
	default => 'conditional',
    }
};

my $next_id_format = {
    lower => {
	type => 'integer',
	description => "Lower, inclusive boundary for free next-id API range.",
	min => 100,
	max => 1000 * 1000 * 1000 - 1,
	default => 100,
	optional => 1,
    },
    upper => {
	type => 'integer',
	description => "Upper, inclusive boundary for free next-id API range.",
	min => 100,
	max => 1000 * 1000 * 1000 - 1,
	default => 1000 * 1000, # lower than the maximum on purpose
	optional => 1,
    },
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

my $webauthn_format = {
    rp => {
	type => 'string',
	description =>
	    'Relying party name. Any text identifier.'
	    .' Changing this *may* break existing credentials.',
	format_description => 'RELYING_PARTY',
	optional => 1,
    },
    origin => {
	type => 'string',
	description =>
	    'Site origin. Must be a `https://` URL (or `http://localhost`).'
	    .' Should contain the address users type in their browsers to access'
	    .' the web interface.'
	    .' Changing this *may* break existing credentials.',
	format_description => 'URL',
	optional => 1,
    },
    id => {
	type => 'string',
	description =>
	    'Relying part ID. Must be the domain name without protocol, port or location.'
	    .' Changing this *will* break existing credentials.',
	format_description => 'DOMAINNAME',
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
	# FIXME: remove with 8.0 (add check to pve7to8!), merged into "migration" since 4.3
	migration_unsecure => {
	    optional => 1,
	    type => 'boolean',
	    description => "Migration is secure using SSH tunnel by default. " .
	      "For secure private networks you can disable it to speed up " .
	      "migration. Deprecated, use the 'migration' property instead!",
	},
	'next-id' => {
	    optional => 1,
	    type => 'string',
	    format => $next_id_format,
	    description => "Control the range for the free VMID auto-selection pool.",
	},
	migration => {
	    optional => 1,
	    type => 'string', format => $migration_format,
	    description => "For cluster wide migration settings.",
	},
	console => {
	    optional => 1,
	    type => 'string',
	    description => "Select the default Console viewer. You can either use the builtin java"
	        ." applet (VNC; deprecated and maps to html5), an external virt-viewer comtatible application (SPICE), an HTML5 based vnc viewer (noVNC), or an HTML5 based console client (xtermjs). If the selected viewer is not available (e.g. SPICE not activated for the VM), the fallback is noVNC.",
	    # FIXME: remove 'applet' with 8.0 (add pve7to8 check!)
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
	webauthn => {
	    optional => 1,
	    type => 'string',
	    format => $webauthn_format,
	    description => 'webauthn configuration',
	},
	description => {
	    type => 'string',
	    description => "Datacenter description. Shown in the web-interface datacenter notes panel."
		." This is saved as comment inside the configuration file.",
	    maxLength => 64 * 1024,
	    optional => 1,
	},
    },
};

# make schema accessible from outside (for documentation)
sub get_datacenter_schema { return $datacenter_schema };

sub parse_datacenter_config {
    my ($filename, $raw) = @_;

    $raw = '' if !defined($raw);

    # description may be comment or key-value pair (or both)
    my $comment = '';
    for my $line (split(/\n/, $raw)) {
	if ($line =~ /^\#(.*)\s*$/) {
	    $comment .= PVE::Tools::decode_text($1) . "\n";
	}
    }

    # parse_config ignores lines with # => use $raw
    my $res = PVE::JSONSchema::parse_config($datacenter_schema, $filename, $raw);

    $res->{description} = $comment;

    if (my $migration = $res->{migration}) {
	$res->{migration} = parse_property_string($migration_format, $migration);
    }

    if (my $next_id = $res->{'next-id'}) {
	$res->{'next-id'} = parse_property_string($next_id_format, $next_id);
    }

    if (my $ha = $res->{ha}) {
	$res->{ha} = parse_property_string($ha_format, $ha);
    }

    if (my $u2f = $res->{u2f}) {
	$res->{u2f} = parse_property_string($u2f_format, $u2f);
    }

    if (my $webauthn = $res->{webauthn}) {
	$res->{webauthn} = parse_property_string($webauthn_format, $webauthn);
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

    if (ref(my $migration = $cfg->{migration})) {
	$cfg->{migration} = PVE::JSONSchema::print_property_string($migration, $migration_format);
    }

    if (defined(my $next_id = $cfg->{'next-id'})) {
        $next_id = parse_property_string($next_id_format, $next_id) if !ref($next_id);

	my $lower = int($next_id->{lower} // $next_id_format->{lower}->{default});
	my $upper = int($next_id->{upper} // $next_id_format->{upper}->{default});

	die "lower ($lower) <= upper ($upper) boundary rule broken" if $lower > $upper;

	$cfg->{'next-id'} = PVE::JSONSchema::print_property_string($next_id, $next_id_format);
    }

    if (ref(my $ha = $cfg->{ha})) {
	$cfg->{ha} = PVE::JSONSchema::print_property_string($ha, $ha_format);
    }

    if (ref(my $u2f = $cfg->{u2f})) {
	$cfg->{u2f} = PVE::JSONSchema::print_property_string($u2f, $u2f_format);
    }

    if (ref(my $webauthn = $cfg->{webauthn})) {
	$cfg->{webauthn} = PVE::JSONSchema::print_property_string($webauthn, $webauthn_format);
    }

    my $comment = '';
    # add description as comment to top of file
    my $description = $cfg->{description} || '';
    foreach my $line (split(/\n/, $description)) {
	$comment .= '#' .  PVE::Tools::encode_text($line) . "\n";
    }
    delete $cfg->{description}; # add only as comment, no additional key-value pair
    my $dump = PVE::JSONSchema::dump_config($datacenter_schema, $filename, $cfg);

    return $comment . "\n" . $dump;
}

PVE::Cluster::cfs_register_file(
    'datacenter.cfg',
    \&parse_datacenter_config,
    \&write_datacenter_config,
);

1;
