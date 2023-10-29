package PVE::DataCenterConfig;

use strict;
use warnings;

use PVE::JSONSchema qw(get_standard_option parse_property_string register_standard_option);
use PVE::Tools;
use PVE::Cluster;

# MA-L (large) assigned by IEEE
my $PROXMOX_OUI = 'BC:24:11';

my $crs_format = {
    ha => {
	type => 'string',
	enum => ['basic', 'static'],
	optional => 1,
	default => 'basic',
	description => "Use this resource scheduler mode for HA.",
	verbose_description => "Configures how the HA manager should select nodes to start or ".
	    "recover services. With 'basic', only the number of services is used, with 'static', ".
	    "static CPU and memory configuration of services is considered.",
    },
    'ha-rebalance-on-start' => {
	type => 'boolean',
	optional => 1,
	default => 0,
	description => "Set to use CRS for selecting a suited node when a HA services request-state"
	    ." changes from stop to start.",
    }
};

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

my $notification_format = {
    'package-updates' => {
	type => 'string',
	enum => ['auto', 'always', 'never'],
	description => "Control when the daily update job should send out notifications.",
	verbose_description => "Control how often the daily update job should send out notifications:\n"
	    ."* 'auto' daily for systems with a valid subscription, as those are assumed to be "
	    ." production-ready and thus should know about pending updates.\n"
	    ."* 'always' every update, if there are new pending updates.\n"
	    ."* 'never' never send a notification for new pending updates.\n",
	default => 'auto',
	optional => 1,
    },
    'target-package-updates' => {
	type => 'string',
	format_description => 'TARGET',
	description => "Control where notifications about available updates should be sent to.",
	verbose_description => "Control where notifications about available"
	    . " updates should be sent to."
	    . " Has to be the name of a notification target (endpoint or notification group)."
	    . " If the 'target-package-updates' parameter is not set, the system will send mails"
	    . " to root via a 'sendmail' notification endpoint.",
	optional => 1,
    },
    'fencing' => {
	type => 'string',
	enum => ['always', 'never'],
	description => "Control if notifications about node fencing should be sent.",
	verbose_description => "Control if notifications about node fencing should be sent.\n"
	    . "* 'always' always send out notifications\n"
	    . "* 'never' never send out notifications.\n"
	    . "For production systems, turning off node fencing notifications is not"
	    . "recommended!\n",
	default => 'always',
	optional => 1,
    },
    'target-fencing' => {
	type => 'string',
	format_description => 'TARGET',
	description => "Control where notifications about fenced cluster nodes should be sent to.",
	verbose_description => "Control where notifications about fenced cluster nodes"
	    . " should be sent to."
	    . " Has to be the name of a notification target (endpoint or notification group)."
	    . " If the 'target-fencing' parameter is not set, the system will send mails"
	    . " to root via a 'sendmail' notification endpoint.",
	optional => 1,
    },
    'replication' => {
	type => 'string',
	enum => ['always', 'never'],
	description => "Control if notifications for replication failures should be sent.",
	verbose_description => "Control if notifications for replication failures should be sent.\n"
	    . "* 'always' always send out notifications\n"
	    . "* 'never' never send out notifications.\n"
	    . "For production systems, turning off replication notifications is not"
	    . "recommended!\n",
	default => 'always',
	optional => 1,
    },
    'target-replication' => {
	type => 'string',
	format_description => 'TARGET',
	description => "Control where notifications for failed storage replication jobs should"
	    . " be sent to.",
	verbose_description => "Control where notifications for failed storage replication jobs"
	    . " should be sent to."
	    . " Has to be the name of a notification target (endpoint or notification group)."
	    . " If the 'target-replication' parameter is not set, the system will send mails"
	    . " to root via a 'sendmail' notification endpoint.",
	optional => 1,
    },
};

register_standard_option('pve-ha-shutdown-policy', {
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
});

my $ha_format = {
    shutdown_policy => get_standard_option('pve-ha-shutdown-policy'),
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
	description => "Upper, exclusive boundary for free next-id API range.",
	min => 100,
	max => 1000 * 1000 * 1000,
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
	    'Relying party ID. Must be the domain name without protocol, port or location.'
	    .' Changing this *will* break existing credentials.',
	format_description => 'DOMAINNAME',
	optional => 1,
    },
    'allow-subdomains' => {
	type => 'boolean',
	description => 'Whether to allow the origin to be a subdomain, rather than the exact URL.',
	optional => 1,
	default => 1,
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

my $COLOR_RE = '[0-9a-fA-F]{6}';
my $TAG_COLOR_OVERRIDE_RE = "(?:${PVE::JSONSchema::PVE_TAG_RE}:${COLOR_RE}(?:\:${COLOR_RE})?)";

my $tag_style_format = {
    'shape' => {
	optional => 1,
	type => 'string',
	enum => ['full', 'circle', 'dense', 'none'],
	default => 'circle',
	description => "Tag shape for the web ui tree. 'full' draws the full tag. "
	    ."'circle' draws only a circle with the background color. "
	    ."'dense' only draws a small rectancle (useful when many tags are assigned to each guest)."
	    ."'none' disables showing the tags.",
    },
    'color-map' => {
	optional => 1,
	type => 'string',
	pattern => "${TAG_COLOR_OVERRIDE_RE}(?:\;$TAG_COLOR_OVERRIDE_RE)*",
	typetext => '<tag>:<hex-color>[:<hex-color-for-text>][;<tag>=...]',
	description => "Manual color mapping for tags (semicolon separated).",
    },
    ordering => {
	optional => 1,
	type => 'string',
	enum => ['config', 'alphabetical'],
	default => 'alphabetical',
	description => 'Controls the sorting of the tags in the web-interface and the API update.',
    },
    'case-sensitive' => {
	type => 'boolean',
	description => 'Controls if filtering for unique tags on update should check case-sensitive.',
	optional => 1,
	default => 0,
    },
};

my $user_tag_privs_format = {
    'user-allow' => {
	optional => 1,
	type => 'string',
	enum => ['none', 'list', 'existing', 'free'],
	default => 'free',
	description => "Controls tag usage for users without `Sys.Modify` on `/` by either"
	    ." allowing `none`, a `list`, already `existing` or anything (`free`).",
	verbose_description => "Controls which tags can be set or deleted on resources a user"
	    ." controls (such as guests). Users with the `Sys.Modify` privilege on `/` are always"
	    ."unrestricted.\n"
	    ."* 'none' no tags are usable.\n"
	    ."* 'list' tags from 'user-allow-list' are usable.\n"
	    ."* 'existing' like list, but already existing tags of resources are also usable.\n"
	    ."* 'free' no tag restrictions.\n",
    },
    'user-allow-list' => {
	optional => 1,
	type => 'string',
	pattern => "${PVE::JSONSchema::PVE_TAG_RE}(?:\;${PVE::JSONSchema::PVE_TAG_RE})*",
	typetext => "<tag>[;<tag>...]",
	description => "List of tags users are allowed to set and delete (semicolon separated) "
	    ."for 'user-allow' values 'list' and 'existing'.",
    },
};

my $datacenter_schema = {
    type => "object",
    additionalProperties => 0,
    properties => {
	crs => {
	    optional => 1,
	    type => 'string', format => $crs_format,
	    description => "Cluster resource scheduling settings.",
	},
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
		'ar', # Arabic
		'ca', # Catalan
		'da', # Danish
		'de', # German
		'en', # English
		'es', # Spanish
		'eu', # Euskera (Basque)
		'fa', # Persian (Farsi)
		'fr', # French
		'hr', # Croatian
		'he', # Hebrew
		'it', # Italian
		'ja', # Japanese
		'ka', # Georgian
		'kr', # Korean
		'nb', # Norwegian (Bokmal)
		'nl', # Dutch
		'nn', # Norwegian (Nynorsk)
		'pl', # Polish
		'pt_BR', # Portuguese (Brazil)
		'ru', # Russian
		'sl', # Slovenian
		'sv', # Swedish
		'tr', # Turkish
		'ukr', # Ukrainian
		'zh_CN', # Chinese (Simplified)
		'zh_TW', # Chinese (Traditional)
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
	    # FIXME: remove 'applet' with 9.0 (add pve8to9 check!)
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
	    default => $PROXMOX_OUI,
	    description => "Prefix for the auto-generated MAC addresses of virtual guests. The"
		." default '$PROXMOX_OUI' is the OUI assigned by the IEEE to Proxmox Server Solutions"
		." GmbH for a 24-bit large MAC block. You're allowed to use this in local networks,"
		." i.e., those not directly reachable by the public (e.g., in a LAN or behind NAT)."
		,
	    verbose_description => "Prefix for the auto-generated MAC addresses of virtual guests."
		." The default `BC:24:11` is the Organizationally Unique Identifier (OUI) assigned"
		." by the IEEE to Proxmox Server Solutions GmbH for a MAC Address Block Large (MA-L)."
		." You're allowed to use this in local networks, i.e., those not directly reachable"
		." by the public (e.g., in a LAN or NAT/Masquerading).\n"
		." \nNote that when you run multiple cluster that (partially) share the networks of"
		." their virtual guests, it's highly recommended that you extend the default MAC"
		." prefix, or generate a custom (valid) one, to reduce the chance of MAC collisions."
		." For example, add a separate extra hexadecimal to the Proxmox OUI for each cluster,"
		." like `$PROXMOX_OUI:0` for the first, `$PROXMOX_OUI:1` for the second, and so on.\n"
		." Alternatively, you can also separate the networks of the guests logically, e.g.,"
		." by using VLANs.\n\nFor publicly accessible guests it's recommended that you get"
		." your own https://standards.ieee.org/products-programs/regauth/[OUI from the IEEE]"
		." registered or coordinate with your, or your hosting providers, network admins."
		,
	},
	notify => {
	    optional => 1,
	    type => 'string', format => $notification_format,
	    description => "Cluster-wide notification settings.",
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
	'tag-style' => {
	    optional => 1,
	    type => 'string',
	    description => "Tag style options.",
	    format => $tag_style_format,
	},
	'user-tag-access' => {
	    optional => 1,
	    type => 'string',
	    description => "Privilege options for user-settable tags",
	    format => $user_tag_privs_format,
	},
	'registered-tags' => {
	    optional => 1,
	    type => 'string',
	    description => "A list of tags that require a `Sys.Modify` on '/' to set and delete. "
		."Tags set here that are also in 'user-tag-access' also require `Sys.Modify`.",
	    pattern => "(?:${PVE::JSONSchema::PVE_TAG_RE};)*${PVE::JSONSchema::PVE_TAG_RE}",
	    typetext => "<tag>[;<tag>...]",
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
	if ($line =~ /^\#(.*)$/) {
	    $comment .= PVE::Tools::decode_text($1) . "\n";
	}
    }

    # parse_config ignores lines with # => use $raw
    my $res = PVE::JSONSchema::parse_config($datacenter_schema, $filename, $raw);

    $res->{description} = $comment;

    # it could be better to track that this is the default, and not explicitly set, but having
    # no MAC prefix is really not ideal, and overriding that here centrally catches all call sites
    $res->{mac_prefix} = $PROXMOX_OUI if !defined($res->{mac_prefix});

    if (my $crs = $res->{crs}) {
	$res->{crs} = parse_property_string($crs_format, $crs);
    }

    if (my $migration = $res->{migration}) {
	$res->{migration} = parse_property_string($migration_format, $migration);
    }

    if (my $next_id = $res->{'next-id'}) {
	$res->{'next-id'} = parse_property_string($next_id_format, $next_id);
    }

    if (my $ha = $res->{ha}) {
	$res->{ha} = parse_property_string($ha_format, $ha);
    }
    if (my $notify = $res->{notify}) {
	$res->{notify} = parse_property_string($notification_format, $notify);
    }

    if (my $u2f = $res->{u2f}) {
	$res->{u2f} = parse_property_string($u2f_format, $u2f);
    }

    if (my $webauthn = $res->{webauthn}) {
	$res->{webauthn} = parse_property_string($webauthn_format, $webauthn);
    }

    if (my $tag_style = $res->{'tag-style'}) {
	$res->{'tag-style'} = parse_property_string($tag_style_format, $tag_style);
    }

    if (my $user_tag_privs = $res->{'user-tag-access'}) {
	$res->{'user-tag-access'} =
	    parse_property_string($user_tag_privs_format, $user_tag_privs);

	if (my $user_tags = $res->{'user-tag-access'}->{'user-allow-list'}) {
	    $res->{'user-tag-access'}->{'user-allow-list'} = [split(';', $user_tags)];
	}
    }

    if (my $admin_tags = $res->{'registered-tags'}) {
	$res->{'registered-tags'} = [split(';', $admin_tags)];
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

    if (defined($cfg->{mac_prefix}) && uc($cfg->{mac_prefix}) eq $PROXMOX_OUI) {
	delete $cfg->{mac_prefix}; # avoid writing out default prefix
    }

    if (ref(my $crs = $cfg->{crs})) {
	$cfg->{crs} = PVE::JSONSchema::print_property_string($crs, $crs_format);
    }

    if (ref(my $migration = $cfg->{migration})) {
	$cfg->{migration} = PVE::JSONSchema::print_property_string($migration, $migration_format);
    }

    if (defined(my $next_id = $cfg->{'next-id'})) {
        $next_id = parse_property_string($next_id_format, $next_id) if !ref($next_id);

	my $lower = int($next_id->{lower} // $next_id_format->{lower}->{default});
	my $upper = int($next_id->{upper} // $next_id_format->{upper}->{default});

	die "lower ($lower) <= upper ($upper) boundary rule broken\n" if $lower > $upper;

	$cfg->{'next-id'} = PVE::JSONSchema::print_property_string($next_id, $next_id_format);
    }

    if (ref(my $ha = $cfg->{ha})) {
	$cfg->{ha} = PVE::JSONSchema::print_property_string($ha, $ha_format);
    }
    if (ref(my $notify = $cfg->{notify})) {
	$cfg->{notify} = PVE::JSONSchema::print_property_string($notify, $notification_format);
    }

    if (ref(my $u2f = $cfg->{u2f})) {
	$cfg->{u2f} = PVE::JSONSchema::print_property_string($u2f, $u2f_format);
    }

    if (ref(my $webauthn = $cfg->{webauthn})) {
	$cfg->{webauthn} = PVE::JSONSchema::print_property_string($webauthn, $webauthn_format);
    }

    if (ref(my $tag_style = $cfg->{'tag-style'})) {
	$cfg->{'tag-style'} = PVE::JSONSchema::print_property_string($tag_style, $tag_style_format);
    }

    if (ref(my $user_tag_privs = $cfg->{'user-tag-access'})) {
	if (my $user_tags = $user_tag_privs->{'user-allow-list'}) {
	    $user_tag_privs->{'user-allow-list'} = join(';', sort $user_tags->@*);
	}
	$cfg->{'user-tag-access'} =
	    PVE::JSONSchema::print_property_string($user_tag_privs, $user_tag_privs_format);
    }

    if (ref(my $admin_tags = $cfg->{'registered-tags'})) {
	$cfg->{'registered-tags'} = join(';', sort $admin_tags->@*);
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
