package PVE::Notify;

use strict;
use warnings;

use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_lock_file cfs_write_file);
use Proxmox::RS::Notify;

cfs_register_file(
    'notifications.cfg',
    \&parse_notification_config,
    \&write_notification_config,
);

cfs_register_file(
    'priv/notifications.cfg',
    \&parse_notification_config,
    \&write_notification_config,
);

my $mail_to_root_target = 'mail-to-root';

sub parse_notification_config {
    my ($filename, $raw) = @_;

    $raw = '' if !defined($raw);
    return $raw;
}

sub write_notification_config {
    my ($filename, $config) = @_;
    return $config;
}

sub lock_config {
    my ($code, $timeout) = @_;

    cfs_lock_file('notifications.cfg', $timeout, sub {
	cfs_lock_file('priv/notifications.cfg', $timeout, $code);
	die $@ if $@;
    });
    die $@ if $@;
}

sub read_config {
    my $config = cfs_read_file('notifications.cfg');
    my $priv_config = cfs_read_file('priv/notifications.cfg');

    my $notification_config = Proxmox::RS::Notify->parse_config($config, $priv_config);

    eval {
	# This target should always be available...
	$notification_config->add_sendmail_endpoint(
	    $mail_to_root_target,
	    undef,
	    ['root@pam'],
	    undef,
	    undef,
	    'Send mail to root@pam\'s email address'
	);
    };

    return $notification_config;
}

sub write_config {
    my ($notification_config) = @_;

    eval {
	# ... but don't persist it to the config.
	# Rationale: If it is in the config, the user might think
	# that it can be changed by editing the configuration there.
	# However, since we always add it in `read_config`, any changes
	# will be implicitly overridden by the default.

	# If users want's to change the configuration, they are supposed to
	# create a new sendmail endpoint.
	$notification_config->delete_sendmail_endpoint($mail_to_root_target);
    };

    my ($config, $priv_config) = $notification_config->write_config();
    cfs_write_file('notifications.cfg', $config);
    cfs_write_file('priv/notifications.cfg', $priv_config);
}

sub default_target {
    return $mail_to_root_target;
}

my $send_notification = sub {
    my ($target, $severity, $title, $message, $properties, $config) = @_;
    $config = read_config() if !defined($config);
    my ($module, $file, $line) = caller(1);

    # Augment properties with the source code location of the notify call
    my $props_with_source = {
	%$properties,
	source => {
	    module => $module,
	    file => $file,
	    line => $line,
	}
    };

    $config->send($target, $severity, $title, $message, $props_with_source);
};

sub notify {
    my ($target, $severity, $title, $message, $properties, $config) = @_;
    $send_notification->($target, $severity, $title, $message, $properties, $config);
}

sub info {
    my ($target, $title, $message, $properties, $config) = @_;
    $send_notification->($target, 'info', $title, $message, $properties, $config);
}

sub notice {
    my ($target, $title, $message, $properties, $config) = @_;
    $send_notification->($target, 'notice', $title, $message, $properties, $config);
}

sub warning {
    my ($target, $title, $message, $properties, $config) = @_;
    $send_notification->($target, 'warning', $title, $message, $properties, $config);
}

sub error {
    my ($target, $title, $message, $properties, $config) = @_;
    $send_notification->($target, 'error', $title, $message, $properties, $config);
}

sub check_may_use_target {
    my ($target, $rpcenv) = @_;
    my $user = $rpcenv->get_user();

    my $config = read_config();
    my $entities = $config->get_referenced_entities($target);

    for my $entity (@$entities) {
	$rpcenv->check($user, "/mapping/notification/$entity", [ 'Mapping.Use' ]);
    }
}

1;
