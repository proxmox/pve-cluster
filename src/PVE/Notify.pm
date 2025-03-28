package PVE::Notify;

use strict;
use warnings;

use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_lock_file cfs_write_file);
use PVE::INotify;
use PVE::Tools;

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

    return $notification_config;
}

sub write_config {
    my ($notification_config) = @_;

    my ($config, $priv_config) = $notification_config->write_config();
    cfs_write_file('notifications.cfg', $config, 1);
    cfs_write_file('priv/notifications.cfg', $priv_config, 1);
}

my $send_notification = sub {
    my ($severity, $template_name, $template_data, $fields, $config) = @_;
    $config = read_config() if !defined($config);
    $config->send($severity, $template_name, $template_data, $fields);
};

sub notify {
    my ($severity, $template_name, $template_data, $fields, $config) = @_;
    $send_notification->(
        $severity,
        $template_name,
        $template_data,
        $fields,
        $config
    );
}

sub info {
    my ($template_name, $template_data, $fields, $config) = @_;
    $send_notification->(
        'info',
        $template_name,
        $template_data,
        $fields,
        $config
    );
}

sub notice {
    my ($template_name, $template_data, $fields, $config) = @_;
    $send_notification->(
        'notice',
        $template_name,
        $template_data,
        $fields,
        $config
    );
}

sub warning {
    my ($template_name, $template_data, $fields, $config) = @_;
    $send_notification->(
        'warning',
        $template_name,
        $template_data,
        $fields,
        $config
    );
}

sub error {
    my ($template_name, $template_data, $fields, $config) = @_;
    $send_notification->(
        'error',
        $template_name,
        $template_data,
        $fields,
        $config
    );
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

my $cached_fqdn;
sub common_template_data {
    # The hostname is already cached by PVE::INotify::nodename,
    # no need to cache it here as well.
    my $hostname = PVE::INotify::nodename();

    if (!$cached_fqdn) {
        $cached_fqdn = PVE::Tools::get_fqdn($hostname);
    }

    my $data = {
        hostname => $hostname,
        fqdn => $cached_fqdn,
    };

    my $cluster_info = PVE::Cluster::get_clinfo();

    if (my $d = $cluster_info->{cluster}) {
        $data->{"cluster-name"} = $d->{name};
    }

    return $data;
}

1;
