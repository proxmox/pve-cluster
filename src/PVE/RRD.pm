package PVE::RRD;

use strict;
use warnings;

use RRDs;

use PVE::Tools;

sub create_rrd_data {
    my ($rrdname, $timeframe, $cf) = @_;

    my $rrddir = "/var/lib/rrdcached/db";

    my $rrd = "$rrddir/$rrdname";

    # Format: [ resolution, number of data points/count]
    # Old ranges, pre PVE9
    my $setup_pve2 = {
        hour => [60, 60], # 1 min resolution, one hour
        day => [60 * 30, 70], # 30 min resolution, one day
        week => [60 * 180, 70], # 3 hour resolution, one week
        month => [60 * 720, 70], # 12 hour resolution, 1 month
        year => [60 * 10080, 70], # 7 day resolution, 1 year
    };

    my $setup = {
        hour => [60, 60], # 1 min resolution
        day => [60, 1440], # 1 min resolution, full day
        week => [60 * 30, 336], # 30 min resolution, 7 days
        month => [3600 * 6, 121], # 6 hour resolution, 30 days, need one more count. Otherwise RRD gets wrong $step
        year => [3600 * 6, 1140], # 6 hour resolution, 360 days
        decade => [86400 * 7, 570], # 1 week resolution, 10 years
    };

    if ($rrdname =~ /^pve2/) {
        $setup = $setup_pve2;
        $timeframe = "year" if $timeframe eq "decade"; # we only store up to one year in the old format
    }
    my $is_node = !!($rrdname =~ /^pve-node/);

    my ($reso, $count) = @{ $setup->{$timeframe} };
    my $ctime = $reso * int(time() / $reso);
    my $req_start = $ctime - $reso * $count;

    $cf = "AVERAGE" if !$cf;

    my @args = (
        "-s" => $req_start,
        "-e" => $ctime - 1,
        "-r" => $reso,
    );

    my $socket = "/var/run/rrdcached.sock";
    push @args, "--daemon" => "unix:$socket" if -S $socket;

    my ($start, $step, $names, $data) = RRDs::fetch($rrd, $cf, @args);

    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;

    die "got wrong time resolution ($step != $reso)\n"
        if $step != $reso;

    my $res = [];
    my $fields = scalar(@$names);
    for my $line (@$data) {
        my $entry = { 'time' => $start };
        $start += $step;
        for (my $i = 0; $i < $fields; $i++) {
            my $name = $names->[$i];
            if (defined(my $val = $line->[$i])) {
                $entry->{$name} = $val;
                $entry->{memavailable} = $val
                    if $is_node && $name eq 'memfree' && !exists($entry->{memavailable});
            } else {
                # leave empty fields undefined
                # maybe make this configurable?
            }
        }
        push @$res, $entry;
    }

    return $res;
}

sub create_rrd_graph {
    my ($rrdname, $timeframe, $ds, $cf) = @_;

    # Using RRD graph is clumsy - maybe it
    # is better to simply fetch the data, and do all display
    # related things with javascript (new extjs html5 graph library).

    my $rrddir = "/var/lib/rrdcached/db";

    my $rrd = "$rrddir/$rrdname";

    my @ids = PVE::Tools::split_list($ds);

    my $ds_txt = join('_', @ids);

    my $filename = "${rrd}_${ds_txt}.png";

    # Format: [ resolution, number of data points/count]
    # Old ranges, pre PVE9
    my $setup_pve2 = {
        hour => [60, 60], # 1 min resolution, one hour
        day => [60 * 30, 70], # 30 min resolution, one day
        week => [60 * 180, 70], # 3 hour resolution, one week
        month => [60 * 720, 70], # 12 hour resolution, 1 month
        year => [60 * 10080, 70], # 7 day resolution, 1 year
    };

    my $setup = {
        hour => [60, 60], # 1 min resolution
        day => [60, 1440], # 1 min resolution, full day
        week => [60 * 30, 336], # 30 min resolution, 7 days
        month => [3600 * 6, 121], # 6 hour resolution, 30 days, need one more count. Otherwise RRD gets wrong $step
        year => [3600 * 6, 1140], # 6 hour resolution, 360 days
        decade => [86400 * 7, 570], # 1 week resolution, 10 years
    };

    if ($rrdname =~ /^pve2/) {
        $setup = $setup_pve2;
        $timeframe = "year" if $timeframe eq "decade"; # we only store up to one year in the old format
    }

    my ($reso, $count) = @{ $setup->{$timeframe} };

    my @args = (
        "--imgformat" => "PNG",
        "--border" => 0,
        "--height" => 200,
        "--width" => 800,
        "--start" => -$reso * $count,
        "--end" => 'now',
        "--lower-limit" => 0,
    );

    my $socket = "/var/run/rrdcached.sock";
    push @args, "--daemon" => "unix:$socket" if -S $socket;

    my @coldef = ('#00ddff', '#ff0000');

    $cf = "AVERAGE" if !$cf;

    my $i = 0;
    foreach my $id (@ids) {
        my $col = $coldef[$i++] || die "fixme: no color definition";
        push @args, "DEF:${id}=$rrd:${id}:$cf";
        my $dataid = $id;
        if ($id eq 'cpu' || $id eq 'iowait') {
            push @args, "CDEF:${id}_per=${id},100,*";
            $dataid = "${id}_per";
        }
        push @args, "LINE2:${dataid}${col}:${id}";
    }

    push @args, '--full-size-mode';

    # we do not really store data into the file
    my $res = RRDs::graphv('-', @args);

    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;

    return { filename => $filename, image => $res->{image} };
}

1;
