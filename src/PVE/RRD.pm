package PVE::RRD;

use strict;
use warnings;

use RRDs;

use PVE::Tools;

my $get_rrd_data = sub {
    my ($rrd, $cf, $is_node, $reso, $args, $res) = @_;
    my ($start, $step, $names, $data) = RRDs::fetch($rrd, $cf, @$args);

    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;

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
};

my sub get_old_rrd_path_if_exist {
    my ($basename) = @_;

    # we can have already migrated rrd files that have the .old suffix too
    if (-e "/var/lib/rrdcached/db/${basename}") {
        return "/var/lib/rrdcached/db/${basename}";
    } elsif (-e "/var/lib/rrdcached/db/${basename}.old") {
        return "/var/lib/rrdcached/db/${basename}.old";
    }

    return undef;
}

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
        month => [60 * 30, 1440], # 30 min resolution  30 days
        year => [3600 * 6, 1440], # 6 hour resolution, 360 days
        decade => [86400 * 7, 570], # 1 week resolution, 10 years
    };

    my $is_node = !!($rrdname =~ /^pve-node/);
    $cf = "AVERAGE" if !$cf;
    my $res = [];

    if ($rrdname =~ /^pve2/) {
        $setup = $setup_pve2;
        $timeframe = "year" if $timeframe eq "decade"; # we only store up to one year in the old format
    }

    my ($reso, $count) = @{ $setup->{$timeframe} };
    my $ctime = $reso * int(time() / $reso);
    my $req_start = $ctime - $reso * $count;

    my $last_old;
    # check if we have old rrd file and if the start point is still covered by
    # it, fetch that data from it for any data not available in the old file we
    # will fetch it from the new file.
    if ($rrdname =~ /pve-(?<type>node|vm|storage)-[0-9]*\.[0-9]*\/(?<resource>.*)/) {
        if (defined(my $old_rrd = get_old_rrd_path_if_exist("pve2-$+{type}/$+{resource}"))) {
            $last_old = RRDs::last($old_rrd);
            if ($req_start < $last_old) {
                my ($reso_old, $count_old) = @{ $setup_pve2->{$timeframe} };
                my $ctime_old = $reso_old * int(time() / $reso_old);
                my $req_start_old = $ctime_old - $reso_old * $count_old;
                my $args = [];
                push(@$args, "-s" => $req_start_old);
                push(@$args, "-e" => $last_old);
                push(@$args, "-r" => $reso_old);

                my $socket = "/var/run/rrdcached.sock";
                push @$args, "--daemon" => "unix:$socket" if -S $socket;

                $get_rrd_data->($old_rrd, $cf, $is_node, $reso_old, $args, $res);
            } else {
                $last_old = undef;
            }
        }
    }

    my $args = [
        '-s' => $last_old ? $last_old : $req_start,
        '-e' => $ctime - 1,
        '-r' => $reso,
    ];

    my $socket = "/var/run/rrdcached.sock";
    push @$args, "--daemon" => "unix:$socket" if -S $socket;

    $get_rrd_data->($rrd, $cf, $is_node, $reso, $args, $res);

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
        month => [60 * 30, 1440], # 30 min resolution  30 days
        year => [3600 * 6, 1440], # 6 hour resolution, 360 days
        decade => [86400 * 7, 570], # 1 week resolution, 10 years
    };

    if ($rrdname =~ /^pve2/) {
        $setup = $setup_pve2;
        $timeframe = "year" if $timeframe eq "decade"; # we only store up to one year in the old format
    }

    my ($reso, $count) = @{ $setup->{$timeframe} };
    my $ctime = $reso * int(time() / $reso);
    my $req_start = $ctime - $reso * $count;

    my ($last_old, $old_rrd);
    # check if we have old rrd file and if the start point is still covered by it
    if ($rrdname =~ /pve-(?<type>node|vm|storage)-[0-9]*\.[0-9]*\/(?<resource>.*)/) {
        if (defined($old_rrd = get_old_rrd_path_if_exist("pve2-$+{type}/$+{resource}"))) {
            $last_old = RRDs::last($old_rrd);
            if ($req_start >= $last_old) {
                $old_rrd = undef; # old RRD exist, but not needed to render requested time range.
            }
        }
    }

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
        my $dataid = $id;
        my $linedef = "DEF:${dataid}=$rrd:${id}:$cf";
        $linedef = "${linedef}:start=${last_old}" if defined($old_rrd); # avoid eventual overlap

        push @args, "${linedef}";

        if ($id eq 'cpu' || $id eq 'iowait') {
            push @args, "CDEF:${dataid}_per=${id},100,*";
            $dataid = "${id}_per";
        }
        push @args, "LINE2:${dataid}${col}:${id}";

        if (defined($old_rrd)) {
            my $dataid = "${id}old";
            push @args, "DEF:${dataid}=$old_rrd:${id}:${cf}";
            if ($id eq 'cpu' || $id eq 'iowait') {
                push @args, "CDEF:${dataid}_per=${dataid},100,*";
                $dataid = "${dataid}_per";
            }
            push @args, "LINE2:${dataid}${col}";
        }
    }

    push @args, '--full-size-mode';

    # we do not really store data into the file
    my $res = RRDs::graphv('-', @args);

    my $err = RRDs::error;
    die "RRD error: $err\n" if $err;

    return { filename => $filename, image => $res->{image} };
}

1;
