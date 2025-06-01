package PVE::RRD;

use strict;
use warnings;

use RRDs;

use PVE::Tools;

sub create_rrd_data {
    my ($rrdname, $timeframe, $cf) = @_;

    my $rrddir = "/var/lib/rrdcached/db";

    my $rrd = "$rrddir/$rrdname";

    my $setup = {
        hour => [60, 70],
        day => [60 * 30, 70],
        week => [60 * 180, 70],
        month => [60 * 720, 70],
        year => [60 * 10080, 70],
    };

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

    my $setup = {
        hour => [60, 60],
        day => [60 * 30, 70],
        week => [60 * 180, 70],
        month => [60 * 720, 70],
        year => [60 * 10080, 70],
    };

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
