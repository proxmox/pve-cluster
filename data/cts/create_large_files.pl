#!/usr/bin/perl -w

use strict;
use POSIX;
use File::Path qw(make_path remove_tree);
use IO::File;

my (undef, $nodename) = POSIX::uname();

sub safe_mkdir {
    my $dir = shift;
    (mkdir $dir) || die "safe_mkdir $dir failed - $!\n";
}

my $data = "0" x (1024*100);

sub create_file {
    my ($filename) = shift;

    my $fh = new IO::File $filename, O_RDWR|O_CREAT|O_EXCL;
    die "cant create file $filename - $!" if !defined $fh;

    #my $data = "$filename\n" x 30;

    (print $fh $data) || die "write $filename failed\n";
    close ($fh);

    #system("cat $filename");
    #system("df -h /etc/pve");
}

my $testdir = "/etc/pve/manyfilestest/";

remove_tree($testdir);

safe_mkdir $testdir;

for (my $i = 0; $i < 300; $i++) {

    create_file("$testdir/test$i.dat");
}
