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

sub safe_rmdir {
    my $dir = shift;
    (rmdir $dir) || die "safe_rmdir $dir failed - $!\n";
}

sub safe_unlink {
    my $file = shift;
    (unlink $file) || die "safe_unlink $file failed - $!\n";
}

sub create_vmfile {
    my ($filename) = shift;

    my $fh = new IO::File $filename, O_RDWR | O_CREAT | O_EXCL;
    die "cant create file $filename - $!" if !defined $fh;

    #my $data = "$filename\n" x 30;
    my $data = "0" x 1024;

    (print $fh $data) || die "write $filename failed\n";
    close($fh);

    #system("cat $filename");
    #system("df -h /etc/pve");
}

sub start_vmtest {
    my ($subdir) = @_;

    for (my $i = 1000; $i < 1100; $i++) {
        my $filename = "$subdir/${i}.conf";
        create_vmfile($filename);
    }

    for (my $i = 1000; $i < 1100; $i++) {
        my $filename = "$subdir/${i}.conf";
        safe_unlink($filename);
    }
}

sub start_subtest {
    my ($subdir) = @_;

    safe_mkdir $subdir;

    start_vmtest($subdir);

    safe_rmdir $subdir;
}

sub start_test {
    my ($subdir) = @_;

    safe_mkdir $subdir;

    start_subtest("$subdir/qemu-server");

    safe_rmdir $subdir;
}

my $basedir = "/etc/pve/nodes/";

my $testdir = "$basedir/${nodename}-test1";

remove_tree($testdir);

while (1) {
    eval {
        local $SIG{INT} = sub { die "interrupted" };
        start_test("$testdir");
    };
    my $err = $@;

    system("date; df -h /etc/pve");

    die $err if $err;
}
