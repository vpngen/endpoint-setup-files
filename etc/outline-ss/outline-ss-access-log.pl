#!/bin/perl

use strict;
use Time::Local;

my %db;

while (my $line = <STDIN>) {
    chomp($line);
    my ($oss) = $line =~ /\soutline\-ss\-/;
    if (not $oss) {
        next;
    }

    if ((index($line, " TCP(") != -1) && (index($line, "Found cipher at index") != -1)) {
        my ($dt) = $line =~ m/D([^ ]+Z)/;
        my ($ky) = $line =~ m/TCP\(([^\)]+)/;
        $db{$dt} = $ky
    } elsif (index($line, " address ") != -1) {
        my ($dt) = $line =~ m/D([^ ]+Z)/;
        my ($ip) = $line =~ m/\saddress\s([0-9\.]+)/;
        my ($dx) = $line =~ m/\-ns\-([^[]+)/;
        if (($db{$dt}) && (defined $ARGV[0]) && (defined $ARGV[1])) {
            open my $in,  '<', "$ARGV[0]-$dx/$ARGV[1]";
            open my $out, '>', "$ARGV[0]-$dx/$ARGV[1].new" or die "Can't write new file: $!";

            my ($found_last_minute) = "";
            my ($current_last_minute) = "";
            while (<$in>) {
                if (index($_, $db{$dt}) != -1) {
                    $_ =~ m/\s([^ ]+):[0-9\.]+Z/;
                    $found_last_minute = $1;
                    $dt =~ m/([^ ]+):[0-9\.]+Z/;
                    $current_last_minute = $1;
                    next;
                }
                print $out $_;
            }
            if (not($found_last_minute eq "") && ($found_last_minute eq $current_last_minute)) {
                close $out;
                unlink "$ARGV[0]-$dx/$ARGV[1].new";
            } else {
                my @dts = split /[\-T:\.]/, $dt;
                print $out $db{$dt}, " ", $dt, " ", $ip, " ", timegm($dts[5], $dts[4], $dts[3], $dts[2], $dts[1], $dts[0]), "\n";

                close $out;
                unlink "$ARGV[0]-$dx/$ARGV[1]";
                rename "$ARGV[0]-$dx/$ARGV[1].new", "$ARGV[0]-$dx/$ARGV[1]";
            }
        }
    }
}
