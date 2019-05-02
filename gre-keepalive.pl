#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Std;
use Net::Pcap;
use Socket;

my %opts;
getopts("hvf", \%opts);
&usage if $opts{"h"};
my $dev = $ARGV[0] or usage("No device specified");
my $verbose = $opts{"v"} || 0;

if ($verbose) {
    $| = 1;
    print "starting gre-keepalive on device $dev\n";
}

unless ($opts{"f"}) {
    use Proc::Daemon;
    Proc::Daemon::Init;
}

socket(my $socket, AF_INET, SOCK_RAW, 255) || die $!;
setsockopt($socket, 0, 1, 1);

my $err;
my $pcap = Net::Pcap::open_live($dev, 1024, 0, 0, \$err);

my $filter = "proto gre";
my $filter_t;
if (Net::Pcap::compile($pcap, \$filter_t, $filter, 1, 0) == -1) {
    die "Unable to compile filter string '$filter'\n";
}
Net::Pcap::setfilter($pcap, $filter_t);

Net::Pcap::loop($pcap, -1, \&process_packet, $socket);

Net::Pcap::close($pcap);

sub process_packet {
    my ($socket, $header, $packet) = @_;

    print "process_packet: ", unpack("H*", $packet), "\n" if $verbose;
    # Strip the "cooked capture" header.
    $packet = unpack("x16a*", $packet);

    my $dest_ip = unpack("x16a4", $packet);
    if (!send($socket, $packet, 0, pack_sockaddr_in(0, $dest_ip))) {
        die "Couldn't send packet: $!";
    }
}

sub usage {
    print STDERR "Error: $_[0]\n" if @_;
    print <<EOF
Usage: gre-keepalive.pl [-hf] device
    -h  Show this message then exit.
    -v  Log incoming packets.
    -f  Run in foreground (don't fork).
EOF
    ;
    exit 1;
}
