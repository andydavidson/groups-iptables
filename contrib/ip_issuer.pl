#! /usr/bin/perl -w

use strict;
use warnings;
use IO::Socket;

unless (@ARGV > 1) { die "usage: $0 host ip secret"; }
my $host = shift(@ARGV);
my $ip   = shift(@ARGV);
my $pass = shift(@ARGV);

   $ip   = &check_ipv4($ip);

unless ($ip) { die "bad ip address $ip"; }


my $remote = IO::Socket::INET->new( Proto     => "tcp",
                                    PeerAddr  => $host,
				    PeerPort  => 1234,
                                  ) || die "Error creating socket: $!"  ;

$remote->autoflush(1);
print $remote "block $ip $pass";
close $remote;



sub check_ipv4($)
{
        my $ip_rgx = "\\d+\\.\\d+\\.\\d+\\.\\d+";
        my ($ip) = $_[0] =~ /($ip_rgx)/o;
        return undef unless $ip;

        for (split /\./, $ip ) 
        {
                return undef if $_ < 0 or $_ > 255;
        }
        return $ip;
}

