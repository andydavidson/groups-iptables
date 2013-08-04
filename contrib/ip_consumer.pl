#!/usr/bin/perl -w

use strict;
use IO::Socket;
use Getopt::Std;
use threads;
use Sys::Syslog;

$SIG{'PIPE'} = 'IGNORE';

## user must specify port to attach to with -p
## user can specify a secret, with -s, or defaults to 'secret'.
## user can specify a file to write blocked ips to, with -f, defaults to /tmp/incoming-ips
## user can specify a file containing whitelisted addresses (always ignore)

my %options=();
getopts("p:f:s:w:",\%options);
if (!$options{p})
{
	die "You have to tell me a port to connect to - use -p 1234 to bind to port 1234";
}

my $writefile = $options{ f} || "/tmp/incoming-ips";
my $secret    = $options{ s} || "secret";

my %whitelist;
my $message;
my $sock = new IO::Socket::INET ( LocalPort => $options{p},
                                  Proto     => "tcp",
                                  Listen    => 10,
                                  Reuse     => 1);
die "Did not bind to port $options{p} and create server." unless $sock;
$message = localtime() . " Server up ... [bound to port $options{p} and accepting clients]";
print $message."\n";
syslog("notice", $message); 

if ($options{ w})
{
	my $filename = $options{ w};
        open CONFIG, "<", $filename or return undef;
        my @config = <CONFIG>;
        close CONFIG;

        chomp @config;
        map { s/\s*#.*$//g } @config;
        map { s/^\s+$//g } @config;
        map { s/^\s*(.*?)\s*$/$1/g } @config;

	foreach (@config)
	{
		my $ip = &check_ipv4($_);
		if (defined($ip))
		{
			$whitelist{$ip} = "whitelisted";
			$message = localtime() . " Whitelisted IP $ip";
			print $message . "\n";
			syslog("notice", $message);

		}
	}
}

eval 
{ 
	threads->create( \&ClientConnect, $sock->accept, )->detach while 1;
};
print "ERR: $@" if $@;

sub ClientConnect
{ 
	my $client = shift;
	$client->autoflush(1);
	$message = localtime() . " [Connect from ".$client->peerhost."]";
	print $message . "\n";
	syslog("notice", $message);

	while (<$client>)
	{
		next unless /\S/;       # ignore blank line
		s/[\n\r]*$//;           # chomp() was only stripping the CR not the LF
		if (/^block\ (.*?)\ (.*?)$/)
		{
			if ($2 ne $secret)
			{
				$message = localtime() . " " . $client->peerhost . " sent block with bad secret.";
				print $message."\n";
				syslog("notice", $message);
				close $client;
				next;
			}
			if ($1 =~ /^10\./ || $1 =~ /^192\.168\./ || $1 =~ /^127\./)
			{
				$message= localtime() . " " . $client->peerhost . " sent strange request to block 127/8 or rfc1918 space.";
                                print $message."\n";
                                syslog("notice", $message);
				close $client;
				next;
			}
			if ($whitelist{$1})
			{
				$message = localtime() . " " . $client->peerhost . " sent request to block whitelisted ip.";
				print $message."\n";
                                syslog("notice", $message);
				close $client;
				next;
			}
			my $ip = &check_ipv4($1);
			unless (defined $ip)
	                {
				$message = localtime() . " " . $client->peerhost . " sent non ipv4 address for blocking.";
				print $message."\n";
                                syslog("notice", $message);
				close $client;
				next;
			}
			$message = localtime() . " Fairly legal looking request to block $ip from " . $client->peerhost;
			print $message."\n";
                        syslog("notice", $message);
			open OUTFILE, ">>", $writefile or return undef;
			print OUTFILE $ip."\n";
        		close OUTFILE;
			system("/usr/sbin/iptables -A INPUT -s $ip -j DROP");
			system("/usr/sbin/iptables -A INPUT -s $ip -j DROP");
	
		} else {
			$message = localtime() . " " . $client->peerhost . " send bad request.";
			print $message."\n";
                        syslog("notice", $message);
			close $client;
			next;
		}
	}
}



#####################
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

