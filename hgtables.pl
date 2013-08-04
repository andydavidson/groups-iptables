#! /usr/bin/perl -w

use strict;
use warnings;
use Carp;
use Switch;
use Sys::Syslog;
use Getopt::Std;
use Data::Dumper;

my $version='0.5-ad20080809';

##### open syslog connection
openlog("hgtables","ndelay,pid,ndelay","local0");
syslog("notice","Starting hgtables interpreter");

##### parse command line options
my %options;
getopt('Vdc:',\%options);

#if ($options{ V})
#{
#	print "hgtables - Version ".$version;
#	print "\n(c) Andy Davidson. Released under the Apache License 2.0.  2008.\n";
#	exit 0;
#}

unless (defined($options{ c}))
{
	print "hgtables - Version ".$version;
	print "\nSpecify config file to load using hgtables -c [configfilename]\n";
	syslog("err","Config file not specified on command line.");
	exit -1;
}

my $configfile=$options{ c};
syslog("info","Configuration file is $configfile");
our $tree = &readconfig($configfile);

# print Dumper ($tree);

unless ((defined($tree->{globals})) && (defined($tree->{rules})))
{
	print "hgtables - Version ".$version;
        print "\nSpecify valid hgtables configuration file only with -c.\n";
	syslog ("err","Assuming bad config file -- no rules or globals section");
	exit -1;
}

#### check that the ip addresses in the config file are all valid.
my @ip_errors;
my @hoststub = keys %{$tree->{addresses}};
foreach (@hoststub)
{
	my $hostcheck = $_;
	foreach (@{$tree->{addresses}{$hostcheck}})
	{
		my $ipcheck = $_;
		# print "$hostcheck is at $ipcheck\n";
		my ($ip,$mask) = split(/\//, $ipcheck);

		unless (defined($mask))
		{
			$mask = "32";
		}
		$ip = &check_ipv4($ip);

		unless (defined $ip)
		{
			push (@ip_errors, "$hostcheck has bad ip address configured, $ipcheck");
			next;
		}

		if ((defined $mask) && ($mask < 0 or $mask > 32))
		{
			push (@ip_errors, "$hostcheck has bad cidr subnet mask configured, \/$mask");
			next;
		}
	}
}
my $ip_errors = @ip_errors;
syslog ("debug", "Rationalisation complete.  number of errors found : $ip_errors");
unless ($ip_errors == 0)
{
	foreach (@ip_errors)
	{
		warn "$_\n";
		syslog("err",$_);
	}
	exit -1;
}

##### Will put lines to pass to the shell in this array.
my @commands;
my @error_console;
my $iptables_path = $tree->{globals}{iptablespath}->[0] || "/usr/sbin/iptables";

##### Flush the policies in place, set the default policy
push (@commands, "## wont make a good router without this");
push (@commands, "echo 1 > /proc/sys/net/ipv4/ip_forward");
push (@commands, "## flush rules in place");
push (@commands, "$iptables_path -F INPUT");
push (@commands, "$iptables_path -F OUTPUT");
push (@commands, "$iptables_path -F FORWARD");

# default input chain
my $dinput = $tree->{rules}{dinput}->[0] || "ACCEPT";

if (($dinput ne "ACCEPT") && ($dinput ne "DROP") && ($dinput ne "REJECT"))
{
	push (@error_console, "[rules] dinput must be either ACCEPT DROP or REJECT.  You said $dinput.");
	## continue to build rules to check for more errors, but don't run rules as the error count is >0 now.
}

# default output chain
my $doutput = $tree->{rules}{doutput}->[0];

if (($doutput ne "ACCEPT") && ($doutput ne "DROP") && ($doutput ne "REJECT"))
{
        push (@error_console, "[rules] doutput must be either ACCEPT DROP or REJECT.  You said $doutput.");
        ## continue to build rules to check for more errors, but don't run rules as the error count is >0 now.
}

# default forward chain
my $dforward = $tree->{rules}{dforward}->[0];

if (($dforward ne "ACCEPT") && ($dforward ne "DROP") && ($dforward ne "REJECT"))
{
        push (@error_console, "[rules] dforward must be either ACCEPT DROP or REJECT.  You said $dforward.");
        ## continue to build rules to check for more errors, but don't run rules as the error count is >0 now.
}

##### FIXME == put the default policies into @commands.


##### Load implicit permits then implicit denys from any included files.
my @alldeny;
my @allpermit;
foreach (@{$tree->{globals}{allpermit}})
{
	my $checkfile = $_;
	my @addresses = &read_addresslist($checkfile);
	foreach (@addresses)
	{
                my $ipcheck = $_;
                my ($ip,$mask) = split(/\//, $ipcheck);

                unless (defined($mask))
                {
                        $mask = "32";
                }
                $ip = &check_ipv4($ip);

                unless (defined $ip)
                {
                        push (@error_console, "Bad IP address in $checkfile (all permit file) - $ipcheck");
                        next;
                }

                if ((defined $mask) && ($mask < 0 or $mask > 32))
                {
                        push (@error_console, "In $checkfile (all permit file), bad subnet mask defined, \/$mask");
                        next;
                }
		push (@allpermit, $ipcheck);
	}
}

push (@commands, "## Host permit rules follow here (if any) :");
foreach (@allpermit)
{
	push (@commands, "$iptables_path -I INPUT -s $_ -j ACCEPT");
	push (@commands, "$iptables_path -I FORWARD -s $_ -j ACCEPT"); 
}


foreach (@{$tree->{globals}{alldeny}})
{
        my $checkfile = $_;
        my @addresses = &read_addresslist($checkfile);
        foreach (@addresses)
        {
                my $ipcheck = $_;
                my ($ip,$mask) = split(/\//, $ipcheck);

                unless (defined($mask))
                {
                        $mask = "32";
                }
                $ip = &check_ipv4($ip);

                unless (defined $ip)
                {
                        push (@error_console, "Bad IP address in $checkfile (all deny file) - $ipcheck");
                        next;
                }

                if ((defined $mask) && ($mask < 0 or $mask > 32))
                {
                        push (@error_console, "In $checkfile (all deny file), bad subnet mask defined, \/$mask");
                        next;
                }
                push (@alldeny, $ipcheck);
        }
}

push (@commands, "## Host deny messages follow here (if any):");
foreach (@alldeny)
{
        push (@commands, "$iptables_path -A INPUT -s $_ -j DROP");
        push (@commands, "$iptables_path -A FORWARD -s $_ -j DROP");
}


### temp allow tcp/22 into firewall.

push (@commands, "## allow tcp/22 into firewall");
push (@commands, "$iptables_path -A INPUT -s 0.0.0.0 --dport 22 -j ACCEPT");

### allow established sessions
push (@commands, "## allow existing sessions");
push (@commands, "$iptables_path -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT");

### allow localhost connections
push (@commands, "## allow traffic on loopback");
push (@commands, "$iptables_path -A INPUT -i lo -j ACCEPT");
push (@commands, "$iptables_path -A OUTPUT -o lo -j ACCEPT");

##### I think in future I will call this the dreaded rule loop.
# we call the 'from' rule the left rule, and the 'to' rule the right rule.
foreach (@{$tree->{rules}{rule}})
{
	my $rule = $_;
	if ($rule =~ /^from\ (.*?)\ to\ (.*?)\ (.*)$/)
	{
		# print "debug: fromto rule encoutered.  f $1.  t $2. a $3.\n";
		switch ($3)
		{
			case (m/^permit\ /)
			{
				my ($action, $transport, $port) = split(/\ /, $3);
				push (@commands, "## Real rule encountered (seen as permit rule) $rule");
				my @leftips  = &walk_members($1,$tree);
				my @rightips = &walk_members($2,$tree); 
	
				foreach (@leftips)
				{
					my $leftip=$_;
					foreach (@rightips)
					{
						my $rightip=$_;
						push (@commands, "$iptables_path -A FORWARD -p $transport -s $leftip -d $rightip --dport $port -j ACCEPT");
					}
				}
			}
			case (m/^deny\ /)
			{
				my ($action, $transport, $port) = split(/\ /, $3);
                                push (@commands, "## Real rule encountered (seen as deny rule) $rule");
                                # print "1 is $1, 2 is $2\n";
				my @leftips  = &walk_members($1,$tree);
                                my @rightips = &walk_members($2,$tree);

                                foreach (@leftips)
                                {
                                        my $leftip=$_;
                                        foreach (@rightips)
                                        {
                                                my $rightip=$_;
                                                push (@commands, "$iptables_path -A FORWARD -p $transport -s $leftip -d $rightip --dport $port -j DROP");
                                        }
                                }
        

			}
		}
	}
	
}


##### If there are any errors, don't let the firewall ruleset get run.
my $error_count = @error_console;
unless ($error_count == 0)
{
	foreach (@error_console)
	{
		warn "$_\n";
		syslog("err",$_);
		exit -1;
	}
}

foreach (@commands)
{
	print "$_\n";
}

### end

closelog;
exit 0;

sub walk_members($)
{
	my $context=shift;
	my $tree=shift;
	# print "context imported is $context\n";
	my @memberips;
	my @members = @{$tree->{$context}{member}};
	# print "members imported  -  @members\n";
	foreach (@members)
	{
		foreach (@{$tree->{addresses}{$_}})
		{
			push (@memberips, $_);
		}
	}
	return @memberips;
}

sub read_addresslist($)
{
	my $filename = shift;
	# read the configuration file
	open ADDRESSFILE, "<", $filename or return undef;
	my @config = <ADDRESSFILE>;
	close ADDRESSFILE;

	# clean up the configuration file
	chomp @config;
	map { s/\s*#.*$//g } @config;
	map { s/^\s+$//g } @config;
	map { s/^\s*(.*?)\s*$/$1/g } @config;
	@config = grep(!/^$/, @config);
	return @config;
}

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




sub readconfig($)
{
        my $filename = shift;
        my $tree;

        # brace, so the only variable that exists outside of the brace is $tree.
        {
                # read the configuration file
                open CONFIG, "<", $filename or return undef;
                my @config = <CONFIG>;
                close CONFIG;

                # clean up the configuration file
                chomp @config;
                map { s/\s*#.*$//g } @config;
                map { s/^\s+$//g } @config;
                map { s/^\s*(.*?)\s*$/$1/g } @config;
                @config = grep(!/^$/, @config);

                # parse the configuration file
                my $context;
                foreach (@config)
                {
                        if ($_ =~ /^\[(.*)\]$/)
                        {
                                $context = $1;
                        }
                        elsif ($_ =~ /^(.*?)\s*=\s*(.*)$/)
                        {
				next unless($context);
				$tree->{$context}{$1} ||= [];
                                push @{$tree->{$context}{$1}}, "$2";
                        }
                }
        }

	# Add some hard-coded contexts.
	push @{$tree->{addresses}{default_all4}},      "0.0.0.0/0";
	push @{$tree->{addresses}{default_mcast4}},    "224.0.0.0/4";
	push @{$tree->{addresses}{default_mcast4loc}}, "224.0.0.0/24";
	push @{$tree->{all4}{member}},      "default_all4";
	push @{$tree->{mcast4}{member}},    "default_mcast4";
	push @{$tree->{mcast4loc}{member}}, "default_mcast4loc";


        return $tree;
}

