#!/usr/bin/perl -w

# parses SNMP output for "interesting" information

use warnings;
use strict;

use Getopt::Long;
use Data::Dumper;
use Net::MAC::Vendor;
use Term::ANSIColor;

my ($host, $comm);
GetOptions(
	"h|host=s"	=> \$host,
	"c|comm=s"	=> \$comm,
);

sub Usage() {
	print <<EOF;

Usage: $0 -h <host name/IP> -c <community name>
EOF

	exit 1;
}

if (!defined($comm) || ($comm eq '')) {
	print colored("Need community string!\n", "red");
	&Usage();
}
if (!defined($host) || ($host eq '')) {
	print colored("Need hostname or IP!\n", "red");
	&Usage();
}

my @data = `snmpwalk -v1 -c $comm $host`;

my (%ips,%paths,%hexstr,%chrstr,%macs,%strs,%emails);
print "Found ".scalar(@data)." lines of SNMP data.\n";
#print Dumper(@data);

my $ip_r = qr/\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\s/;
my $email_r = qr/([a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z][a-z]+)/;

foreach my $line (@data) {
	if ($line =~ /$ip_r/) {
		my $ip = $1;
		$ips{$ip}++;
	}
	if ($line =~ /$email_r/) {
		my $em = $1;
		$emails{$em}++;
	}
	if ($line =~ /.*hex-string:(?:\s|\t)?([0123456789abcdef ]*)/si) {
		my $h = $1;
		$hexstr{$h}++;
	}
	if ($line =~ /.* = string: (.*)/i) {
		my $s = $1;
		$strs{$s}++;
		if ($s =~ /(.*\\.*)/) {
			my $p = $1;
			$paths{$p}++;
		}
	} 
}

foreach my $hk ( keys(%hexstr) ) {
	my @pairs = split(/\s/, $hk);
	next if (scalar(@pairs) < 3);
	if (scalar(@pairs) == 6) {
		#probably a MAC
		my $tmp = join(":", @pairs);
		$macs{$tmp}++;
	}
	foreach my $p ( @pairs ) {
		#print "$p | ".hex($p)." | ".chr(hex($p))." |\n";
		my $o = hex($p);
		if (($o > 32) && ($o < 128)) {
			#print "$p: $o\n";
			my $c = chr($o);
			$chrstr{$hk} .= $c;
		}
	}
	
}

print colored("Found ".scalar(keys(%ips))." unique IPs.\n", "green");
foreach my $k (sort(keys(%ips))) {
	print "\t$k\t$ips{$k}\n";
}

print colored("Found ".scalar(keys(%emails))." unique email addresses.\n", "green");
foreach my $k (sort(keys(%emails))) {	
	print "\t$k\t$emails{$k}\n";
}

print colored("Found ".scalar(keys(%hexstr))." unique hex strings.\n", "green");
#foreach my $k (sort(keys(%hexstr))) {
#	print "\t$k\t$hexstr{$k}\n";
#}

foreach my $hk ( keys(%chrstr) ) {
	print "\t$hk| $chrstr{$hk}\n";
}

print colored("\tThese look like MAC addresses:\n", "green");
foreach my $mk (keys(%macs)) {
	my $mv = &lookup_mac_vendor($mk);
	if ((!defined($mv)) || ($mv eq "")) { 
		$mv = "Unknown or invalid MAC.";
	}
	print "\t\t$mk\t$macs{$mk}\t($mv)\n";
}

print colored("Found ".scalar(keys(%strs))." unique strings.\n", "green");
foreach my $sk (keys(%strs)) {
	print "\t$sk\n";
}
print colored("\tThese look like filesystem paths:\n", "green");
foreach my $pk (keys(%paths)) {
	print "\t\t$pk\t$paths{$pk}\n";
}

sub lookup_mac_vendor() {
	my $_mac = shift(@_);
	if ((defined($_mac)) && ($_mac ne "")) {
		my $arr;
		eval{ $arr = Net::MAC::Vendor::lookup($_mac); };
		if ((defined($@)) && ($@ ne "")) {
			return "Unknown or invalid MAC.";
		} else {
			return $arr->[0];
		}
	} else {
		return "Unknown or invalid MAC";
	}
}
