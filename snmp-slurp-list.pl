#!/usr/bin/perl -w

# parses SNMP output for "interesting" information

use warnings;
use strict;

use Getopt::Long;
use Data::Dumper;
use LWP::Simple;
use Term::ANSIColor;
#use Scalar::Util;

my ($host, $comm, $infile, $outfile, $workingdir);
GetOptions(
	'i|in=s'		=> \$infile,
	'o|out=s'		=> \$outfile,
	'h|host=s'		=> \$host,
	'c|comm=s'		=> \$comm,
	'd|directory=s'	=>	\$workingdir,
);

sub usage {
	print <<EOF;

Usage: $0 -c <community name> -i <input file> -o <output file> -d <working directory>
EOF

	exit 0;
}

if ((!defined($comm)) or ($comm eq '')) {
	print colored("Need community string!\n", "red");
	&usage();
}
if ((!defined($infile)) or ($infile eq '')) {
	print colored("Need an input file!\n", "red");
	&usage();
}
if ((!defined($outfile)) or ($outfile eq '')) {
	print colored("Need an output file!\n", "red");
	&usage();
}
if ((!defined($workingdir)) or ($workingdir eq '')) {
	print colored("No working directory specified.  Using _tmp_...\n", "yellow");
	$workingdir = "_tmp_";
}

if (! -e $workingdir ) {
	mkdir($workingdir);
} elsif ( -d $workingdir ) {
	print colored("Working directory already exists.\n", "yellow");
	print colored("Files may be overwritten.  Continue? (Y/n/q)\n", "yellow");
	my $ans = readline();
	chomp($ans);
	if ($ans =~ /([?:Nn][Oo]?|[Qq](?:[Uu][Ii][Tt])?)/) {
		print "Quitting.\n";
		exit 255;
	}
}

my $ip_r = qr/\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\s/;
my $email_r = qr/([a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z][a-z]+)/;
	
open IN, "<$infile" or die colored("Couldn't open input file: $!", "red");
open OUT, ">$outfile" or die colored("Couldn't open output file: $!", "red");
print OUT "community string,hostname,lines,ips,email addresses,hex strings,mac addresses,strings,paths\n";
while (my $host = <IN>) {
	chomp($host);
	my $csv_str = '';
	$csv_str = "$comm,$host";

	print colored("Processing $host with community string \"$comm\"...\n", "bright_black");
	my @data = `snmpwalk -v1 -c $comm $host`;

	my (%ips,%paths,%hexstr,%chrstr,%macs,%strs,%emails);
	print "Found ".scalar(@data)." lines of SNMP data for $host.\n";
	$csv_str .= ",".scalar(@data);
	#print Dumper(@data);

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

	if (scalar(@data) == 0) {
		$csv_str .= ",NA,NA,NA,NA,NA,NA\n";
		print colored($csv_str, "yellow");
		print OUT "$csv_str";
		next;
	}

	if ( ! -d "$workingdir/$host" ) { mkdir("$workingdir/$host"); }
	my ($ip_str, $email_str, $hexstr_str, $mac_str, $str_str, $path_str);
	print colored("Found ".scalar(keys(%ips))." unique IPs.\n", "green");
	my @generic_ips = qw/ 0.0.0.0 255.255.255.255 255.0.0.0 127.0.0.1 /;
	push @generic_ips, $host;
	if (scalar(keys(%ips)) > 0) {
		$ip_str = scalar(keys(%ips))." IPs";
		foreach my $k (sort { $ips{$b} <=> $ips{$a} } keys(%ips)) {
			open IPOUT, ">>$workingdir/$host/ips.txt" or die colored("Couldn't open file for appending: $!", "red");
			print IPOUT "$k\t$ips{$k}\n";
			close IPOUT or die colored("Theire was a problem closing the file: $!", "red");
		}
	} else {
		$ip_str = "-";
	}
	$csv_str .= ",$ip_str";

	print colored("Found ".scalar(keys(%emails))." unique email addresses.\n", "green");
	if (scalar(keys(%emails)) > 0) {
		foreach my $k (sort { $emails{$b} <=> $emails{$a} } keys(%emails)) {
			open MAILOUT, ">>$workingdir/$host/emails.txt" or die colored("Couldn't open file for appending: $!", "red");
			print MAILOUT "$k\t$emails{$k}\n";
			close MAILOUT or die colored("There was a problem closing the file: $!", "red");
		}
		$email_str = scalar(keys(%emails))." emails";
	} else {
		$email_str = "-";
	}
	$csv_str .= ",$email_str";

	print colored("Found ".scalar(keys(%hexstr))." unique hex strings.\n", "green");
	if (scalar(keys(%chrstr)) > 0) {
		$hexstr_str = scalar(keys(%chrstr))." hex strings";
		foreach my $hk ( keys(%chrstr) ) {
			open HEXOUT, ">>$workingdir/$host/hexstrs.txt" or die colored("Couldn't open file for appending: $!", "red");
			print HEXOUT "$hk\t$chrstr{$hk}\n";
			close HEXOUT or die colored("There was a problem closing the file: $!", "red");
		}
	} else {
		$hexstr_str = "-";
	}
	$csv_str .= ",$hexstr_str";

	print colored("Found ".scalar(keys(%macs))." unique MAC addresses.\n", "green");
	if (scalar(keys(%macs)) > 0) {
		$mac_str = scalar(keys(%macs))." MACs";
		foreach my $mk (keys(%macs)) {
			my $mv = &lookup_mac_vendor($mk);
			if ((!defined($mv)) || ($mv eq "")) { 
				$mv = "Unknown or invalid MAC.";
			}
			open MACOUT, ">>$workingdir/$host/macs.txt" or diecolored("Couldn't open file for appending: $!", "red");
			print MACOUT "$mk\t$macs{$mk}\t($mv)\n";
			close MACOUT or die colored("There was a problem closing the file: $!", "red");
		}
	} else {
		$mac_str = "-";
	}
	$csv_str .= ",$mac_str";

	print colored("Found ".scalar(keys(%strs))." unique strings.\n", "green");
	if (scalar(keys(%strs)) > 0) {
		$str_str = scalar(keys(%strs))." strings";
		foreach my $sk (keys(%strs)) {
			open STROUT, ">>$workingdir/$host/strings.txt" or die colored("Couldn't open file for appending: $!", "red");
			print STROUT "$sk\t$strs{$sk}\n";
			close STROUT or die colored("There was a problem closing the file: $!", "red");
		}
	} else {
		$str_str = "-";
	}
	$csv_str .= ",$str_str";

	print colored("Found ".scalar(keys(%paths))." possible path strings.\n", "green");
	if (scalar(keys(%paths)) > 0) {
		$path_str = scalar(keys(%paths))." paths";
		foreach my $pk (keys(%paths)) {
			open POUT, ">>$workingdir/$host/paths.txt" or die colored("Coulnd't open file for appensing: $!", "red");
			print POUT "$pk\t$paths{$pk}\n";
			close POUT or die colored("There was a problem closing this file: $!", "red");
		}
	} else {
		$path_str = "-";
	}
	$csv_str .= ",$path_str\n";
	print colored($csv_str, "bright_yellow");
	print OUT "$csv_str";
}
close IN or die colored("There was a problem closing the input file: $!", "red");
close OUT or die colored("There was a problem closing the output file: $!", "red");

###############################################################################
### Subs
###############################################################################
sub lookup_mac_vendor {
	my $_mac = shift(@_);
	if ((defined($_mac)) && ($_mac ne "")) {
		#my $arr;
		#eval{ $arr = Net::MAC::Vendor::lookup($_mac); };
		my $fmac = get("http://api.macvendors.com/$_mac");
		#if ((defined($@)) && ($@ ne "")) {
		#	return "Unknown or invalid MAC.";
		#} else {
		#	return $arr->[0];
		#}
		if (!defined($fmac)) {
			return "Unknown or invalid MAC address.";
		} else {
			return $fmac;
		}
	} else {
		return "Expected MAC address to lookup.  Got nothing.";
	}
}
