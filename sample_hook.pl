#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;

my %test = ();
my %recv_results = ();
my %send_results = ();

my $in_test_config = 0;
my $in_send_output = 0;
my $in_recv_output = 0;

while(<>) {
	chomp;

	my $line = $_;

	if ($line =~ /<TEST_CONFIG>/) {
		$in_test_config = 1;
		next;
	} elsif ($line =~ /<\/TEST_CONFIG>/) {
		$in_test_config = 0;
		next;
	} elsif ($line =~ /<RECV_OUTPUT>/) {
		$in_recv_output = 1;
		next;
	} elsif ($line =~ /<\/RECV_OUTPUT>/) {
		$in_recv_output = 0;
		next;
	} elsif ($line =~ /<SEND_OUTPUT>/) {
		$in_send_output = 1;
		next;
	} elsif ($line =~ /<\/SEND_OUTPUT>/) {
		$in_send_output = 0;
		next;
	}

	if ($in_test_config) {
		parse_test_config_line(\%test, $line);
	} elsif ($in_send_output) {
		parse_tool_output_line(\%test, \%recv_results, $line);
	} elsif ($in_recv_output) {
		parse_tool_output_line(\%test, \%send_results, $line);
	}
}

print "Test: ";
print Dumper(\%test);
print "Send: ";
print Dumper(\%send_results);
print "Recv: ";
print Dumper(\%recv_results);



my $user;
my $bandwidth;
my $direction;
my $duration;

if (not $test{"user"}) {
	$user = "anonymous"
} else{
	$user = $test{"user"};
}

if ($test{"is_host_sender"} eq "YES") {
	$direction = "outgoing";
	$bandwidth = $send_results{"bandwidth"};
	$duration = $send_results{"duration"};
} else {
	$direction = "incoming";
	$bandwidth = $recv_results{"bandwidth"};
	$duration = $recv_results{"duration"};
}

print "User '$user' used $bandwidth Mbps of $direction bandwidth for $duration second(s)\n";

exit 0;



sub parse_test_config_line {
	my ($test, $line) = @_;

	if ($line =~ /^([^:]*): (.*)$/) {
		$test{$1} = $2;
	}
}

sub parse_tool_output_line {
	my ($test, $results, $line) = @_;

	if ($test->{tool} eq "iperf") {
		parse_iperf_output_line($test, $results, $line);
	} elsif ($test->{tool} eq "nuttcp") {
		parse_nuttcp_output_line($test, $results, $line);
	} elsif ($test->{tool} eq "thrulay") {
		parse_thrulay_output_line($test, $results, $line);
	}
}

sub parse_thrulay_output_line {
	my ($test, $results, $line) = @_;

	# Grab the duration
	if ($line =~ /duration = (\d+\.\d+)s/) {
		$results->{"duration"} = $1;
	}

	# Grab the bandwidth acheived and convert the Mbps
	if ($line =~ /throughput = (\d+\.\d+)Mb\/s/) {
		$results->{"throughput"} = $1 * 1000 * 1000;
	}
}

sub parse_iperf_output_line {
	my ($test, $results, $line) = @_;

	if ($line =~ /0.0-(\d+.\d).*(\d+) ([M|G|K]?)Bytes.*(\d+) ([M|G|K]?)Bits\/sec/) {
		# Grab the duration
		$results->{"duration"} = $1;

		# Grab the bandwidth acheived and convert the Mbps
		my $bandwidth = $4;
		if ($3 eq "G") {
			$bandwidth *= 1000;
		}
		if ($3 eq "K") {
			$bandwidth /= 1000;
		}
		if (not $3) {
			$bandwidth /= 1000*1000;
		}
		$results->{"bandwidth"} = $bandwidth;
	}
}

sub parse_nuttcp_output_line {
	my ($test, $results, $line) = @_;

	if ($line =~ /(\d+\.\d+) real seconds .* = (\d+\.\d+) Mbps/) {
		$results->{"duration"} = $1;
		$results->{"bandwidth"} = $2;
	}
}
