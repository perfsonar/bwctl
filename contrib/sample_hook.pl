#!/usr/bin/perl

# The sample_hook.pl script is an example post hook script for bwctl. This
# script can be easily modified to perform any number of tasks with the
# resulting output or simply as a guide for how one might parse the output from
# the bwctl server.

my $facility = "daemon";

##########################
#  End of Configuration
##########################

use strict;
use warnings;

use Sys::Syslog;
use Data::Dumper;

my $arg = shift;

# Check if we're being asked to validate ourselves. If so, a more involved
# script might check that syslog is running or the database is accessible.
if ($arg and $arg eq "--validate") {
	print "Status: OK\n";
	exit(0);
}

# BWCTL will pass us the input via standard input. Grab all the input into the array @input.
my @input = <>;

my ($test, $recv_results, $send_results) = parse_input(\@input);

# The section here could be easily modified to report this information to
# syslog, email the results somewhere or store them in a database.

# Display the structure of the returned elements.
#print "Test: ";
#print Dumper($test);
#print "Send: ";
#print Dumper($send_results);
#print "Recv: ";
#print Dumper($recv_results);

# Create a summary of the test results for syslog
my $user;
my $bandwidth;
my $direction;
my $duration;
my $protocol;
my $sender;
my $receiver;
my $client;
my $limit_class;
my $start_time;
my $streams;

$limit_class = $test->{"limit_class"};
$start_time = $test->{"start_time"};
$receiver = $test->{"receiver"};
$sender = $test->{"sender"};
$protocol = ($test->{"use_udp"} eq "YES")?"UDP":"TCP";
$sender = $test->{"sender"};
$receiver = $test->{"receiver"};
$client = $test->{"client"};

$streams = $test->{"parallel_streams"};
if ($streams == 0) {
	$streams = 1;
}

# If the user field is unset, the user was anonymous
if (not $test->{"user"}) {
	$user = "anonymous";
} else{
	$user = $test->{"user"};
}

# The is_host_sender field will be either "YES" or "NO" depending on whether
# the bwctl instance executing the posthook was the sender.
if ($test->{"is_host_sender"} eq "YES") {
	$direction = "outgoing";

	if ($test->{tool} eq "thrulay") {
		# thrulay is a special case since no final result gets displayed on the send side
		$bandwidth = $recv_results->{"bandwidth"};
		$duration = $recv_results->{"duration"};
	} else {
		$bandwidth = $send_results->{"bandwidth"};
		$duration = $send_results->{"duration"};
	}
} else {
	$direction = "incoming";
	$bandwidth = $recv_results->{"bandwidth"};
	$duration = $recv_results->{"duration"};
}

my $res = "USER=$user LIMIT_CLASS=$limit_class BANDWIDTH=$bandwidth DIRECTION=$direction DURATION=$duration PROTOCOL=$protocol START_TIME=$start_time SENDER=$sender RECEIVER=$receiver CLIENT=$client STREAMS=$streams";
#print $res."\n";
openlog('bwctld','',$facility);
syslog('info', $res);
closelog;

exit 0;






# The 'parse_input' function takes an array of lines containing the results
# provided by the bwctl program. It then parses that input into 3 structures:
# test, recv_results and send_results.
#
# The test structure will be a hash containing the settings used for the test. 
# 
# The recv_results will be a hash containing the bandwidth and duration seen by
# the recv side for the given test. This might be empty if the host was not the
# receiver.
# 
# The send_results will be a hash containing the bandwidth and duration seen by
# the send side for the given test. This might be empty if the host was not the
# sender.
sub parse_input {
	my ($lines) = @_;

	my %test = ();
	my %recv_results = ();
	my %send_results = ();

	my $in_test_config = 0;
	my $in_send_output = 0;
	my $in_recv_output = 0;

	foreach my $line (@$lines) {
		chomp $line;

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
			parse_tool_output_line(\%test, \%send_results, $line);
		} elsif ($in_recv_output) {
			parse_tool_output_line(\%test, \%recv_results, $line);
		}
	}

	return (\%test, \%recv_results, \%send_results);
}

# The parse_test_config_line parses the lines describing the test settings.
#
# All those lines are of the form: 
#    variable: value
#
# The function fills in the passed 'test' hash with the variable it finds
sub parse_test_config_line {
	my ($test, $line) = @_;

	if ($line =~ /^([^:]*): (.*)$/) {
		$test->{$1} = $2;
	}
}

# The parse_tool_output_line parses the lines for the send/recv tool output.
# It simply checks what tool was used in the test and calls the function to
# parse that tools line.
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

# The parse_thrulay_output_line parses the lines for the send/recv thrulay output.
# It looks for duration/bandwidth entries in each line of the output and fills
# in the $results hash.
sub parse_thrulay_output_line {
	my ($test, $results, $line) = @_;

        # Grab the duration. There may be multiple "final" lines if a
        # multistream test occurred so grab the longest duration.
        if ($line =~ /duration = (\d+\.\d+)s/) {
                if (not $results->{"duration"} or $1 > $results->{"duration"}) {
                        $results->{"duration"} = $1;
                }
        }

        # Grab the bandwidth acheived and convert the Mbps. There may be
        # multiple "final" lines if a multistream test occurred.
        if ($line =~ /throughput = (\d+\.\d+)Mb\/s/) {
                if (not $results->{"bandwidth"}) {
                        $results->{"bandwidth"} = 0;
                }

                $results->{"bandwidth"} += $1;
        }
}

# The parse_iperf_output_line parses the lines for the send/recv iperf output.
# It looks for the 'footer' line in the output and fills in the $results hash.
sub parse_iperf_output_line {
	my ($test, $results, $line) = @_;

	if ($line =~ /0.0- ?(\d+.\d+) .*(\d+) ([M|G|K]?)Bytes *(\d+) ([M|G|K]?)[B|b]its\/sec/) {
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

# The parse_nuttcp_output_line parses the lines for the send/recv nuttcp output.
# It looks for the 'footer' line in the output and fills in the $results hash.
sub parse_nuttcp_output_line {
	my ($test, $results, $line) = @_;

	if ($line =~ /(\d+\.\d+) real seconds .* = (\d+\.\d+) Mbps/) {
		$results->{"duration"} = $1;
		$results->{"bandwidth"} = $2;
	}
}
