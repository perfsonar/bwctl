#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long;
use XML::LibXML;
use Data::Dumper;

my $sender = "local";
my $sender_conf;
my $catcher = "local";
my $catcher_conf;
my $testfiles;
my $help;
my $bwctl_cmd;
my $bwctld_cmd;
my $skip;

my $opt_status = GetOptions(
        'sender|s:s' => \$sender,
        'sender-conf|S:s' => \$sender_conf,
        'catcher|c:s' => \$catcher,
        'catcher-conf|C:s' => \$catcher_conf,
        'bwctl:s' => \$bwctl_cmd,
        'bwctld:s' => \$bwctld_cmd,
        'tests|f=s' => \$testfiles,
        'skip|i=s' => \$skip,
        'help' => \$help,
        );

if (not $opt_status or $help) {
    print "$0: BWCTL Testing Framework\n";
    print " -s/--sender: specify an ip address for the sender\n";
    print " -S/--sender-conf: specify the configuration directory for the sender\n";
    print " -c/--catcher: specify an ip address for the destination\n";
    print " -C/--catcher-conf: specify the configuration directory for the catcher\n";
    print " -f/--tests: specify the file containing the set of tests to run\n";
    print " -i/--skip: skip the specified list of tests\n";
    print " --bwctl: the location of the bwctl binary\n";
    print " --bwctld: the location of the bwctld binary\n";
    print "--help: display this snappy help message\n";

    exit(1);
}

if ($catcher eq "client" and $sender eq "client") {
    print "Error: can't set both sender and catcher to 'client'\n";
    exit(2);
}

my %conf = ();
$conf{"sender"} = $sender;
$conf{"catcher"} = $catcher;
$conf{"bwctl_path"} = $bwctl_cmd;
$conf{"bwctld_path"} = $bwctld_cmd;
$conf{"sender_conf"} = $sender_conf;
$conf{"catcher_conf"} = $catcher_conf;

if (not $conf{"bwctl_path"}) {
    $conf{"bwctl_path"} = `which bwctl 2>&1`;
    chomp($conf{"bwctl_path"});
    if ($conf{"bwctl_path"} =~ /no bwctl/) {
        print "Error: no bwctl specified or found in path\n";
        exit(1);
    }
}

if (not $conf{"bwctld_path"}) {
    $conf{"bwctld_path"} = `which bwctld 2>&1`;
    chomp($conf{"bwctld_path"});
    if ($conf{"bwctld_path"} =~ /no bwctld/) {
        print "Error: no bwctld specified or found in path\n";
        exit(1);
    }
}

my @skip = ();
if ($skip) {
    @skip = split(',', $skip);
}

my ($status, $tests) = parseTestFile($testfiles);
if ($status != 0) {
    print "Couldn't parse test file: $tests\n";
    exit(1);
}

# Pre-emptively "skip" all the tests specified on the command-line
foreach my $id (@skip) {
    if ($tests->{$id}) {
        $tests->{$id}->{"status"} = "SKIPPED";
    }
}

my @remaining_tests = ();

# add all the tests onto the queue to perform
foreach my $id (keys %$tests) {
    unshift @remaining_tests, $id;
}

while($#remaining_tests > -1) {
    my $curr_id = $remaining_tests[0];
    my $test = $tests->{$curr_id};

    print "Current Test: ".$test->{"id"}."\n";

    # Don't run the test if we've already run it or it was skipped earlier.
    if ($test->{"status"}) {
        shift @remaining_tests;
        next;
    }

    # add any unmet dependencies to the queue
    if ($test->{"dependencies"}) {
        my $unmet_dependencies = 0;
        foreach my $id (@{ $test->{"dependencies"} }) {
            if (not $tests->{$id}->{"status"}) {
                print "Adding $id for $curr_id\n";
                unshift @remaining_tests, $id;
                $unmet_dependencies = 1;
            }
        }

        # If we have unmet dependencies, restart the process
        next if ($unmet_dependencies);
    }

    # All the dependencies have been run, so handle the test
    shift @remaining_tests;

    if ($test->{"dependencies"}) {
        my $skip_test = 0;

        foreach my $id (@{ $test->{"dependencies"} }) {
            my $dependent_test = $tests->{$id};

            if ($tests->{$id}->{"status"} eq "FAIL" or $tests->{$id}->{"status"} eq "SKIPPED") {
                $skip_test = 1;
                last;
            }
        }

        # If some of our dependencies were skipped or failed, mark us as such
        # and move on
        if ($skip_test) {
            print "Skipping $curr_id\n";
            $test->{"status"} = "SKIPPED";
            next;
        }
    }

    print "Running $curr_id\n";

    runTest(\%conf, $test);
}

foreach my $id (sort keys %$tests) {
    print "$id, ".$tests->{$id}->{"status"}."\n";
    if ($tests->{$id}->{"status"} eq "FAIL" and $tests->{$id}->{"results"}) {
        print "Results: \n";
        print $tests->{$id}->{"results"}."\n";
    }
}

exit(0);

sub spawnBwctld {
    my %args = @_;
    my $bwctld = $args{"bwctld"};
    my $args = $args{"args"};
    my $time_offset = $args{"time_offset"};
    my $conf_dir = $args{"conf_dir"};
    my $var_dir = $args{"var_dir"};

    my $pid = fork();
    if ($pid == 0) {
        if ($time_offset) {
            print "Setting time offset to $time_offset\n";
            $ENV{"BWCTL_DEBUG_TIMEOFFSET"} = $time_offset;
        }

        exec($bwctld . " -R $var_dir -Z $args -c $conf_dir &> out.".int(rand(1000)));
        exit(1);
    }

    return $pid;
}

sub runTest {
    my ($conf, $test) = @_;

    my ($catcher_pid, $sender_pid, $catcher_vardir, $sender_vardir);

    my $catcher = $conf->{"catcher"};
    my $sender = $conf->{"sender"};

    # If the catcher is defined as 'local', spawn a local bwctld
    if ($conf->{"catcher"} eq "local") {
        my $catcher_args = $test->{"catcher"}->{"args"};

        # Randomly generate a port assignment, set the bwctld argument so the
        # catcher will listen on that port and point the catcher variable at
        # to be spawned daemon
        my $port = 1024 + int(rand(5000));
        $catcher = "localhost:$port";
        $catcher_args .= " -S :$port";

        # We need a directory to hold the PID for this instance, so randomly
        # create one. It will be removed at the end of the test.
        do {
            $catcher_vardir = "/tmp/bwctl_tester.".int(rand(1000));
        } while(-d $catcher_vardir);

        mkdir($catcher_vardir);

        # If the test has a config directory for the catcher, use it.
        # If the person running the test has specified a directory, use that one
        # Otherwise, complain since our daemon will have no config file
        my $conf_dir = $test->{"catcher"}->{"conf_dir"};
        $conf_dir = $conf->{"catcher_conf"} if ($conf->{"catcher_conf"});

        if (not $conf_dir) {
            $test->{"status"} = "SKIPPED";
            goto OUT;
        }

        # spawn the local bwctld.
        $catcher_pid = spawnBwctld(bwctld => $conf->{"bwctld_path"}, args => $catcher_args, time_offset => $test->{"catcher"}->{"offset"}, conf_dir => $conf_dir, var_dir => $catcher_vardir);
    }

    # If the sender is defined as 'local', spawn a local bwctld
    if ($conf->{"sender"} eq "local") {
        my $sender_args = $test->{"sender"}->{"args"};

        # Randomly generate a port assignment, set the bwctld argument so the
        # catcher will listen on that port and point the catcher variable at
        # to be spawned daemon
        my $port = 1024 + int(rand(5000));
        $sender = "localhost:$port";
        $sender_args .= " -S :$port";

        # We need a directory to hold the PID for this instance, so randomly
        # create one. It will be removed at the end of the test.
        do {
            $sender_vardir = "/tmp/bwctl_tester.".int(rand(1000));
        } while(-d $sender_vardir);

        mkdir($sender_vardir);

        # If the test has a config directory for the sender, use it.
        # If the person running the test has specified a directory, use that one
        # Otherwise, complain since our daemon will have no config file
        my $conf_dir = $test->{"sender"}->{"conf_dir"};
        $conf_dir = $conf->{"sender_conf"} if ($conf->{"sender_conf"});

        if (not $conf_dir) {
            $test->{"status"} = "SKIPPED";
            goto OUT;
        }

        # spawn the local bwctld.
        $sender_pid = spawnBwctld(bwctld => $conf->{"bwctld_path"}, args => $sender_args, time_offset => $test->{"sender"}->{"offset"}, conf_dir => $conf_dir, var_dir => $sender_vardir);
    }

    # wait for the daemons to come up
    sleep(1);

    my $client_args = "";
    $client_args .= $test->{"client"}->{"args"};

    if ($conf->{"catcher"} eq "client") {
        $client_args .= " -s ".$sender;
    } elsif ($conf->{"sender"} eq "client") {
        $client_args .= " -c ".$catcher;
    } else {
        $client_args .= " -c ".$catcher." -s ".$sender;
    }

    # Set the local time offset
    if ($test->{"client"}->{"offset"}) {
        $ENV{"BWCTL_DEBUG_TIMEOFFSET"} = $test->{"client"}->{"offset"};
        print "Set client offset to ".$test->{"client"}->{"offset"}."\n";
    }

    my $cmd = $conf->{"bwctl_path"}." -x ".$client_args;
    my $data = `$cmd 2>&1`;

    $test->{"results"} = $data;

    foreach my $regex (@{ $test->{"failure_regexes"} }) {
        if ($data =~ /$regex/m) {
            $test->{"status"} = "FAIL";
            print "Failed on failure regex: '$regex'\n";
            last;
        }
    }

    foreach my $regex (@{ $test->{"success_regexes"} }) {
        if (!($data =~ /$regex/m)) {
            $test->{"status"} = "FAIL";
            print "Failed on success regex: '$regex'\n";
            last;
        }
    }

    if (not $test->{"status"}) {
        $test->{"status"} = "SUCCESS";
    }

OUT:
    if ($sender_pid) {
        kill('TERM', $sender_pid);
        # XXX fix this
        kill('TERM', $sender_pid+1);
        `rm -f $sender_vardir/*`;
        `rmdir $sender_vardir`;
    }

    if ($catcher_pid) {
        kill('TERM', $catcher_pid);
        # XXX fix this
        kill('TERM', $catcher_pid+1);
        `rm -f $catcher_vardir/*`;
        `rmdir $catcher_vardir`;
    }
}

sub parseTestFile {
    my ($file) = shift;

    my $dom;
    eval {
        $dom = XML::LibXML->new->parse_file($file);
    };
    if ($@) {
        chomp($@);
        return (-1, $@);
    }

    my %tests = ();

    foreach my $test ($dom->documentElement->getElementsByTagName("test")) {
        my $id = $test->getAttribute("id");

        if (not $id) {
            return (-1, "Test missing identifier");
        }

        if ($id and $tests{$id}) {
            return (-1, "Multiple tests with id $id");
        }

        my $depends = $test->findvalue("dependencies");
        my $client_args = $test->findvalue("./client/cmd_args");
        my $catcher_args = $test->findvalue("./catcher/cmd_args");
        my $catcher_config_dir = $test->findvalue("./catcher/config_dir");
        my $sender_args = $test->findvalue("./sender/cmd_args");
        my $sender_config_dir = $test->findvalue("./sender/config_dir");

        my @dependencies;
        if ($depends) {
            @dependencies = split(/,/, $depends);
        } else {
            @dependencies = ();
        }

        if ($client_args) {
            $client_args =~ s/^\s+//;
            $client_args =~ s/\s+$//;
        }

        if ($catcher_args) {
            $catcher_args =~ s/^\s+//;
            $catcher_args =~ s/\s+$//;
        }

        if ($sender_args) {
            $sender_args =~ s/^\s+//;
            $sender_args =~ s/\s+$//;
        }

        my $client_offset = $test->findvalue("./client/clock_offset");
        my $catcher_offset = $test->findvalue("./catcher/clock_offset");
        my $sender_offset = $test->findvalue("./sender/clock_offset");

        my $regexes;

        my @success_regexes = ();

        $regexes = $test->find("./success_regex");
        if ($regexes) {
            foreach my $regex_node ($regexes->get_nodelist) {
                my $regex = $regex_node->textContent;
                push @success_regexes, $regex;
            }
        }

        my @failure_regexes = ();

        $regexes = $test->find("./failure_regex");
        if ($regexes) {
            foreach my $regex_node ($regexes->get_nodelist) {
                my $regex = $regex_node->textContent;
                push @failure_regexes, $regex;
            }
        }

        my %test = ();
        $test{"id"} = $id;
        $test{"dependencies"} = \@dependencies;
        $test{"success_regexes"} = \@success_regexes;
        $test{"failure_regexes"} = \@failure_regexes;

        $test{"client"} = ();
        $test{"client"}->{"args"} = $client_args;
        $test{"client"}->{"offset"} = $client_offset;

        $test{"sender"} = ();
        $test{"sender"}->{"args"} = $sender_args;
        $test{"sender"}->{"conf_dir"} = $sender_config_dir;
        $test{"sender"}->{"offset"} = $sender_offset;

        $test{"catcher"} = ();
        $test{"catcher"}->{"args"} = $catcher_args;
        $test{"catcher"}->{"conf_dir"} = $catcher_config_dir;
        $test{"catcher"}->{"offset"} = $catcher_offset;

        $tests{$id} = \%test;
    }

    foreach my $id (keys %tests) {
        foreach my $dependency (@{ $tests{$id}->{"dependencies"} }) {
            if (not $tests{$dependency}) {
                return (-1, "Test $id depends on non-existent test $dependency");
            }
        }
    }

    return (0, \%tests);
}

# vim: expandtab shiftwidth=4 tabstop=4
