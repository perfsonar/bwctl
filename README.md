#BWCTL

bwctl is a scheduling and policy daemon that wraps iperf, traceroute, owamp and
a few other measurement tools. It works by contacting a bwctld process on the
remote system and on the local system and requests that those daemons perform a
specific iperf test between them.  The bwctl software uses the "autoconf" tools
to prepare a build process. It is distributed with a pre-built "configure"
script - so the "autoconf" tools should not be needed. (gnumake may be
required... I have not tried using other versions of make.)

bwctl does require a reasonably synchronized clock. (It is
scheduling tests and needs to be sure it has the same general concept of
when a test should take place as the peer system the test is being done with.)
Therefore bwctl requires ntp be installed and used to synchronize the system
clock.

##Building bwctl

###Prerequisites
* I2util: You can install it via RPM, or download the source from http://software.internet2.edu/sources/I2util/
* iperf3 (optional): You can install it via RPM, or download the source from https://github.com/esnet/iperf/

###Building

```bash
./configure; make; make install
```

(Note: If configure fails, try running ./bootstrap.sh first)

##Latest version

To check out the most recent code, do:  git clone https://github.com/perfsonar/bwctl.git

##Running

###Daemon

To run the daemon:

```bash
bwctld -c /path/to/directory/with/bwctld.conf
```

The daemon will run without a bwctld configuration file if you use enough
of the command-line flags - but it is much easier to use the config file.
There is an example configuration file in conf/bwctld.conf.

To get the list of available options use:

```bash
bwctld -h
```

bwctld -h will give you the list of options. Specifically, if you have problems you may want to use the -Z flag to run it in the foreground and have error messages come to the console in addition to syslog.

###Client

To run the client:

```bash
bwctl [options] [-c catchhost] [-s sendhost]
```

At least a -c or a -s must be specified to indicate the direction of the
test. If only one of them is specified, the local host is assumed to be
the other one. If a local bwctld is not running, then bwctl will
execute the bwctld functionality required to run the test.

To get the list of available options use:

```bash
bwctl -h
```

The bwctl program will allow you to run bandwidth tests like iperf, iperf3 and
nuttcp. To run traceroute/tracepath, use the 'bwtraceroute' program, and to use
ping/owamp, use the 'bwping' program.

##Bug Reports

Before submitting a bug report, try checking out the latest version of
the code, and confirm that its not already fixed. Then submit to:
https://github.com/perfsonar/bwctl/issues

For more information see: https://github.com/perfsonar/bwctl/

