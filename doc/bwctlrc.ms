." The first line of this file must contain the '"[e][r][t][v] line
." to tell man to run the appropriate filter "t" for table.
."
."	$Id: bwctlrc.man 493 2008-10-09 16:27:47Z aaron $
."
."######################################################################
."#									#
."#			   Copyright (C)  2004				#
."#	     			Internet2				#
."#			   All Rights Reserved				#
."#									#
."######################################################################
."
."	File:		bwctlrc.8
."
."	Author:		Jeff Boote and Aaron Brown
."			    Internet2
."
."	Date:		Tue Jan 06 07:44:09 EST 2009
."
."	Description:	
."
.TH bwctlrc 5 "$Date: 2008-10-09 12:27:47 -0400 (Thu, 09 Oct 2008) $"
.SH NAME
bwctlrc \- \fBB\fRand\fBw\fRidth \fBC\fRon\fBt\fRro\fBl\fR configuration file
.SH DESCRIPTION
The \fBbwctlrc\fR file is a configuration file for the bwctl(8) program.
If a test is requested using bwctl, and there is not a local bwctld(8)
running, bwctl will spawn its own copy of bwctld. This configuration file is
used to configure the basic operation of the automatically spawned server. For
example, it can be used to configure whether to allow the local clock to be
unsynchroznied, or where the iperf command is located.
.PP
This file can be placed in ~/.bwctlrc, where it will be automatically read by
bwctl when it spawns off a bwctld. If the file is put elsewhere, the BWCTLRC
environmental variable can be set to the path to the file and bwctl will read
it.
.PP
.so bwctld_conf_opts.man
.SH SEE ALSO
bwctl(1), bwctld(8), bwctld.limits(5), bwctld.keys(5),
and the \%http://e2epi.internet2.edu/bwctl/ web site.
.PP
For details on \fBIperf\fR, see the \%http://dast.nlanr.net/Projects/Iperf/
web site.
.PP
For details on \fBNuttcp\fR, see the \%http://www.wcisd.hpc.mil/nuttcp/Nuttcp-HOWTO.html
web site.
.PP
For details on \fBThrulay\fR, see the \%http://e2epi.internet2.edu/thrulay/
web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
