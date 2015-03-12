.\" The first line of this file must contain the '"[e][r][t][v] line
.\" to tell man to run the appropriate filter "t" for table.
.\"
.\"	$Id: bwctld.conf.man 493 2008-10-09 16:27:47Z aaron $
.\"
.\"######################################################################
.\"#									#
.\"#			   Copyright (C)  2004				#
.\"#	     			Internet2				#
.\"#			   All Rights Reserved				#
.\"#									#
.\"######################################################################
.\"
.\"	File:		bwctld.8
.\"
.\"	Author:		Jeff Boote
.\"			Internet2
.\"
.\"	Date:		Thu Feb 12 15:44:09 MST 2004
.\"
.\"	Description:
.\"
.TH bwctld.conf 5 "$Date: 2008\-10\-09 12:27:47 \-0400 (Thu, 09 Oct 2008) $"
.SH NAME
bwctld.conf \- \fBB\fRand\fBw\fRidth \fBC\fRon\fBt\fRro\fBl\fR
\fBd\fRaemon configuration file
.SH DESCRIPTION
The \fBbwctld.conf\fR file is the configuration file for the bwctld(8)
program. It is used to configure the basic operation of the server. For
example, what addresses and ports it should listen on, where it should
send error messages, and where it should save files.
.PP
The policy rules for \fBbwctld\fR are configured using the \fBbwctld.limits\fR
file; the details for configuring those policies are described in
the bwctld.limits(5) manual page.
.PP
.so bwctld_conf_opts.man
.RE
.SH SEE ALSO
bwctl(1), bwctld(8), bwctld.limits(5), bwctld.keys(5),
and the \%http://software.internet2.edu/bwctl/ web site.
.PP
For details on \fBIperf3\fR, see the \%https://github.com/esnet/iperf
web site.
.PP
For details on \fBIperf\fR, see the \%http://sourceforge.net/projects/iperf
web site.
.PP
For details on \fBNuttcp\fR, see the \%http://www.wcisd.hpc.mil/nuttcp/Nuttcp\-HOWTO.html
web site.
.PP
For details on \fBOwamp\fR, see the \%http://software.internet2.edu/owamp
web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings, and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
