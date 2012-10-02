#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2003				#
#	     			Internet2				#
#			   All Rights Reserved				#
#									#
#########################################################################
#
#	File:		Makefile.am
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Fri Sep 12 13:33:27 MDT 2003
#
#	Description:

bin_PROGRAMS	= bwctl
bwctl_SOURCES	= bwctl.c bwctlP.h
bwctl_CFLAGS	= -I..

if TOOL_THRULAY
if USE_SYS_THRULAY
BWLIBTHRULAY = -lthrulay
else
BWLIBTHRULAY = ../thrulay/thrulay/libthrulay.la
endif
else
BWLIBTHRULAY =
endif

if TOOL_IPERF3
if USE_SYS_IPERF3
BWLIBIPERF3 = -liperf
else
BWLIBIPERF3 = ../iperf3/src/libiperf.a
endif
else
BWLIBIPERF3 =
endif

bwctl_LDADD	= -L../bwlib -lbwlib $(BWLIBTHRULAY) $(BWLIBIPERF3) -lI2util
