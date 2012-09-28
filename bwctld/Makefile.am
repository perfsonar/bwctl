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
#	Date:		Tue Sep 16 14:28:33 MDT 2003
#
#	Description:	bwctld build description

bin_PROGRAMS	= bwctld
bwctld_SOURCES	= bwctldP.h bwctld.c policy.h policy.c 
bwctld_CFLAGS	= -I..

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
BWLIBIPERF = -liperf
else
BWLIBIPERF =
endif

bwctld_LDADD	= -L../bwlib -lbwlib $(BWLIBTHRULAY) $(BWLIBIPERF) -lI2util
