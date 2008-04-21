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

if USE_SYS_THRULAY
BWLIBTHRULAY	= -lthrulay
else
BWLIBTHRULAY	= ../thrulay/thrulay/libthrulay.la
endif

bwctl_LDADD	= -L../bwlib -lbwlib $(BWLIBTHRULAY) -lI2util
