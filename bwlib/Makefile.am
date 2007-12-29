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
#	Date:		Tue Sep 16 14:23:59 MDT 2003
#
#	Description:	libbwlib build description.

INCLUDES		= $(BWLINCS) $(I2UTILINCS)

lib_LIBRARIES		= libbwlib.a
libbwlib_a_SOURCES	= api.c capi.c sapi.c context.c error.c bwlibP.h \
			protocol.c io.c endpoint.c time.c arithm64.c \
			rijndael-alg-fst.c rijndael-alg-fst.h \
			rijndael-api-fst.c rijndael-api-fst.h \
			util.c schedule.c $(TOOL_SOURCES)

TOOL_SOURCES		= tools.c

if TOOL_THRULAY
TOOL_SOURCES		+= thrulay.c
endif

if TOOL_IPERF
TOOL_SOURCES		+= iperf.c
endif

if TOOL_NUTTCP
TOOL_SOURCES		+= nuttcp.c
endif

EXTRA_DIST		= bwlib.h
