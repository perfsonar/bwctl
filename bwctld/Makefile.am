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

# possible solution to conf dir location
AM_CFLAGS = $(BWL_PREFIX_CFLAGS)

INCLUDES	= $(BWLINCS) $(I2UTILINCS)

bin_PROGRAMS	= bwctld
bwctld_SOURCES	= bwctldP.h bwctld.c policy.h policy.c conf.h conf.c
bwctld_LDADD	= $(BWLLIBS) $(I2UTILLIBS) $(MALLOCDEBUGLIBS)
bwctld_DEPENDENCIES = $(BWLLIBDEPS) $(I2UTILLIBDEPS)
