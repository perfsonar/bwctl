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

INCLUDES	= $(BWLINCS) $(I2UTILINCS)
AM_CFLAGS	= $(BWL_PREFIX_CFLAGS)

bin_PROGRAMS	= bwctl
bwctl_SOURCES	= bwctl.c bwctlP.h
bwctl_LDADD	= $(BWLLIBS) $(I2UTILLIBS) $(MALLOCDEBUGLIBS)
bwctl_DEPENDENCIES = $(BWLLIBDEPS) $(I2UTILLIBDEPS)

