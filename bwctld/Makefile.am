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
#	Description:	iperfcd build description

# possible solution to conf dir location
AM_CFLAGS = $(IPF_PREFIX_CFLAGS)

INCLUDES	= $(IPFINCS) $(I2UTILINCS)

bin_PROGRAMS	= iperfcd
iperfcd_SOURCES	= iperfcdP.h iperfcd.c policy.h policy.c conf.h conf.c
iperfcd_LDADD	= $(IPFLIBS) $(I2UTILLIBS) $(MALLOCDEBUGLIBS)
iperfcd_DEPENDENCIES = $(IPFLIBDEPS) $(I2UTILLIBDEPS)
