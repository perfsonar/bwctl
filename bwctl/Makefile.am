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

INCLUDES	= $(IPFINCS) $(I2UTILINCS)
AM_CFLAGS	= $(IPF_PREFIX_CFLAGS)

bin_PROGRAMS	= iperfc
iperfc_SOURCES	= iperfc.c iperfcP.h
iperfc_LDADD	= $(IPFLIBS) $(I2UTILLIBS) $(MALLOCDEBUGLIBS)
iperfc_DEPENDENCIES = $(IPFLIBDEPS) $(I2UTILLIBDEPS)

