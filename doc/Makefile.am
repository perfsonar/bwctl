#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2004				#
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
#	Date:		Tue Feb 17 11:08:20 MST 2004
#
#	Description:

dist_man1_MANS = bwctl.man
dist_man5_MANS = bwctlrc.man bwctld.conf.man bwctld.limits.man bwctld.keys.man
dist_man8_MANS = bwctld.man

SOELIM=soelim

SUFFIXES = .man .ms

.ms.man:
	$(SOELIM) $< > $@

# EXTRA_DIST = $(man1_MANS) $(man5_MANS) $(man8_MANS)
EXTRA_DIST = index.html architecture.html bwctl_arch.png bwctl_arch_servless.png bwctld.conf.ms bwctlrc.ms bwctl_infosheet.pdf bwctl_ntp_conf.html bwctl_firewalls.html

if HAVE_MAN2HTML
SUFFIXES += .man.html
.man.man.html:
	man2html -r $< > $@

EXTRA_DIST += bwctl.man.html bwctlrc.man.html bwctld.conf.man.html bwctld.limits.man.html bwctld.keys.man.html bwctld.man.html
endif
