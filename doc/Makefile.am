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

dist_man1_MANS = bwctl.man bwtraceroute.man bwping.man
dist_man5_MANS = bwctlrc.man bwctld.conf.man bwctld.limits.man bwctld.keys.man
dist_man8_MANS = bwctld.man

SOELIM=soelim

CLEANFILES	= bwctlrc.man bwctld.conf.man

SUFFIXES = .man .ms

.ms.man:
	$(SOELIM) $< > $@

# EXTRA_DIST = $(man1_MANS) $(man5_MANS) $(man8_MANS)
EXTRA_DIST = index.html architecture.html bwctl_arch.png bwctl_arch_servless.png bwctld.conf.ms bwctlrc.ms bwctl_infosheet.pdf bwctl_ntp_conf.html bwctl_firewalls.html bwctld_conf_opts.man

if HAVE_MAN2HTML
SUFFIXES += .man.html
.man.man.html:
	man2html -r $< | grep -v Content-type | sed -e 's/..\/man[0-9]\///g' | sed -e 's/\.[0-9]\.html/.man.html/g' > $@

EXTRA_DIST += bwctl.man.html bwctlrc.man.html bwctld.conf.man.html bwctld.limits.man.html bwctld.keys.man.html bwctld.man.html
endif
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
