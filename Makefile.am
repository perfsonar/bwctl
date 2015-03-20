#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2002				#
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
#	Date:		Wed Apr 17 13:37:24 EDT 2002
#
#	Description:	toplevel build for bwctl
#
SUBDIRS = @TOP_BUILD_DIRS@ bwlib bwctld bwctl conf doc contrib

RPM_FLAGS=--define "_topdir ${PWD}" --define "_specdir ${PWD}" --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" --define "_rpmdir ${PWD}" --define "_builddir ${PWD}"

# uncomment this when we stop using broken automake 1.5
# (then remove from DIST_EXTRA in subdir)
#nobase_include_HEADERS = bwlib/bwlib.h

#EXTRA_DIST	=		bootstrap
#MAINTAINERCLEANFILES	=	aclocal.m4 Makefile.in configure config.log \
#				config.status

EXTRA_DIST	=		LICENSE

srpm: dist
	@rpmbuild -bs ${RPM_FLAGS} bwctl.spec
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
