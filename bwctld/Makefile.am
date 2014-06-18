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
bwctld_SOURCES	= bwctldP.h bwctld.c policy.h policy.c missing_queue.h
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
if USE_SYS_IPERF3
BWLIBIPERF3 = -liperf
else
BWLIBIPERF3 = ../iperf3/src/libiperf.a
endif
else
BWLIBIPERF3 =
endif

bwctld_LDADD	= -L../bwlib -lbwlib $(BWLIBTHRULAY) $(BWLIBIPERF3) -lI2util
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
