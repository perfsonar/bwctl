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

# INCLUDES		= $(BWLINCS) $(I2UTILINCS)

lib_LIBRARIES		= libbwlib.a
libbwlib_a_SOURCES	= api.c capi.c sapi.c context.c error.c bwlibP.h \
			protocol.c io.c endpoint.c time.c arithm64.c \
			rijndael-alg-fst.c rijndael-alg-fst.h \
			rijndael-api-fst.c rijndael-api-fst.h \
			util.c daemon.c missing_getopt.c missing_getopt.h \
                        $(TOOL_SOURCES)

# add parent
libbwlib_a_CFLAGS	= -I..

TOOL_SOURCES		= tools.c iperf3.c ping.c traceroute.c tracepath.c owamp.c paris-traceroute.c

if TOOL_THRULAY
TOOL_SOURCES		+= thrulay.c
endif

if TOOL_IPERF
TOOL_SOURCES		+= iperf.c
endif

if TOOL_NUTTCP
TOOL_SOURCES		+= nuttcp.c
endif

I2utilincludedir = $(pkgincludedir)
I2utilinclude_HEADERS	= bwlib.h
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
