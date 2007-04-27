#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2003				#
#				Internet2				#
#			   All Rights Reserved				#
#									#
#########################################################################
#
#	File:		configure.ac
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Tue Sep 16 14:22:47 MDT 2003
#
#	Description:	autoconfig input script for bwctl build
#
#	Usage:		see bootstrap...
#
#	Environment:
#
#	Files:
#
#
#	Options:
# Process this file with autoconf to produce a configure script.
AC_INIT(bwctl, 1.3rc, bwctl-users@internet2.edu)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(bwctl, 1.3rc, [no-define])
AC_CONFIG_SRCDIR(bwlib/context.c)
AM_CONFIG_HEADER(bwlib/config.h)

TOP_BUILD_DIRS=""

#
# add configure options.
#
AC_ARG_WITH(efence,
		AC_HELP_STRING([--with-efence=<path/libefence.a>],
				[yes means use -L/usr/local/lib -lefence]),
		with_efence=$withval, with_efence=no)


#
# setup efence
#
MALLOCDEBUGLIBS=""
if test "$with_efence" != "no"; then
	if test "$with_efence" = "yes"; then
		MALLOCDEBUGLIBS="-L/usr/local/lib -lefence"
	else
		efence_dir=`dirname $with_efence`
		efence_file=`basename $with_efence`
		case $efence_dir in
			/*) ;; # already absolute path
			*) efence_dir="`pwd`/$efence_dir" ;;
		esac
		MALLOCDEBUGLIBS="$efence_dir/$efence_file"
	fi
fi
AC_SUBST(MALLOCDEBUGLIBS)

#
# --with-I2Util should probably only be used by developers. Instead
# install the library.
#
AC_ARG_WITH(I2util,
            AC_HELP_STRING([--with-I2util=<path>],
                           [defaults to using installed I2util, use <path> to indicate path to build tree ]),
                           with_I2util=$withval, with_I2util=yes)

if test -n "$with_I2util" -a "$with_I2util" != "yes" -a -d "$with_I2util"; then 
	# Path given for libthrulay
	LDFLAGS="$LDFLAGS -L$with_I2util/I2util"
	CFLAGS="$CFLAGS -I$with_I2util"
        BWLLIBDEPS="$BWLLIBDEPS $with_I2util/I2util/libI2util.a"
fi

AC_SEARCH_LIBS(I2AddrByNode,I2util, ,AC_MSG_ERROR([Couldn't find I2util]))
AC_CHECK_HEADERS([I2util/util.h I2util/conf.h], ,AC_MSG_ERROR([Couldn't find I2util header files]), [AC_INCLUDES_DEFAULT])

#
# Configure option to specify where to look for libthrulay if not installed.
#
AC_ARG_WITH([thrulay],
		AC_HELP_STRING([--with-thrulay=<path>],
				[libthrulay path; defaults to system installation]),
				with_thrulay=$withval)

if test -n "$with_thrulay" -a "$with_thrulay" != "yes" -a -d "$with_thrulay"; then 
	# Path given for libthrulay
	CFLAGS="$CFLAGS -I$with_thrulay"
	LDFLAGS="$LDFLAGS -L$with_thrulay/thrulay"
        BWLLIBDEPS="$BWLLIBDEPS $with_thrulay/thrulay/libthrulay.la"
fi
AC_SEARCH_LIBS(thrulay_client_init,thrulay)
#AC_CHECK_LIB([thrulay], [main])
AC_CHECK_HEADERS([thrulay/client.h thrulay/server.h], ,AC_MSG_WARN([Couldn't fine thrulay headers: configuring for no thrulay support]), [AC_INCLUDES_DEFAULT])


BWLINCS='-I${top_srcdir}'

BWL_dir='${top_srcdir}/bwlib'
BWLLDFLAGS="-L$BWL_dir"
BWLLIBS="$BWLLDFLAGS -lbwlib"
BWLLIBDEPS="$BWLLIBDEPS $BWL_dir/libbwlib.a"

AC_SUBST(BWLINCS)
AC_SUBST(BWLLIBS)
AC_SUBST(BWLLIBDEPS)

AC_SUBST(TOP_BUILD_DIRS)

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_LN_S

# possible solution to config location
BWL_PREFIX='${prefix}'
BWL_PREFIX_CFLAGS="-DBWL_PREFIX=$BWL_PREFIX"
AC_DEFINE(AUTOCONF_SYSCONFDIR,/etc,"name of sysconfdir under prefix")
AC_SUBST(BWL_PREFIX_CFLAGS)

# Checks for libraries.
AC_CHECK_LIB([socket], [main])
AC_CHECK_LIB([nsl], [main])
AC_CHECK_LIB([rt], [main])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h netdb.h stdlib.h sys/param.h sys/socket.h sys/time.h sys/timex.h])

# Checks for typedefs, structures, and compiler characteristics.
I2_C___ATTRIBUTE__
AC_C_CONST
AC_HEADER_TIME
AC_CHECK_MEMBERS([struct sockaddr.sa_len], , ,
	[#include <sys/types.h>
	#include <sys/socket.h>])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket getaddrinfo mergesort])

# Checks for variable/function declarations.
AC_CHECK_DECLS([optreset])
AC_CHECK_DECLS([fseeko])

# AC_CONFIG_FILES([Makefile owamp/Makefile])

AC_SUBST(ac_aux_dir)
AC_OUTPUT([Makefile bwlib/Makefile bwctld/Makefile bwctl/Makefile conf/Makefile doc/Makefile],
	[test -z "$CONFIG_HEADERS" || echo timestamp > bwlib/stamp-h.in])
