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
AC_INIT(bwctl, 1.0b, bwctl-bugs@internet2.edu)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(bwctl, 1.0b, [no-define])
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

AC_ARG_WITH(I2util,
		AC_HELP_STRING([--with-I2util=<dir>],
				[defaults to building I2util under owamp if exists]),
		with_I2util=$withval, with_I2util=yes)

#
# find I2util
#
I2UTILLDFLAGS=""
I2UTILLIBS=""
I2UTILLIBDEPS=""
I2UTILINCS=""
if test "$with_I2util" != "no"; then
	# first, check for directory given.
	if test "$with_I2util" != "yes"; then
		I2util_dir=`dirname $with_I2util`
		case $I2util_dir in
			/*) ;; # already an absolute path
			*) I2util_dir="`pwd`/$I2util_dir" ;;
		esac
		I2UTILINCS="-I$I2util_dir/include $I2UTILINCS"
		I2UTILLDFLAGS="-L$I2util_dir/lib $I2UTILLDFLAGS"
		I2UTILLIBDEPS="$I2util_dir/lib/libI2util.a"
	# now, check for sub-build/sub-configure
	elif test -d I2util/I2util; then
		AC_CONFIG_SUBDIRS(I2util)
		TOP_BUILD_DIRS="I2util $TOP_BUILD_DIRS"
		I2util_dir='${top_srcdir}/I2util'
		I2UTILINCS="-I$I2util_dir $I2UTILINCS"
		I2UTILLDFLAGS="-L$I2util_dir/I2util $I2UTILLDFLAGS"
		I2UTILLIBDEPS="$I2util_dir/I2util/libI2util.a"
		
	# now, check for installed I2util
	elif test -d /usr/local/I2util; then
		I2UTILINCS="-I/usr/local/I2util/include $I2UTILINCS"
		I2UTILLDFLAGS="-L/usr/local/I2util/lib $I2UTILLDFLAGS"
		I2UTILLIBDEPS="/usr/local/I2util/lib/libI2util.a"
	fi

	if test -z "$I2UTILLDFLAGS"; then
		AC_MSG_ERROR([couldn't find I2util library])
	else
		I2UTILLIBS="$I2UTILLDFLAGS -lI2util"
	fi
fi

BWLINCS='-I${top_srcdir}'

BWL_dir='${top_srcdir}/bwlib'
BWLLDFLAGS="-L$BWL_dir"
BWLLIBS="$BWLLDFLAGS -lbwlib"
BWLLIBDEPS="$BWL_dir/libbwlib.a"

AC_SUBST(I2UTILINCS)
AC_SUBST(I2UTILLIBS)
AC_SUBST(I2UTILLIBDEPS)
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

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h netdb.h stdlib.h sys/param.h sys/socket.h sys/time.h])

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
AC_OUTPUT([Makefile bwlib/Makefile bwctld/Makefile bwctl/Makefile conf/Makefile ],
	[test -z "$CONFIG_HEADERS" || echo timestamp > bwlib/stamp-h.in])

