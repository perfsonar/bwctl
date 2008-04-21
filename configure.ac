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
PACKAGE=bwctl
VERSION="1.3rc1"

AC_INIT(bwctl, 1.3rc1, bwctl-users@internet2.edu)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(bwctl, 1.3rc1, [no-define])

AC_CONFIG_SRCDIR(bwlib/context.c)
AM_CONFIG_HEADER(bwlib/config.h)

TOP_BUILD_DIRS=""

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
#AC_PROG_RANLIB
AC_PROG_LN_S

# possible solution to config location
#BWL_PREFIX='${prefix}'
#BWL_PREFIX_CFLAGS="-DBWL_PREFIX=$BWL_PREFIX"
#AC_SUBST(BWL_PREFIX_CFLAGS)
AC_DEFINE(AUTOCONF_SYSCONFDIR,/etc,"name of sysconfdir under prefix")

# Checks for libraries.
AC_SEARCH_LIBS(getaddrinfo, [socket nsl])
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(nanosleep, rt)

AC_SEARCH_LIBS(trunc, m)

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
AC_CHECK_FUNCS([memset socket getaddrinfo mergesort])

# Checks for variable/function declarations.
AC_CHECK_DECLS([optreset])
AC_CHECK_DECLS([fseeko])

# XXX: Replace this efence stuff with something that sets LDFLAGS (for -L)
# and then uses AC_SEARCH_LIB to add to LIBS.
# 
##
## add configure options.
##
#AC_ARG_WITH(efence,
#		AC_HELP_STRING([--with-efence=<path/libefence.a>],
#				[yes means use -L/usr/local/lib -lefence]),
#		with_efence=$withval, with_efence=no)
#
#
##
## setup efence
##
#MALLOCDEBUGLIBS=""
#if test "$with_efence" != "no"; then
#	if test "$with_efence" = "yes"; then
#		MALLOCDEBUGLIBS="-L/usr/local/lib -lefence"
#	else
#		efence_dir=`dirname $with_efence`
#		efence_file=`basename $with_efence`
#		case $efence_dir in
#			/*) ;; # already absolute path
#			*) efence_dir="`pwd`/$efence_dir" ;;
#		esac
#		MALLOCDEBUGLIBS="$efence_dir/$efence_file"
#	fi
#fi
#AC_SUBST(MALLOCDEBUGLIBS)

#
# --with-I2util:
# If not specified, or is 'yes' then:
#       build with local-dir if available
#       use installed otherwise (depends on CFLAGS/LDFLAGS env set correctly)
# If <path> specified, then that <path> must point to an already installed
# prefix style tree (and include/lib subdir is assumed and used to set
# LDFLAGS/CFLAGS
#
AC_ARG_WITH(I2util,
            AC_HELP_STRING([--with-I2util=<path>],
                           [defaults to using sub-dir if avail, otherwise installed. If <path> specified, attempts to use that.]),
                           with_I2util=$withval, with_I2util=yes)

if test \( -z "$with_I2util" -o "$with_I2util" == "yes" \) -a -d I2util; then
    # Use local I2util? - just setup LDFLAGS/CFLAGS so libtool can find
    # it from the Makefile.am during build.
    AC_MSG_WARN([Using local I2util])
    AC_CONFIG_SUBDIRS(I2util)
    TOP_BUILD_DIRS="I2util $TOP_BUILD_DIRS"
    I2util_dir="`pwd`/I2util"
    LDFLAGS="-L$I2util_dir/I2util $LDFLAGS"
    CFLAGS="-I$I2util_dir $CFLAGS"
else
    # else - libI2util must already be built. If <path>, then add to
    # LDFLAGS/CFLAGS - but ultimately, AC_SEARCH_LIBS and AC_CHECK_HEADERS
    # must succeed.
    if test -n "$with_I2util" -a -d "$with_I2util"; then
        I2util_dir=`dirname $with_I2util`
        case $I2util_dir in
            /*) ;; # already an absolute path
            *) I2util_dir="`pwd`/$I2util_dir" ;;
        esac
        LDFLAGS="-L$with_I2util/lib $LDFLAGS"
        CFLAGS="-I$I2util_dir/include $CFLAGS"
    fi
    AC_SEARCH_LIBS([I2AddrByNode],I2util, ,AC_MSG_ERROR([Couldn't find I2util library]))
    AC_CHECK_HEADERS([I2util/util.h I2util/conf.h], ,AC_MSG_ERROR([Couldn't find I2util header files]), [AC_INCLUDES_DEFAULT])
fi

#
# --with-thrulay:
# If not specified, or is 'yes' then:
#       build with local-dir if available
#       use installed otherwise (depends on CFLAGS/LDFLAGS env set correctly)
# If <path> specified, then that <path> must point to an already installed
# prefix style tree (and include/lib subdir is assumed and used to set
# LDFLAGS/CFLAGS
#
AC_ARG_WITH(thrulay,
            AC_HELP_STRING([--with-thrulay=<path>],
                           [defaults to using sub-dir if avail, otherwise installed. If <path> specified, attempts to use that.]),
                           with_thrulay=$withval, with_thrulay=yes)

if test \( -z "$with_thrulay" -o "$with_thrulay" == "yes" \) -a -d thrulay; then
    # Use local thrulay? - just setup LDFLAGS/CFLAGS so libtool can find
    # it from the Makefile.am during build.
    AC_MSG_WARN([Using local thrulay])
    AC_CONFIG_SUBDIRS(thrulay)
    TOP_BUILD_DIRS="thrulay $TOP_BUILD_DIRS"
    thrulay_dir="`pwd`/thrulay"
    LDFLAGS="-L$thrulay_dir/thrulay $LDFLAGS"
    CFLAGS="-I$thrulay_dir $CFLAGS"
else
    # else - libthrulay must already be built. If <path>, then add to
    # LDFLAGS/CFLAGS - but ultimately, AC_SEARCH_LIBS and AC_CHECK_HEADERS
    # must succeed.
    if test -n "$with_thrulay" -a -d "$with_thrulay"; then
        thrulay_dir=`dirname $with_thrulay`
        case $thrulay_dir in
            /*) ;; # already an absolute path
            *) thrulay_dir="`pwd`/$thrulay_dir" ;;
        esac
        LDFLAGS="-L$with_thrulay/lib $LDFLAGS"
        CFLAGS="-I$thrulay_dir/include $CFLAGS"
    fi
    AC_SEARCH_LIBS([thrulay_client_init],thrulay, ,AC_MSG_ERROR([Couldn't find thrulay library]))
    AC_CHECK_HEADERS([thrulay/client.h thrulay/server.h], ,AC_MSG_ERROR([Couldn't find thrulay header files]), [AC_INCLUDES_DEFAULT])
    use_sys_thrulay="true"
fi
do_thrulay=true

# if test -n "$with_I2util" -a "$with_I2util" != "yes" -a -d "$with_I2util"; then 
# 	# Path given for libI2util
# 	LDFLAGS="$LDFLAGS -L$with_I2util/I2util"
# 	CFLAGS="$CFLAGS -I$with_I2util"
#         BWLLIBDEPS="$BWLLIBDEPS $with_I2util/I2util/libI2util.a"
# fi
# 
# AC_SEARCH_LIBS([I2AddrByNode],I2util, ,AC_MSG_ERROR([Couldn't find I2util]))
# AC_CHECK_HEADERS([I2util/util.h I2util/conf.h], ,AC_MSG_ERROR([Couldn't find I2util header files]), [AC_INCLUDES_DEFAULT])
# 
#
# Configure option to specify where to look for libthrulay if not installed.
#
# AC_ARG_WITH([thrulay],
# 		AC_HELP_STRING([--with-thrulay=<path>],
# 				[libthrulay path; defaults to system installation]),
# 				with_thrulay=$withval)
# 
# if test "$with_thrulay" != "no"; then
#     if test -n "$with_thrulay" -a "$with_thrulay" != "yes" -a -d "$with_thrulay"; then 
#         # Path given for libthrulay
#         LDFLAGS="$LDFLAGS -L$with_thrulay/thrulay/.libs"
#         CFLAGS="$CFLAGS -I$with_thrulay"
#         BWLLIBDEPS="$BWLLIBDEPS $with_thrulay/thrulay/.libs/libthrulay.a"
#     fi
#     AC_SEARCH_LIBS([thrulay_client_init],thrulay,
#             # if lib found
#             AC_CHECK_HEADERS([thrulay/client.h thrulay/server.h],
#                         [
#                         #if header found
#                         AC_DEFINE(TOOL_THRULAY, 1, [THRULAY throuphput tool])
#                         do_thrulay=true
#                         ],
#                         #if header not found
#                         [
#                             if test "$with_thrulay" = ""; then
#                                 AC_MSG_WARN([Couldn't fine thrulay headers: configuring for no thrulay support])
#                             else
#                                 AC_MSG_ERROR([Couldn't fine thrulay headers])
#                             fi
#                         ], [AC_INCLUDES_DEFAULT]),
#             #if lib not found
#             [
#                 if test "$with_thrulay" = ""; then
#                     AC_MSG_WARN([Couldn't find libthrulay])
#                 else
#                     AC_MSG_ERROR([Couldn't find libthrulay])
#                 fi
#             ])
# fi

AM_CONDITIONAL(USE_SYS_THRULAY, test x$use_sys_thrulay = xtrue)
AM_CONDITIONAL(TOOL_THRULAY, test x$do_thrulay = xtrue)

AC_ARG_ENABLE(IPERF,
              AC_HELP_STRING([--enable-IPERF], [- IPERF throughput tool]),
              [tool_ok=$enableval], [tool_ok=yes])
if test "$tool_ok" = "yes"; then
    AC_DEFINE(TOOL_IPERF, 1, [IPERF throuphput tool])
    do_iperf=true
fi
AM_CONDITIONAL(TOOL_IPERF, test x$do_iperf = xtrue)

AC_ARG_ENABLE(NUTTCP,
              AC_HELP_STRING([--enable-NUTTCP], [- NUTTCP throughput tool]),
              [tool_ok=$enableval], [tool_ok=yes])
if test "$tool_ok" = "yes"; then
    AC_DEFINE(TOOL_NUTTCP, 1, [NUTTCP throuphput tool])
    do_nuttcp=true
fi
AM_CONDITIONAL(TOOL_NUTTCP, test x$do_nuttcp = xtrue)


#BWLINCS='-I${ac_top_srcdir}'

#BWL_dir='${ac_top_srcdir}/bwlib'
#BWLLDFLAGS="-L$BWL_dir"
#BWLLIBS="$BWLLDFLAGS -lbwlib"
#BWLLIBDEPS="$BWLLIBDEPS $BWL_dir/libbwlib.a"

#AC_SUBST(BWLINCS)
#AC_SUBST(BWLLIBS)
#AC_SUBST(BWLLIBDEPS)

AC_SUBST(TOP_BUILD_DIRS)
# AC_CONFIG_FILES([Makefile owamp/Makefile])

AC_SUBST(ac_aux_dir)
AC_OUTPUT([Makefile bwlib/Makefile bwctld/Makefile bwctl/Makefile conf/Makefile doc/Makefile bwctl.spec],
	[test -z "$CONFIG_HEADERS" || echo timestamp > bwlib/stamp-h.in])
