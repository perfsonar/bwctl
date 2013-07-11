#!/bin/sh
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
#	File:		bootstrap
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Tue Sep 16 14:21:57 MDT 2003
#
#	Description:	
#			This script is used to bootstrap the autobuild
#			process.
#
#			RUNNING THIS SCRIPT IS NOT RECOMMENDED
#			(You should just use the "configure" script
#			that was bundled with the distribution if
#			at all possible.)
#
case "$1" in
	ac257)
		alias autoconf=autoconf257
		alias autoheader=autoheader257
		alias automake=automake17
		alias aclocal=aclocal17
		export AUTOCONF=autoconf257
		;;
	*)
		;;
esac

if test -x I2util/bootstrap.sh; then
        echo
        echo "## I2util/bootstrap"
        echo
        cd I2util
        ./bootstrap.sh $*
        cd ..
        echo
        echo "## Finished I2util/bootstrap"
        echo
fi

if test -x thrulay/bootstrap.sh; then
        echo
        echo "## thrulay/bootstrap"
        echo
        cd thrulay
        ./bootstrap.sh $*
        cd ..
        echo
        echo "## Finished thrulay/bootstrap"
        echo
fi

#iperf3 is in mecurial, so can't do svn external
if [ ! -d "iperf3" ]; then
    echo
    echo "## Downloading iperf3"
    hg clone https://code.google.com/p/iperf/ ./iperf3
    if [ "$?" != "0" ]; then
        echo "## Unable to export iperf3. Please verify mecurial installed."
        echo "## Please ignore this message if you do not want to build with iperf3 support."
    fi 
    echo
fi

if test -x iperf3/bootstrap.sh; then
        echo
        echo "## iperf3/bootstrap"
        echo
        cd iperf3
        ./bootstrap.sh $*
        cd ..
        echo
        echo "## Finished iperf3/bootstrap"
        echo
fi

set -x
libtoolize --copy --force --automake
aclocal -I config
autoheader
automake --foreign --add-missing --copy
autoconf
rm -rf config.cache
