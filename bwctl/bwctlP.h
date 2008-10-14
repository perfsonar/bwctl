/*
 *      $Id$
 */
/*
 *	File:		bwctlP.h
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Mon Sep 15 11:16:04 MDT 2003
 *
 *	Description:	
 *
 *    License:
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the following copyright notice,
 *       this list of conditions and the disclaimer below.
 * 
 *        Copyright (c) 2003-2008, Internet2
 * 
 *                              All rights reserved.
 * 
 *     * Redistribution in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 *    *  Neither the name of Internet2 nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       explicit prior written permission.
 * 
 * You are under no obligation whatsoever to provide any enhancements to Internet2,
 * or its contributors.  If you choose to provide your enhancements, or if you
 * choose to otherwise publish or distribute your enhancement, in source code form
 * without contemporaneously requiring end users to enter into a separate written
 * license agreement for such enhancements, then you thereby grant Internet2, its
 * contributors, and its members a non-exclusive, royalty-free, perpetual license
 * to copy, display, install, use, modify, prepare derivative works, incorporate
 * into the software or other computer software, distribute, and sublicense your
 * enhancements or derivative works thereof, in binary and source code form.
 * 
 * DISCLAIMER - THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * “AS IS” AND WITH ALL FAULTS.  THE UNIVERSITY OF DELAWARE, INTERNET2, ITS CONTRI-
 * BUTORS, AND ITS MEMBERS DO NOT IN ANY WAY WARRANT, GUARANTEE, OR ASSUME ANY RES-
 * PONSIBILITY, LIABILITY OR OTHER UNDERTAKING WITH RESPECT TO THE SOFTWARE. ANY E-
 * XPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRAN-
 * TIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT
 * ARE HEREBY DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH THE USER THEREOF.  IN NO EVENT SHALL THE COPYRIGHT
 * OWNER, CONTRIBUTORS, OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELO-
 * PMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTIT-
 * UTE GOODS OR SERVICES; REMOVAL OR REINSTALLATION LOSS OF USE, DATA, SAVINGS OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILIT-
 * Y, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHE-
 * RWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRUBUTION OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */
#ifndef	_bwctlp_h_
#define	_bwctlp_h_

#include <I2util/table.h>

/*
 * This estimate is used to give each reservation a 'buffer' around it.
 * It is basically a very conservative estimate of how long it will take
 * to fork/exec iperf on each endpoint. (Read conservative as we never want
 * it to take longer than this, but we need to tempor that with realizing
 * that people will want to run this application interactively and we
 * americans have very short attention spans...)
 */
#define	SETUP_ESTIMATE	2

/*
 * Reasonable limits on these so dynamic memory is not needed.
 */
#define	MAX_PASSPROMPT	256
#define	MAX_PASSPHRASE	256

/*
 * Default for UDP tests.
 */
#define DEF_UDP_RATE	1000000

/*
 * Lock file name. This file is created in the output directory to ensure
 * there is not more than one bwctl process writing there.
 */
#define	BWLOCK	".bwctllock"
/* TSTAMP FMT YYYYMMDDTHHMMSS	*/
#define TSTAMPCHARS	15
#define SUMMARY_EXT	".sum"

#define	SEND_EXT	".send"
#define RECV_EXT	".recv"
/*
 * MAX(SEND_EXT,RECV_EXT)
 */
#define DIRECTION_EXT_LEN	5

typedef struct {
    /*
     * mode var
     */
    uint32_t    auth_mode;

    /*
     * AESKEY auth vars
     */
    char	*identity;
    char	*keyfile;
    uint8_t	*aeskey;
    uint8_t	aesbuff[16];
} aeskey_auth_rec, *aeskey_auth;

typedef struct{
    char		*host;
    aeskey_auth	        auth;
    BWLControl	        cntrl;
    int		        sockfd;
    BWLNum64	        rttbound;
    BWLNum64	        waketime;
    BWLBoolean	        send;
    BWLTestSpec         tspec;
    BWLToolAvailability avail_tools;
} ipsess_trec, *ipsess_t;

/*
 * Application "context" structure
 */
typedef	struct {
    /*
     **	Command line options
     */
    struct  {
        /* Flags */

        char		*srcaddr;	/* -B (bind) */

#ifndef	NDEBUG
        I2Boolean	childwait;	/* -W */
#endif

        I2Boolean	printfiles;	/* -p */
        I2Boolean	sender_results;	/* -x (xmit)*/
        char		*savedir;	/* -d */
        uint32_t	seriesInterval;	/* -I (seconds) */
        uint32_t	randomizeStart;	/* -R (alpha[0-50])	*/
        uint32_t	nIntervals;	/* -n */
        I2Boolean	continuous;	/* == !nIntervals && seriesI */
        uint32_t	seriesWindow;	/* -L (seconds) */

        /* Determines how far into
         * a seriesInterval a test
         * should be allowed to start.
         * If seriesInterval is in
         * place, default ensures test
         * will complete before next
         * interval, but no later than
         * 50% of seriesInterval.
         * If seriesInterval is not
         * being used, than defaults
         * to 2xtest duration.
         */
        int		facility;	/* -e */
        /* -r stderr too */
        I2Boolean	version;	/* -V */
        I2Boolean	verbose;	/* -v */
        I2Boolean	quiet;		/* -q */
        uint32_t	tool_id;   	/* -T iperf/nuttcp/thrulay */

        uint32_t	reportInterval;	/* -i (seconds) */
        I2numT  	lenBuffer;	/* -l (bytes)	*/
        I2Boolean	udpTest;	/* -u	*/
        I2Boolean	winset;		/* -w/-W specified */
        I2numT  	windowSize;	/* -w 	*/
        I2Boolean	dynamicWindowSize;	/* -W used for -w */
        I2numT  	bandWidth;	/* -b (bits/sec) */
        uint32_t	timeDuration;	/* -t (secs) */
        uint8_t	        units;          /* -f	*/
        uint8_t	        outformat;      /* -y	*/
        uint32_t	parallel;	/* -P	*/
        uint32_t	tos;		/* -S	*/
        double          allowUnsync;    /* -a   */

    } opt;


    ipsess_t		recv_sess;
    ipsess_t		send_sess;

    aeskey_auth		def_auth;

    BWLScheduleContext	sctx;
    BWLSID			sid;

    BWLNum64		*sessionStart;
    BWLNum64		tstamp_mem;

    FILE		*fp;
    FILE		*testfp;
    char		fname[PATH_MAX];

} ipapp_trec, *ipapp_t;

#endif
