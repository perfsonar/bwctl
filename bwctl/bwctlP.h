/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2003			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		bwctlP.h
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Mon Sep 15 11:16:04 MDT 2003
 *
 *	Description:	
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
		char		*authmode;	/* -A */
		char		*identity;	/* -U */
		char		*keyfile;	/* -k */

#ifndef	NDEBUG
		I2Boolean	childwait;	/* -W */
#endif

		I2Boolean	printfiles;	/* -p */
		I2Boolean	sender_results;	/* -x (xmit)*/
		char		*savedir;	/* -d */
		u_int32_t	seriesInterval;	/* -I (seconds) */
		u_int32_t	randomizeStart;	/* -R (alpha[0-50])	*/
		u_int32_t	nIntervals;	/* -n */
		I2Boolean	continuous;	/* == !nIntervals && seriesI */
		u_int32_t	seriesWindow;	/* -L (seconds) */
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

		u_int32_t	reportInterval;	/* -i (seconds) */
		u_int32_t	lenBuffer;	/* -l (bytes)	*/
		I2Boolean	udpTest;	/* -u	*/
		I2Boolean	winset;		/* -w/-W specified */
		u_int32_t	windowSize;	/* -w 	*/
		I2Boolean	dynamicWindowSize;	/* -W used for -w */
		u_int32_t	bandWidth;	/* -b (bits/sec) */
		u_int32_t	timeDuration;	/* -t (secs) */
		u_int32_t	parallel;	/* -P	*/
		u_int32_t	tos;		/* -S	*/

		I2Boolean	recv;		/* -s (iperf server) */
		I2Boolean	send;		/* -c (iperf client) */

	} opt;

	char			*remote_test;

	u_int32_t		auth_mode;

	BWLScheduleContext	sctx;
	BWLSID			sid;

	BWLNum64		*sessionStart;
	BWLNum64		tstamp_mem;

	FILE			*fp;
	FILE			*testfp;
	char			fname[PATH_MAX];

} ipapp_trec, *ipapp_t;

typedef struct{
	BWLControl	cntrl;
	int		sockfd;
	BWLNum64	rttbound;
	BWLNum64	waketime;
	BWLBoolean	send;
	BWLTestSpec	tspec;
} ipsess_trec, *ipsess_t;

#endif
