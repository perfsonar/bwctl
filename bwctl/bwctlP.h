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
 *	File:		iperfcP.h
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Mon Sep 15 11:16:04 MDT 2003
 *
 *	Description:	
 */
#ifndef	_iperfcp_h_
#define	_iperfcp_h_

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

#define DEF_UDP_RATE	1000000
/*
 * Lock file name. This file is created in the output directory to ensure
 * there is not more than one iperfc process writing there.
 */
#define	IPLOCK	".iplock"
/* TSTAMP FMT YYYYMMDDTHHMMSS	*/
#define TSTAMPCHARS	15
#define SUMMARY_EXT	".sum"

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

		I2Boolean	allowunsync	/* -Y */
#ifndef	NDEBUG
		I2Boolean	childwait;	/* -W */
#endif

		char		*savedir;	/* -d */
		u_int32_t	seriesInterval;	/* -I (seconds) */
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
		I2Boolean	printfiles;	/* -p */
		int		facility;	/* -e */
						/* -r stderr too */
		I2Boolean	version;	/* -v */

		u_int32_t	reportInterval;	/* -i (seconds) */
		u_int32_t	lenBuffer;	/* -l (bytes)	*/
		I2Boolean	udpTest;	/* -u	*/
		u_int32_t	windowSize;	/* -w 	*/
		u_int32_t	bandWidth;	/* -b (bits/sec) */
		u_int32_t	timeDuration;	/* -t (secs) */
		u_int32_t	parallel;	/* -P	*/
		u_int32_t	tos;		/* -S	*/

		I2Boolean	recv;		/* -s (iperf server) */
		I2Boolean	send;		/* -c (iperf client) */

	} opt;

	char			*remote_test;

	u_int32_t		auth_mode;

	IPFScheduleContext	sctx;
	IPFSID			sid;

	IPFNum64		*sessionStart;
	IPFNum64		ipftime_mem;

	FILE			*fp;
	FILE			*testfp;
	char			fname[PATH_MAX];

} ipapp_trec, *ipapp_t;

typedef struct{
	IPFControl	cntrl;
	int		sockfd;
	IPFNum64	rttbound;
	IPFNum64	waketime;
	IPFBoolean	send;
	IPFTestSpec	tspec;
} ipsess_trec, *ipsess_t;

#endif
