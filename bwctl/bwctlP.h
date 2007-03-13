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

typedef struct {
	/*
	 * mode var
	 */
	uint32_t	auth_mode;

	/*
	 * AESKEY auth vars
	 */
	char		*identity;
	char		*keyfile;
	uint8_t	*aeskey;
	uint8_t	aesbuff[16];
} aeskey_auth_rec, *aeskey_auth;

typedef struct{
	char		*host;
	aeskey_auth	auth;
	BWLControl	cntrl;
	int		sockfd;
	BWLNum64	rttbound;
	BWLNum64	waketime;
	BWLBoolean	send;
        BWLTestSpec     tspec;
        BWLTesterAvailability avail_testers;
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
		uint32_t	tester;   	/* -T iperf/nuttcp/thrulay */

		uint32_t	reportInterval;	/* -i (seconds) */
		uint32_t	lenBuffer;	/* -l (bytes)	*/
		I2Boolean	udpTest;	/* -u	*/
		I2Boolean	winset;		/* -w/-W specified */
		uint32_t	windowSize;	/* -w 	*/
		I2Boolean	dynamicWindowSize;	/* -W used for -w */
		uint32_t	bandWidth;	/* -b (bits/sec) */
		uint32_t	timeDuration;	/* -t (secs) */
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

	FILE			*fp;
	FILE			*testfp;
	char			fname[PATH_MAX];

} ipapp_trec, *ipapp_t;

#endif
