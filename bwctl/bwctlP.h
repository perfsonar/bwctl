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
 *	Date:		Fri Sep 12 13:42:51 MDT 2003
 *
 *	Description:	
 */
#ifndef	_iperfcp_h_
#define	_iperfcp_h_

/*
 * Application "context" structure
 */
typedef	struct {
	/*
	**	Command line options
	*/
	struct  {
		/* Flags */
		I2Boolean       records;          /* -v */
		I2Boolean       full;             /* -V */
		I2Boolean	quiet;            /* -Q */
		I2Boolean	raw;		/* -R */

		I2Boolean	to;               /* -t */
		I2Boolean	from;             /* -f */
		char            *save_to_test;    /* -T */
		char            *save_from_test;  /* -F */

		char		*authmode;        /* -A */
		char		*identity;        /* -u */
		u_int32_t	numPackets;       /* -c */

		double		lossThreshold;    /* -l */
		float           percentile;       /* -a */

		char		*passwd;          /* -P */
		char		*srcaddr;         /* -S */

#ifndef	NDEBUG
		I2Boolean	childwait;        /* -w */
#endif

		float		mean_wait;        /* -i  (seconds) */
		u_int32_t	padding;          /* -s */

	} opt;

	char			*remote_test;
	char			*remote_serv;

	u_int32_t		auth_mode;

	IPFContext		lib_ctx;
	IPFControl		cntrl;

} ip_cntrl_trec, *ip_cntrl_t;

#endif
