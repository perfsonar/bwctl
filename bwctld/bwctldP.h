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
 *	File:		iperfcdP.h
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep  9 16:07:42 MDT 2003
 *
 *	Description:	
 */
#ifndef	_IPERFCDP_H_
#define	_IPERFCDP_H_

#ifndef	IPERFCD_CONF_FILE
#define	IPERFCD_CONF_FILE	"iperfcd.conf"
#endif

/*
 * Types
 */
typedef struct {

	I2Boolean	verbose;
	I2Boolean	help;

	char		cwd[MAXPATHLEN];
	char		*confdir;
	char		*vardir;
	char		*ip2class;
	char		*class2limits;
	char		*passwd;

	char		*datadir;

	char		*authmode;
	u_int32_t	auth_mode;	/* cooked version of authmode */
	char		*srcnode;

	char		*user;
	char		*group;

	double		diskfudge;
	u_int32_t	dieby;
	u_int32_t	controltimeout;
#ifndef	NDEBUG
	I2Boolean	childwait;
#endif
	I2Boolean	daemon;
} iperfcd_opts;

#endif	/*	_IPERFCDP_H_	*/
