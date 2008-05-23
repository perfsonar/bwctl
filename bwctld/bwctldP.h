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
 *	File:		bwctldP.h
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep  9 16:07:42 MDT 2003
 *
 *	Description:	
 */
#ifndef	_BWCTLDP_H_
#define	_BWCTLDP_H_

#ifndef	BWCTLD_CONF_FILE
#define	BWCTLD_CONF_FILE	"bwctld.conf"
#endif

#define	BWCTLD_IPERF_DEF_TESTPORT	(5001)
#define	BWCTLD_THRULAYD_DEF_TESTPORT	(5003)

/*
 * Types
 */
typedef struct {
    I2Boolean	    help;

    char	    cwd[MAXPATHLEN];
    char	    *confdir;
    char	    *vardir;

    char	    *authmode;
    uint32_t	    auth_mode;	/* cooked version of authmode */
    char	    *srcnode;

    char	    *user;
    char	    *group;
    I2Boolean       allowRoot;

    uint32_t	    dieby;
    uint32_t	    controltimeout;
    I2Boolean	    daemon;

} bwctld_opts;

#endif	/*	_BWCTLDP_H_	*/
