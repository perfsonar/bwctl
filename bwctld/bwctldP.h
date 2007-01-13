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

#define	BWCTLD_DEF_TESTPORT	(5001)

/*
 * Types
 */
typedef struct {

	I2Boolean	verbose;
	I2Boolean	help;

        int             access_prio;

	char		cwd[MAXPATHLEN];
	char		*confdir;
	char		*vardir;

	char		*iperfcmd;
	I2numT          bottleneckcapacity;
	uint16_t	*iperfports;
	uint16_t	def_port;
	uint16_t	port_range_len;
	uint16_t	port_count;
	char		*datadir;

        BWLPortRange    peerports;

	char		*authmode;
	uint32_t	auth_mode;	/* cooked version of authmode */
	char		*srcnode;

	char		*user;
	char		*group;
        I2Boolean       allowRoot;

	uint32_t	dieby;
	uint32_t	controltimeout;
#ifndef	NDEBUG
	I2Boolean	childwait;
#endif
	I2Boolean	daemon;

	double		syncfuzz;
        I2Boolean       allowUnsync;
} bwctld_opts;

#endif	/*	_BWCTLDP_H_	*/
