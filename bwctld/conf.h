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
 *	File:		conf.h
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:28:48 MDT 2003
 *
 *	Description:	
 */
#ifndef	IPD_CONF_H
#define	IPD_CONF_H

#include <stdio.h>
#include <ipcntrl/ipcntrl.h>

/*
 * Growth increment for linebuffer.
 */
#define IPFDLINEBUFINC	120


/*
 * same charactors isspace checks for - useful for strtok splits
 * of whitespace.
 */
#define IPFDWSPACESET   "\t\n\v\f\r "

extern int
IPFDGetConfLine(
	IPFContext	ctx,
	FILE		*fp,
	int		rc,
	char		**lbuf,
	size_t		*lbuf_max
	);

extern int
IPFDReadConfVar(
	FILE	*fp,
	int	rc,
	char	*key,
	char	*val,
	size_t	max,
	char	**lbuf,
	size_t	*lbuf_max
	);

#endif	/* IPD_CONF_H */
