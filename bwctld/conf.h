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
#include <bwlib/bwlib.h>

/*
 * Growth increment for linebuffer.
 */
#define BWLDLINEBUFINC	120


/*
 * same charactors isspace checks for - useful for strtok splits
 * of whitespace.
 */
#define BWLDWSPACESET   "\t\n\v\f\r "

extern int
BWLDGetConfLine(
	BWLContext	ctx,
	FILE		*fp,
	int		rc,
	char		**lbuf,
	size_t		*lbuf_max
	);

extern int
BWLDReadConfVar(
	FILE	*fp,
	int	rc,
	char	*key,
	char	*val,
	size_t	max,
	char	**lbuf,
	size_t	*lbuf_max
	);

#endif	/* IPD_CONF_H */
