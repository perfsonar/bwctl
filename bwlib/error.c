/*
**      $Id$
*/
/************************************************************************
*									*
*			     Copyright (C)  2003			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
**	File:		error.c
**
**	Author:		Jeff W. Boote
**
**	Date:		Tue Sep 16 14:26:09 MDT 2003
**
**	Description:	
*/
#include <stdio.h>
#include <stdarg.h>
#include <ipcntrlP.h>

void
IPFError_(
	IPFContext		ctx,
	IPFErrSeverity		severity,
	IPFErrType		etype,
	const char		*fmt,
	...
)
{
	va_list		ap;

	va_start(ap,fmt);

	if(ctx && ctx->eh){
		I2ErrLogVT(ctx->eh,(int)severity,etype,fmt,ap);
	}
	else{
		char		buff[_IPF_ERR_MAXSTRING];

		vsnprintf(buff,sizeof(buff),fmt,ap);
		fwrite(buff,sizeof(char),strlen(buff),stderr);
		fwrite("\n",sizeof(char),1,stderr);
	}
	va_end(ap);

	return;
}
