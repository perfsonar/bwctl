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
 *
 *    License:
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
#include <stdio.h>
#include <stdarg.h>
#include <bwlibP.h>

void
BWLError_(
        BWLContext	ctx,
        BWLErrSeverity	severity,
        BWLErrType	etype,
        const char	*fmt,
        ...
        )
{
    va_list ap;

    /*
     * Don't report errors that are not at least as severe as errmaskprio
     */
    if(severity > ctx->errmaskprio){
        return;
    }

    va_start(ap,fmt);

    if(ctx && ctx->eh){
        I2ErrLogVT(ctx->eh,(int)severity,(int)etype,fmt,ap);
    }
    else{
        char		buff[_BWL_ERR_MAXSTRING];

        vsnprintf(buff,sizeof(buff),fmt,ap);
        fwrite(buff,sizeof(char),strlen(buff),stderr);
        fwrite("\n",sizeof(char),1,stderr);
    }
    va_end(ap);

    return;
}
