/*
 *      $Id$
 */
/*
 *	File:		util.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:27:47 MDT 2003
 *
 *	Description:	
 *
 *    License:
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the following copyright notice,
 *       this list of conditions and the disclaimer below.
 * 
 *        Copyright (c) 2003-2008, Internet2
 * 
 *                              All rights reserved.
 * 
 *     * Redistribution in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 *    *  Neither the name of Internet2 nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       explicit prior written permission.
 * 
 * You are under no obligation whatsoever to provide any enhancements to Internet2,
 * or its contributors.  If you choose to provide your enhancements, or if you
 * choose to otherwise publish or distribute your enhancement, in source code form
 * without contemporaneously requiring end users to enter into a separate written
 * license agreement for such enhancements, then you thereby grant Internet2, its
 * contributors, and its members a non-exclusive, royalty-free, perpetual license
 * to copy, display, install, use, modify, prepare derivative works, incorporate
 * into the software or other computer software, distribute, and sublicense your
 * enhancements or derivative works thereof, in binary and source code form.
 * 
 * DISCLAIMER - THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * “AS IS” AND WITH ALL FAULTS.  THE UNIVERSITY OF DELAWARE, INTERNET2, ITS CONTRI-
 * BUTORS, AND ITS MEMBERS DO NOT IN ANY WAY WARRANT, GUARANTEE, OR ASSUME ANY RES-
 * PONSIBILITY, LIABILITY OR OTHER UNDERTAKING WITH RESPECT TO THE SOFTWARE. ANY E-
 * XPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRAN-
 * TIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT
 * ARE HEREBY DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH THE USER THEREOF.  IN NO EVENT SHALL THE COPYRIGHT
 * OWNER, CONTRIBUTORS, OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELO-
 * PMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTIT-
 * UTE GOODS OR SERVICES; REMOVAL OR REINSTALLATION LOSS OF USE, DATA, SAVINGS OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILIT-
 * Y, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHE-
 * RWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRUBUTION OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <bwlib/bwlib.h>

#include "bwlibP.h"

/*
 * Function:    BWLPortsSetI
 *
 * Description:    
 *              Initialize port-range so the 'next port' function starts
 *              with the given 'i' port. If i is 0, this function initializes
 *              the port-range with a random port (or failing that, uses
 *              the lowest value in the port-range).
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
void
BWLPortsSetI(
        BWLContext      ctx,
        BWLPortRange    prange,
        uint16_t        i
        )
{
    uint16_t    range;

    /*
     * Initialize current port
     */
    if((i != 0) && (i > prange->low) && (i < prange->high)){
        prange->i = i;
    }
    else{
        prange->i = prange->low;
        if( (range = BWLPortsRange(prange))){
            uint32_t    r;

            /*
             * Get a random 32bit num to aid in selecting first port.
             * (Silently fail - it is not that big of a deal if the
             * first port is selected.)
             */
            if(I2RandomBytes(ctx->rand_src,(uint8_t*)&r,4) == 0){
                prange->i = prange->low + ((double)r / 0xffffffff * range);
            }
        }
    }

    return;
}

/*
 * Function:    BWLPortsParse
 *
 * Description:    
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
I2Boolean
BWLPortsParse(
        BWLContext      ctx,
        const char      *pspec,
        BWLPortRange    prange
        )
{
    char        chmem[BWL_MAX_TOOLNAME];
    char        *tstr,*endptr;
    long        tint;

    if(!pspec || (strlen(pspec) >= sizeof(chmem))){
	BWLError(ctx,BWLErrFATAL,EINVAL,"Invalid port-range: \"%s\"",pspec);
        return False;
    }
    strcpy(chmem,pspec);

    tstr = chmem;
    endptr = NULL;

    while(isspace((int)*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto failed;
    }
    prange->low = (uint16_t)tint;

    while(isspace((int)*endptr)) endptr++;

    switch(*endptr){
        case '\0':
            prange->high = prange->low;
            goto done;
            break;
        case '-':
            endptr++;
            break;
        default:
            goto failed;
    }

    tstr = endptr;
    endptr = NULL;
    while(isspace((int)*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto failed;
    }
    prange->high = (uint16_t)tint;

    if(prange->high < prange->low){
        goto failed;
    }

done:
    BWLPortsSetI(ctx,prange,0);
    return True;

failed:
    BWLError(ctx,BWLErrFATAL,EINVAL,"Invalid port-range: \"%s\"",pspec);

    return False;
}

uint16_t
BWLPortsNext(
        BWLPortRange   prange
        )
{
    uint16_t    i;

    assert(prange);

    if( !BWLPortsRange(prange)){
        return prange->i;
    }

    /* save i to return */
    i = prange->i;

    /* compute next i */
    prange->i -= prange->low;
    prange->i = (prange->i + 1) % BWLPortsRange(prange);
    prange->i += prange->low;

    return i;
}

char *
BWLUInt64Dup(
        BWLContext  ctx,
        uint64_t    n
        )
 {
    char    nbuf[100];
    int     len;
    char    *ret;

    nbuf[sizeof(nbuf)-1] = '\0';
    len = snprintf(nbuf,sizeof(nbuf)-1,"%llu",(unsigned long long)n);
    if((len < 0) || ((unsigned)len >= sizeof(nbuf))){
        BWLError(ctx,BWLErrFATAL,errno,"snprintf(): %M");
        return NULL;
    }

    if((ret = strdup(nbuf)))
        return ret;

    BWLError(ctx,BWLErrFATAL,errno,"strdup(): %M");
    return NULL;
 }

char *
BWLUInt32Dup(
        BWLContext  ctx,
        uint32_t    n
        )
{
    return BWLUInt64Dup(ctx,(uint64_t)n);
}
