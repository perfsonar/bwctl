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
