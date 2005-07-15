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
 *	File:		util.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:27:47 MDT 2003
 *
 *	Description:	
 */
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <bwlib/bwlib.h>


/*
 * Function:    BWLParsePorts
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
BWLParsePorts(
        char            *pspec,
        BWLPortRange    prange,
        BWLPortRange    *prange_ret,
        I2ErrHandle     ehand,
        FILE            *fout
        )
{
    char    *tstr,*endptr;
    long    tint;

    if(!pspec) return False;

    tstr = pspec;
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
            /* only allow a single value if it is 0 */
            if(prange->low){
                goto failed;
            }
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
    /*
     * If ephemeral is specified, shortcut by not setting.
     */
    if(!prange->high && !prange->low)
        return True;

    /*
     * Set.
     */
    *prange_ret = prange;

    return True;

failed:
    if(ehand){
        I2ErrLogP(ehand,EINVAL,"Invalid port-range: \"%s\"",pspec);
    }
    else if(fout){
        fprintf(fout,"Invalid port-range: \"%s\"",pspec);
    }

    return False;
}
