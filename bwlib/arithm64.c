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
 *	File:		arithm64.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:25:16 MDT 2003
 *
 *	Description:
 *		Arithmatic and conversion functions for the BWLNum64
 *		type.
 *
 * BWLNum64 is interpreted as 32bits of "seconds" and 32bits of
 * "fractional seconds".
 * The byte ordering is defined by the hardware for this value. 4 MSBytes are
 * seconds, 4 LSBytes are fractional. Each set of 4 Bytes is pulled out
 * via shifts/masks as a 32bit unsigned int when needed independently.
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
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <bwlib/bwlib.h>

#define MASK32(x) ((x) & 0xFFFFFFFFUL)
#define BILLION 1000000000UL
#define MILLION 1000000UL
#define	EXP2POW32	0x100000000ULL

/************************************************************************
 *									*	
 *			Arithmetic functions				*
 *									*	
 ************************************************************************/

/*
 * Function:	BWLNum64Mult
 *
 * Description:	
 *	Multiplication. Allows overflow.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLNum64
BWLNum64Mult(
        BWLNum64	x,
        BWLNum64	y
        )
{
    uint64_t xlo, xhi, ylo, yhi;

    xlo = MASK32(x);
    xhi = MASK32(x>>32);
    ylo = MASK32(y);
    yhi = MASK32(y>>32);

    return ((xlo*ylo)>>32)
         +  (xhi*ylo)
         +  (xlo*yhi)
         + ((xhi*yhi)<<32);
}

/************************************************************************
 *									*	
 *			Conversion functions				*
 *									*	
 ************************************************************************/

/*
 * Function:	BWLULongToNum64
 *
 * Description:	
 *	Convert an unsigned 32-bit integer into a BWLNum64 struct..
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLNum64
BWLULongToNum64(uint32_t a)
{
    return ((uint64_t)a << 32);
}

/*
 * Function:	BWLI2numTToNum64
 *
 * Description:	
 *	Convert an unsigned 64-bit integer into a BWLNum64 struct..
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLNum64
BWLI2numTToNum64(I2numT a)
{
    return (a << 32);
}


/*
 * Function:	BWLNum64toTimespec
 *
 * Description:	
 * 	Convert a time value in BWLNum64 representation to timespec
 * 	representation. These are "relative" time values. (Not absolutes - i.e.
 * 	they are not relative to some "epoch".) BWLNum64 values are
 * 	unsigned 64 integral types with the MS (Most Significant) 32 bits
 * 	representing seconds, and the LS (Least Significant) 32 bits
 * 	representing fractional seconds (at a resolution of 32 bits).
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
BWLNum64ToTimespec(
        struct timespec	*to,
        BWLNum64	from
        )
{
    /*
     * MS 32 bits represent seconds
     */
    to->tv_sec = (long)MASK32(from >> 32);

    /*
     * LS 32 bits represent fractional seconds, normalize them to nsecs:
     * frac/2^32 == nano/(10^9), so
     * nano = frac * 10^9 / 2^32
     */
    to->tv_nsec = (long)MASK32((MASK32(from)*BILLION) >> 32);

    while(to->tv_nsec >= (long)BILLION){
        to->tv_sec++;
        to->tv_nsec -= BILLION;
    }
}

/*
 * Function:	BWLTimespecToNum64
 *
 * Description:	
 *
 * 	Convert a time value in timespec representation to an BWLNum64
 * 	representation. These are "relative" time values. (Not absolutes - i.e.
 * 	they are not relative to some "epoch".) BWLNum64 values are
 * 	unsigned 64 integral types with the Most Significant 32 of those
 * 	64 bits representing seconds. The Least Significant 32 bits
 * 	represent fractional seconds at a resolution of 32 bits.
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
BWLTimespecToNum64(
        BWLNum64	*to,
        struct timespec	*from
        )
{
    uint32_t	sec = from->tv_sec;
    uint32_t	nsec = from->tv_nsec;

    *to = 0;

    /*
     * Ensure nsec's is only fractional.
     */
    while(nsec >= BILLION){
        sec++;
        nsec -= BILLION;
    }

    /*
     * Place seconds in MS 32 bits.
     */
    *to = (uint64_t)MASK32(sec) << 32;
    /*
     * Normalize nsecs to 32bit fraction, then set that to LS 32 bits.
     */
    *to |= MASK32(((uint64_t)nsec << 32)/BILLION);

    return;
}
/*
 * Function:	BWLNum64toTimeval
 *
 * Description:	
 * 	Convert a time value in BWLNum64 representation to timeval
 * 	representation. These are "relative" time values. (Not absolutes - i.e.
 * 	they are not relative to some "epoch".) BWLNum64 values are
 * 	unsigned 64 integral types with the MS (Most Significant) 32 bits
 * 	representing seconds, and the LS (Least Significant) 32 bits
 * 	representing fractional seconds (at a resolution of 32 bits).
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
BWLNum64ToTimeval(
        struct timeval	*to,
        BWLNum64	from
        )
{
    /*
     * MS 32 bits represent seconds
     */
    to->tv_sec = (long)MASK32(from >> 32);

    /*
     * LS 32 bits represent fractional seconds, normalize them to usecs:
     * frac/2^32 == micro/(10^6), so
     * nano = frac * 10^6 / 2^32
     */
    to->tv_usec = (long)MASK32((MASK32(from)*MILLION) >> 32);

    while(to->tv_usec >= (long)MILLION){
        to->tv_sec++;
        to->tv_usec -= MILLION;
    }
}

/*
 * Function:	BWLTimevalToNum64
 *
 * Description:	
 *
 * 	Convert a time value in timeval representation to an BWLNum64
 * 	representation. These are "relative" time values. (Not absolutes - i.e.
 * 	they are not relative to some "epoch".) BWLNum64 values are
 * 	unsigned 64 integral types with the Most Significant 32 of those
 * 	64 bits representing seconds. The Least Significant 32 bits
 * 	represent fractional seconds at a resolution of 32 bits.
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
BWLTimevalToNum64(
        BWLNum64	*to,
        struct timeval	*from
        )
{
    uint32_t	sec = from->tv_sec;
    uint32_t	usec = from->tv_usec;

    *to = 0;

    /*
     * Ensure usec's is only fractional.
     */
    while(usec >= MILLION){
        sec++;
        usec -= MILLION;
    }

    /*
     * Place seconds in MS 32 bits.
     */
    *to = (uint64_t)MASK32(sec) << 32;
    /*
     * Normalize usecs to 32bit fraction, then set that to LS 32 bits.
     */
    *to |= MASK32(((uint64_t)usec << 32)/MILLION);

    return;
}

/*
 * Function:	BWLNum64toDouble
 *
 * Description:	
 * 	Convert an BWLNum64 time value to a double representation. 
 * 	The double will contain the number of seconds with the fractional
 * 	portion of the BWLNum64 mapping to the portion of the double
 * 	represented after the radix point. This will obviously loose
 * 	some precision after the radix point, however - larger values
 * 	will be representable in double than an BWLNum64.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
double
BWLNum64ToDouble(
        BWLNum64	from
        )
{
    return (double)from / EXP2POW32;
}

/*
 * Function:	BWLDoubleToNum64
 *
 * Description:	
 * 	Convert a double value to an BWLNum64 representation.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLNum64
BWLDoubleToNum64(
        double	from
        )
{
    if(from < 0){
        return 0;
    }
    return (BWLNum64)(from * EXP2POW32);
}

/*
 * Function:	BWLUsecToNum64
 *
 * Description:	
 * 	Convert an unsigned 32bit number representing some number of
 * 	microseconds to an BWLNum64 representation.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
    BWLNum64
BWLUsecToNum64(uint32_t usec)
{
    return ((uint64_t)usec << 32)/MILLION;
}
