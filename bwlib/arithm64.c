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
 *	Multiplication. Allows overflow. Straightforward implementation
 *	of Knuth vol.2 Algorithm 4.3.1.M (p.268)
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
	unsigned long w[4];
	u_int64_t xdec[2];
	u_int64_t ydec[2];

	int i, j;
	u_int64_t k, t;
	BWLNum64 ret;

	xdec[0] = MASK32(x);
	xdec[1] = MASK32(x>>32);
	ydec[0] = MASK32(y);
	ydec[1] = MASK32(y>>32);

	for (j = 0; j < 4; j++)
		w[j] = 0; 

	for (j = 0;  j < 2; j++) {
		k = 0;
		for (i = 0; ; ) {
			t = k + (xdec[i]*ydec[j]) + w[i + j];
			w[i + j] = t%EXP2POW32;
			k = t/EXP2POW32;
			if (++i < 2)
				continue;
			else {
				w[j + 2] = k;
				break;
			}
		}
	}

	ret = w[2];
	ret <<= 32;
	return w[1] + ret;
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
BWLULongToNum64(u_int32_t a)
{
	return ((u_int64_t)a << 32);
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
	to->tv_sec = MASK32(from >> 32);

	/*
	 * LS 32 bits represent fractional seconds, normalize them to nsecs:
	 * frac/2^32 == nano/(10^9), so
	 * nano = frac * 10^9 / 2^32
	 */
	to->tv_nsec = MASK32((MASK32(from)*BILLION) >> 32);
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
	u_int32_t	sec = from->tv_sec;
	u_int32_t	nsec = from->tv_nsec;

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
	*to = (u_int64_t)MASK32(sec) << 32;
	/*
	 * Normalize nsecs to 32bit fraction, then set that to LS 32 bits.
	 */
	*to |= MASK32(((u_int64_t)nsec << 32)/BILLION);

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
	to->tv_sec = MASK32(from >> 32);

	/*
	 * LS 32 bits represent fractional seconds, normalize them to usecs:
	 * frac/2^32 == micro/(10^6), so
	 * nano = frac * 10^6 / 2^32
	 */
	to->tv_usec = MASK32((MASK32(from)*MILLION) >> 32);
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
	u_int32_t	sec = from->tv_sec;
	u_int32_t	usec = from->tv_usec;

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
	*to = (u_int64_t)MASK32(sec) << 32;
	/*
	 * Normalize usecs to 32bit fraction, then set that to LS 32 bits.
	 */
	*to |= MASK32(((u_int64_t)usec << 32)/MILLION);

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
BWLUsecToNum64(u_int32_t usec)
{
	return ((u_int64_t)usec << 32)/MILLION;
}
