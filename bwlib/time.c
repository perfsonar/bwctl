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
 *	File:		time.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:27:27 MDT 2003
 *
 *	Description:	
 *
 *	functions to encode and decode BWLTimeStamp into 8 octet
 *	buffer for transmitting over the network.
 *
 *	The format for a timestamp messages is as follows:
 *
 *	   0                   1                   2                   3
 *	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                Integer part of seconds			  |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|              Fractional part of seconds                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *	The format for an Error Estimate is:
 *	   0                   1           
 *	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|S|Z|   Scale   |   Multiplier  |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <bwlib/bwlib.h>

/*
 * Function:	_BWLEncodeTimeStamp
 *
 * Description:	
 * 		Takes an BWLTimeStamp structure and encodes the time
 * 		value from that structure to the byte array in network
 * 		byte order appropriate for sending the value over the wire.
 * 		(See above format diagram.)
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
_BWLEncodeTimeStamp(
	u_int8_t	buf[8],
	BWLTimeStamp	*tstamp
	)
{
	u_int32_t	t32;

	assert(tstamp);
	assert(buf);

	/*
	 * seconds - Most Significant 32 bits hold the seconds in
	 * host byte order. Set t32 to this value in network byte order,
	 * then copy them to bytes 0-4 in buf.
	 */
	t32 = htonl((tstamp->tstamp >> 32) & 0xFFFFFFFF);
	memcpy(&buf[0],&t32,4);

	/*
	 * frac seconds - Least significant 32 bits hold the fractional
	 * seconds in host byte order. Set t32 to this value in network
	 * byte order, then copy them to bytes 5-8 in buf.
	 */
	t32 = htonl(tstamp->tstamp & 0xFFFFFFFF);
	memcpy(&buf[4],&t32,4);

	return;
}

/*
 * Function:	_BWLEncodeTimeStampErrEstimate
 *
 * Description:	
 * 		Takes an BWLTimeStamp structure and encodes the time
 * 		error estimate value from that structure to the byte array
 * 		in network order as appropriate for sending the value over
 * 		the wire. (See above format diagram.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLBoolean
_BWLEncodeTimeStampErrEstimate(
	u_int8_t        buf[2],
	BWLTimeStamp    *tstamp
	)
{
	assert(tstamp);
	assert(buf);

	/*
	 * If multiplier is 0, this is an invalid error estimate.
	 */
	if(!tstamp->multiplier){
		return False;
	}

	/*
	 * Scale is 6 bit quantity, and first 2 bits MUST be zero here.
	 */
	buf[0] = tstamp->scale & 0x3F;

	/*
	 * Set the first bit for sync.
	 */
	if(tstamp->sync){
		buf[0] |= 0x80;
	}

	buf[1] = tstamp->multiplier;

	return True;
}

/*
 * Function:	_BWLDecodeTimeStamp
 *
 * Description:	
 * 		Takes a buffer of 8 bytes of bwlib protocol timestamp
 * 		information and saves it in the BWLTimeStamp structure
 * 		in the tstamp BWLNum64 field. (See above format diagram
 * 		for bwlib protocol timestamp format, and bwlib.h header
 * 		file for a description of the BWLNum64 type.)
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
_BWLDecodeTimeStamp(
	BWLTimeStamp	*tstamp,
	u_int8_t	buf[8]
	)
{
	u_int32_t	t32;

	assert(tstamp);
	assert(buf);

	/*
	 * First clear tstamp.
	 */
	memset(&tstamp->tstamp,0,8);

	/*
	 * seconds is first 4 bytes in network byte order.
	 * copy to a 32 bit int, correct the byte order, then assign
	 * to the most significant 32 bits of tstamp.
	 */
	memcpy(&t32,&buf[0],4);
	tstamp->tstamp = (BWLNum64)(ntohl(t32)) << 32;

	/*
	 * fractional seconds are the next 4 bytes in network byte order.
	 * copy to a 32 bit int, correct the byte order, then assign to
	 * the least significant 32 bits of tstamp.
	 */
	memcpy(&t32,&buf[4],4);
	tstamp->tstamp |= (ntohl(t32) & 0xFFFFFFFF);

	return;
}

/*
 * Function:	_BWLDecodeTimeStampErrEstimate
 *
 * Description:	
 * 		Takes a buffer of 2 bytes of bwlib protocol timestamp
 * 		error estimate information and saves it in the BWLTimeStamp
 * 		structure. (See above format diagram for bwlib protocol
 * 		timestamp error estimate format, and bwlib.h header
 * 		file for a description of the BWLNum64 type.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * 		True if the ErrEstimate is valid, False if it is not.
 * Side Effect:	
 */
BWLBoolean
_BWLDecodeTimeStampErrEstimate(
	BWLTimeStamp	*tstamp,
	u_int8_t	buf[2]
	)
{
	assert(tstamp);
	assert(buf);

	/*
	 * If multiplier is 0, this is an invalid timestamp. From here, just
	 * set sync and scale to 0 as well.
	 */
	if(!buf[1]){
		buf[0] = 0;
	}

	tstamp->sync = (buf[0] & 0x80)?1:0;
	tstamp->scale = buf[0] & 0x3F;
	tstamp->multiplier = buf[1];

	return (tstamp->multiplier != 0);
}

/*
 * Function:	BWLTimevalToTimeStamp
 *
 * Description:	
 * 	This function takes a struct timeval and converts the time value
 * 	to an BWLTimeStamp. This function assumes the struct timeval is
 * 	an absolute time offset from unix epoch (0h Jan 1, 1970), and converts
 * 	the time to an BWLTimeStamp which uses time similar to the description
 * 	in RFC 1305 (NTP). i.e. epoch is 0h Jan 1, 1900.
 *
 * 	The Error Estimate of the BWLTimeStamp structure is invalidated
 * 	in this function. (A struct timeval gives no indication of the error.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLTimeStamp *
BWLTimevalToTimeStamp(
	BWLTimeStamp	*tstamp,
	struct timeval	*tval
)
{
	/*
	 * Ensure valid tstamp, tval - and ensure scale of tv_nsec is valid
	 */
	if(!tstamp || !tval)
		return NULL;

	/*
	 * Now convert representation.
	 */
	BWLTimevalToNum64(&tstamp->tstamp,tval);

	/*
	 * Convert "epoch"'s - must do after conversion or there is the risk
	 * of overflow since time_t is a 32bit signed quantity instead of
	 * unsigned.
	 */
	tstamp->tstamp = BWLNum64Add(tstamp->tstamp,
				BWLULongToNum64(BWLJAN_1970));

	return tstamp;
}

/*
 * Function:	BWLTimeStampToTimeval
 *
 * Description:	
 * 	This function takes an BWLTimeStamp structure and returns a
 * 	valid struct timeval based on the time value encoded in it.
 * 	This function assumees the BWLTimeStamp is holding an absolute
 * 	time value, and is not holding a relative time. i.e. It assumes
 * 	the time value is relative to NTP epoch.
 *
 * 	The Error Estimate of the BWLTimeStamp structure is ignored by
 * 	this function. (A struct timeval gives no indication of the error.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
struct timeval *
BWLTimeStampToTimeval(
	struct timeval	*tval,
	BWLTimeStamp	*tstamp
	)
{
	if(!tval || !tstamp)
		return NULL;

	/*
	 * Convert "epoch"'s - must do before conversion or there is the risk
	 * of overflow since time_t is a 32bit signed quantity instead of
	 * unsigned.
	 */
	tstamp->tstamp = BWLNum64Sub(tstamp->tstamp,
				BWLULongToNum64(BWLJAN_1970));
	BWLNum64ToTimeval(tval,tstamp->tstamp);

	return tval;
}

/*
 * Function:	BWLTimespecToTimeStamp
 *
 * Description:	
 * 	This function takes a struct timespec and converts it to an
 * 	BWLTimeStamp. The timespec is assumed to be an absolute time
 * 	relative to unix epoch. The BWLTimeStamp will be an absolute
 * 	time relative to 0h Jan 1, 1900.
 *
 * 	If errest is not set, then parts of the BWLTimeStamp that deal
 * 	with the error estimate. (scale, multiplier, sync) will be
 * 	set to 0.
 *
 * 	If errest is set, sync will be unmodified. (An errest of 0 is
 * 	NOT valid, and will be treated as if errest was not set.)
 *
 * 	Scale and Multiplier will be set from the value of errest.
 *
 * 	If last_errest is set, then Scale and Multiplier will be left
 * 	unmodified if (*errest == *last_errest).
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLTimeStamp *
BWLTimespecToTimeStamp(
	BWLTimeStamp	*tstamp,
	struct timespec	*tval,
	u_int32_t	*errest,	/* usec's */
	u_int32_t	*last_errest
	)
{
	/*
	 * Ensure valid tstamp, tval - and ensure scale of tv_nsec is valid
	 */
	if(!tstamp || !tval)
		return NULL;

	/*
	 * Now convert representation.
	 */
	BWLTimespecToNum64(&tstamp->tstamp,tval);

	/*
	 * Convert "epoch"'s - must do after conversion or there is the risk
	 * of overflow since time_t is a 32bit signed quantity instead of
	 * unsigned.
	 */
	tstamp->tstamp = BWLNum64Add(tstamp->tstamp,
				BWLULongToNum64(BWLJAN_1970));

	/*
	 * If errest is set, and is non-zero.
	 */
	if(errest && *errest){
		/*
		 * If last_errest is set, and the error hasn't changed,
		 * then we don't touch the prec portion assuming it is
		 * already correct.
		 */
		if(!last_errest || (*errest != *last_errest)){
			BWLNum64	err;

			/*
			 * First normalize errest to 32bit fractional seconds.
			 */
			err = BWLUsecToNum64(*errest);

			/*
			 * Just in the unlikely event that err is represented
			 * by a type larger than 64 bits...
			 * (This ensures that scale will not overflow the
			 * 6 bits available to it.)
			 */
			err &= (u_int64_t)0xFFFFFFFFFFFFFFFFULL;

			/*
			 * Now shift err until it will fit in an 8 bit
			 * multiplier (after adding one for rounding err: this
			 * is the reason a value of 0xFF is shifted one last
			 * time), counting the shifts to set the scale.
			 */
			tstamp->scale = 0;
			while(err >= 0xFF){
				err >>= 1;
				tstamp->scale++;
			}
			err++;	/* rounding error:represents shifted off bits */
			tstamp->multiplier = 0xFF & err;
		}
	}
	else{
		tstamp->sync = 0;
		tstamp->scale = 0;
		tstamp->multiplier = 0;
	}

	return tstamp;
}

/*
 * Function:	BWLTimeStampToTimespec
 *
 * Description:	
 * 	This function takes an BWLTimeStamp structure and returns a
 * 	valid struct timespec based on the time value encoded in it.
 * 	This function assumees the BWLTimeStamp is holding an absolute
 * 	time value, and is not holding a relative time. i.e. It assumes
 * 	the time value is relative to NTP epoch.
 *
 * 	The Error Estimate of the BWLTimeStamp structure is ignored by
 * 	this function. (A struct timespec gives no indication of the error.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
struct timespec *
BWLTimeStampToTimespec(
	struct timespec	*tval,
	BWLTimeStamp	*tstamp
	)
{
	if(!tval || !tstamp)
		return NULL;

	/*
	 * Convert "epoch"'s - must do before conversion or there is the risk
	 * of overflow since time_t is a 32bit signed quantity instead of
	 * unsigned.
	 */
	tstamp->tstamp = BWLNum64Sub(tstamp->tstamp,
				BWLULongToNum64(BWLJAN_1970));
	BWLNum64ToTimespec(tval,tstamp->tstamp);

	return tval;
}

/*
 * Function:	BWLGetTimeStampError
 *
 * Description:	
 * 	Retrieve the timestamp error estimate as a double in seconds.
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
BWLGetTimeStampError(
	BWLTimeStamp	*tstamp
	)
{
	BWLNum64	err;
	u_int8_t	scale;

	if(!tstamp)
		return 0.0;

	/*
	 * Place multiplier in 64bit int large enough to hold full value.
	 * (Due to the interpretation of BWLNum64 being 32 bits of seconds,
	 * and 32 bits of "fraction", this effectively divides by 2^32.)
	 */
	err = tstamp->multiplier & 0xFF;

	/*
	 * Now shift it based on the "scale".
	 * (This affects the 2^scale multiplication.)
	 */
	scale = tstamp->scale & 0x3F;
	while(scale>0){
		err <<= 1;
		scale--;
	}

	return err;
}

/*
 * Function:	_BWLInitNTP
 *
 * Description:	
 * 	Initialize NTP.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 *
 * If STA_NANO is defined, we insist it is set, this way we can be sure that
 * ntp_gettime is returning a timespec and not a timeval.
 *
 * TODO: The correct way to fix this is:
 * 1. If ntptimeval contains a struct timespec - then use nano's period.
 * 2. else if STA_NANO is set, then use nano's.
 * 3. else ???(mills solution requires root - ugh)
 *    will this work?
 *    (do a timing test:
 * 		gettimeofday(A);
 * 		getntptime(B);
 * 		nanosleep(1000);
 * 		getntptime(C);
 * 		gettimeofday(D);
 *
 * 		1. Interprete B and C as usecs
 * 			if(D-A < C-B)
 * 				nano's
 * 			else
 * 				usecs
 */
int
_BWLInitNTP(
	BWLContext	ctx,
	I2Boolean	allowunsync
	)
{
	struct timex	ntp_conf;

	ntp_conf.modes = 0;

	if(ntp_adjtime(&ntp_conf) < 0){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"ntp_adjtime(): %M");
		return 1;
	}

	if(ntp_conf.status & STA_UNSYNC){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"NTP: Status UNSYNC!");
		if(!allowunsync)
			return 1;
	}

#ifdef	STA_NANO
	if( !(ntp_conf.status & STA_NANO)){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
		"_BWLInitNTP: STA_NANO must be set! - try \"ntptime -N\"");
		return 1;
	}
#endif
	return 0;
}

/*
 * rewrite _BWLGetTimespec to use the "offset" from ntp.
 * TODO: Remove this version once the other has been tested reasonably.
 */
#if	NOT
static struct timespec *
_BWLGetTimespec(
	BWLContext	ctx,
	struct timespec	*ts,
	u_int32_t	*esterr,
	int		*sync
	)
{
	struct ntptimeval	ntv;
	int			status;

	status = ntp_gettime(&ntv);

	if(status < 0){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"ntp_gettime(): %M");
		return NULL;
	}
	if(status > 0)
		*sync = 0;
	else
		*sync = 1;

	*esterr = (u_int32_t)ntv.esterror;
	assert((long)*esterr == ntv.esterror);

	/*
	 * Error estimate should never be 0, but I've seen ntp do it!
	 */
	if(!*esterr){
		*esterr = 1;
	}

#ifdef	STA_NANO
	*ts = ntv.time;
#else
	/*
	 * convert usec to nsec if not STA_NANO
	 */
	*(struct timeval*)ts = ntv.time;
	ts->tv_nsec *= 1000;
#endif

	return ts;
}
#endif

static struct timespec *
_BWLGetTimespec(
		BWLContext		ctx,
		struct timespec		*ts,
		u_int32_t		*esterr,
		int			*sync
		)
{
	struct timeval	tod;
	struct timex	ntp_conf;
	long		sec;

	ntp_conf.modes = 0;

	if(gettimeofday(&tod,NULL) != 0)
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"gettimeofday(): %M");
		return NULL;
	}

	if(ntp_adjtime(&ntp_conf) < 0)
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"ntp_adjtime(): %M");
		return NULL;
	}

	/* assign localtime */
	ts->tv_sec = tod.tv_sec;
	ts->tv_nsec = tod.tv_usec * 1000;	/* convert to nsecs */

	/*
	 * Apply ntp "offset"
	 */
#ifdef	STA_NANO
	sec = 1000000000;
#else
	sec = 1000000;
#endif
	/*
	 * Convert negative offsets to positive ones by decreasing
	 * the ts->tv_sec.
	 */
	while(ntp_conf.offset < 0){
		ts->tv_sec--;
		ntp_conf.offset += sec;
	}

	/*
	 * Make sure the "offset" is less than 1 second
	 */
	while(ntp_conf.offset >= sec){
		ts->tv_sec++;
		ntp_conf.offset -= sec;
	}

#ifndef	STA_NANO
	ntp_conf.offset *= 1000;
#endif
	ts->tv_nsec += ntp_conf.offset;
	if(ts->tv_nsec >= 1000000000){
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000;
	}

	/*
	 * Check sync flag
	 */
	if(ntp_conf.status & STA_UNSYNC)
		*sync = 0;
	else
		*sync = 1;

	/*
	 * Set estimated error
	 */
	*esterr = (u_int32_t)ntp_conf.esterror;
	assert((long)*esterr == ntp_conf.esterror);

	/*
	 * Error estimate should never be 0, but I've seen ntp do it!
	 */
	if(!*esterr){
		*esterr = 1;
	}

	return ts;
}

BWLTimeStamp *
BWLGetTimeStamp(
	BWLContext	ctx,
	BWLTimeStamp	*tstamp
	       )
{
	struct timespec		ts;
	u_int32_t		errest;
	int			sync;

	if(!tstamp)
		return NULL;

	if(!_BWLGetTimespec(ctx,&ts,&errest,&sync))
		return NULL;

	/* type conversion */
	return BWLTimespecToTimeStamp(tstamp,&ts,&errest,NULL);
}
