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
 *	functions to encode and decode IPFTimeStamp into 8 octet
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
#include <ipcntrl/ipcntrl.h>

/*
 * Function:	_IPFEncodeTimeStamp
 *
 * Description:	
 * 		Takes an IPFTimeStamp structure and encodes the time
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
_IPFEncodeTimeStamp(
	u_int8_t	buf[8],
	IPFTimeStamp	*tstamp
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
	t32 = htonl((tstamp->ipftime >> 32) & 0xFFFFFFFF);
	memcpy(&buf[0],&t32,4);

	/*
	 * frac seconds - Least significant 32 bits hold the fractional
	 * seconds in host byte order. Set t32 to this value in network
	 * byte order, then copy them to bytes 5-8 in buf.
	 */
	t32 = htonl(tstamp->ipftime & 0xFFFFFFFF);
	memcpy(&buf[4],&t32,4);

	return;
}

/*
 * Function:	_IPFEncodeTimeStampErrEstimate
 *
 * Description:	
 * 		Takes an IPFTimeStamp structure and encodes the time
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
IPFBoolean
_IPFEncodeTimeStampErrEstimate(
	u_int8_t        buf[2],
	IPFTimeStamp    *tstamp
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
 * Function:	_IPFDecodeTimeStamp
 *
 * Description:	
 * 		Takes a buffer of 8 bytes of ipcntrl protocol timestamp
 * 		information and saves it in the IPFTimeStamp structure
 * 		in the ipftime IPFNum64 field. (See above format diagram
 * 		for ipcntrl protocol timestamp format, and ipcntrl.h header
 * 		file for a description of the IPFNum64 type.)
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
_IPFDecodeTimeStamp(
	IPFTimeStamp	*tstamp,
	u_int8_t	buf[8]
	)
{
	u_int32_t	t32;

	assert(tstamp);
	assert(buf);

	/*
	 * First clear ipftime.
	 */
	memset(&tstamp->ipftime,0,8);

	/*
	 * seconds is first 4 bytes in network byte order.
	 * copy to a 32 bit int, correct the byte order, then assign
	 * to the most significant 32 bits of ipftime.
	 */
	memcpy(&t32,&buf[0],4);
	tstamp->ipftime = (IPFNum64)(ntohl(t32)) << 32;

	/*
	 * fractional seconds are the next 4 bytes in network byte order.
	 * copy to a 32 bit int, correct the byte order, then assign to
	 * the least significant 32 bits of ipftime.
	 */
	memcpy(&t32,&buf[4],4);
	tstamp->ipftime |= (ntohl(t32) & 0xFFFFFFFF);

	return;
}

/*
 * Function:	_IPFDecodeTimeStampErrEstimate
 *
 * Description:	
 * 		Takes a buffer of 2 bytes of ipcntrl protocol timestamp
 * 		error estimate information and saves it in the IPFTimeStamp
 * 		structure. (See above format diagram for ipcntrl protocol
 * 		timestamp error estimate format, and ipcntrl.h header
 * 		file for a description of the IPFNum64 type.)
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
IPFBoolean
_IPFDecodeTimeStampErrEstimate(
	IPFTimeStamp	*tstamp,
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
 * Function:	IPFTimevalToTimeStamp
 *
 * Description:	
 * 	This function takes a struct timeval and converts the time value
 * 	to an IPFTimeStamp. This function assumes the struct timeval is
 * 	an absolute time offset from unix epoch (0h Jan 1, 1970), and converts
 * 	the time to an IPFTimeStamp which uses time similar to the description
 * 	in RFC 1305 (NTP). i.e. epoch is 0h Jan 1, 1900.
 *
 * 	The Error Estimate of the IPFTimeStamp structure is invalidated
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
IPFTimeStamp *
IPFTimevalToTimeStamp(
	IPFTimeStamp	*tstamp,
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
	IPFTimevalToNum64(&tstamp->ipftime,tval);

	/*
	 * Convert "epoch"'s - must do after conversion or there is the risk
	 * of overflow since time_t is a 32bit signed quantity instead of
	 * unsigned.
	 */
	tstamp->ipftime = IPFNum64Add(tstamp->ipftime,
				IPFULongToNum64(IPFJAN_1970));

	return tstamp;
}

/*
 * Function:	IPFTimeStampToTimeval
 *
 * Description:	
 * 	This function takes an IPFTimeStamp structure and returns a
 * 	valid struct timeval based on the time value encoded in it.
 * 	This function assumees the IPFTimeStamp is holding an absolute
 * 	time value, and is not holding a relative time. i.e. It assumes
 * 	the time value is relative to NTP epoch.
 *
 * 	The Error Estimate of the IPFTimeStamp structure is ignored by
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
IPFTimeStampToTimeval(
	struct timeval	*tval,
	IPFTimeStamp	*tstamp
	)
{
	if(!tval || !tstamp)
		return NULL;

	/*
	 * Convert "epoch"'s - must do before conversion or there is the risk
	 * of overflow since time_t is a 32bit signed quantity instead of
	 * unsigned.
	 */
	tstamp->ipftime = IPFNum64Sub(tstamp->ipftime,
				IPFULongToNum64(IPFJAN_1970));
	IPFNum64ToTimeval(tval,tstamp->ipftime);

	return tval;
}

/*
 * Function:	IPFTimespecToTimeStamp
 *
 * Description:	
 * 	This function takes a struct timespec and converts it to an
 * 	IPFTimeStamp. The timespec is assumed to be an absolute time
 * 	relative to unix epoch. The IPFTimeStamp will be an absolute
 * 	time relative to 0h Jan 1, 1900.
 *
 * 	If errest is not set, then parts of the IPFTimeStamp that deal
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
IPFTimeStamp *
IPFTimespecToTimeStamp(
	IPFTimeStamp	*tstamp,
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
	IPFTimespecToNum64(&tstamp->ipftime,tval);

	/*
	 * Convert "epoch"'s - must do after conversion or there is the risk
	 * of overflow since time_t is a 32bit signed quantity instead of
	 * unsigned.
	 */
	tstamp->ipftime = IPFNum64Add(tstamp->ipftime,
				IPFULongToNum64(IPFJAN_1970));

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
			IPFNum64	err;

			/*
			 * First normalize errest to 32bit fractional seconds.
			 */
			err = IPFUsecToNum64(*errest);

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
 * Function:	IPFTimeStampToTimespec
 *
 * Description:	
 * 	This function takes an IPFTimeStamp structure and returns a
 * 	valid struct timespec based on the time value encoded in it.
 * 	This function assumees the IPFTimeStamp is holding an absolute
 * 	time value, and is not holding a relative time. i.e. It assumes
 * 	the time value is relative to NTP epoch.
 *
 * 	The Error Estimate of the IPFTimeStamp structure is ignored by
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
IPFTimeStampToTimespec(
	struct timespec	*tval,
	IPFTimeStamp	*tstamp
	)
{
	if(!tval || !tstamp)
		return NULL;

	/*
	 * Convert "epoch"'s - must do before conversion or there is the risk
	 * of overflow since time_t is a 32bit signed quantity instead of
	 * unsigned.
	 */
	tstamp->ipftime = IPFNum64Sub(tstamp->ipftime,
				IPFULongToNum64(IPFJAN_1970));
	IPFNum64ToTimespec(tval,tstamp->ipftime);

	return tval;
}

/*
 * Function:	IPFGetTimeStampError
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
IPFNum64
IPFGetTimeStampError(
	IPFTimeStamp	*tstamp
	)
{
	IPFNum64	err;
	u_int8_t	scale;

	if(!tstamp)
		return 0.0;

	/*
	 * Place multiplier in 64bit int large enough to hold full value.
	 * (Due to the interpretation of IPFNum64 being 32 bits of seconds,
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
 * Function:	_IPFInitNTP
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
_IPFInitNTP(
	IPFContext	ctx
	)
{
	struct timex	ntp_conf;

	ntp_conf.modes = 0;

	if(ntp_adjtime(&ntp_conf) < 0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"ntp_adjtime(): %M");
		return 1;
	}

	if(ntp_conf.status & STA_UNSYNC){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"NTP: Status UNSYNC!");
		return 1;
	}

#ifdef	STA_NANO
	if( !(ntp_conf.status & STA_NANO)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
		"_IPFInitNTP: STA_NANO must be set! - try \"ntptime -N\"");
		return 1;
	}
#endif
	return 0;
}

static struct timespec *
_IPFGetTimespec(
	IPFContext	ctx,
	struct timespec	*ts,
	u_int32_t	*esterr,
	int		*sync
	)
{
	struct ntptimeval	ntv;
	int			status;

	status = ntp_gettime(&ntv);

	if(status < 0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"ntp_gettime(): %M");
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

IPFTimeStamp *
IPFGetTimeStamp(
	IPFContext	ctx,
	IPFTimeStamp	*tstamp
	       )
{
	struct timespec		ts;
	u_int32_t		errest;
	int			sync;

	if(!tstamp)
		return NULL;

	if(!_IPFGetTimespec(ctx,&ts,&errest,&sync))
		return NULL;

	/* type conversion */
	return IPFTimespecToTimeStamp(tstamp,&ts,&errest,NULL);
}
