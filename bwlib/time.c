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
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <sys/time.h>
#include <sys/types.h>
#include <bwlib/bwlib.h>
#ifdef  HAVE_SYS_TIMEX_H
#include <sys/timex.h>
#endif

static struct timeval   timeoffset;
static int              sign_timeoffset = 0;
static int              ntpsyscall_fails = 0;
static int              allow_unsync = 0;

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
        BWLContext	ctx
        )
{
    char    *toffstr=NULL;

    /*
     * If this system has the ntp system calls, use them. Otherwise,
     * assume the clock is not synchronized.
     * (Setting SyncFuzz is advisable in this case.)
     */
#ifdef  HAVE_SYS_TIMEX_H
    {
        struct timex	ntp_conf;

        memset(&ntp_conf,0,sizeof(ntp_conf));
        if( ntp_adjtime(&ntp_conf) < 0){
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,"ntp_adjtime(): %M");
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "NTP: BWCTL will not be able to verify synchronization on this system");
            ntpsyscall_fails = 1;
            goto NOADJTIME;
        }

        if(ntp_conf.status & STA_UNSYNC){
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "NTP: Status UNSYNC (clock offset problems likely)");
        }

#ifdef	STA_NANO
        if( !(ntp_conf.status & STA_NANO)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "NTP: STA_NANO must be set! - try \"ntptime -N\"");
            return 1;
        }
#endif	/*  STA_NANO */
    }
#else
NOADJTIME:
    if( (BWLContextConfigGetV(ctx,BWLAllowUnsync))){
        allow_unsync = 1;
    }
    else{
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                "NTP: Status UNSYNC (clock offset problems likely)");
    }
#endif  /* HAVE_SYS_TIMEX_H */

    if( !(toffstr = getenv("BWCTL_DEBUG_TIMEOFFSET"))){
        timeoffset.tv_sec = 0;
        timeoffset.tv_usec = 0;
    }
    else{
        double  td;
        char    *estr=NULL;

        td = strtod(toffstr,&estr);
        if((toffstr == estr) || (errno == ERANGE)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "Invalid BWCTL_DEBUG_TIMEOFFSET env var: %s",toffstr);
            return 1;
        }

        if(td == 0.0){
            sign_timeoffset = 0;
        }
        else{
            if(td > 0.0){
                sign_timeoffset = 1;
            }
            else{
                sign_timeoffset = -1;
                td = -td;
            }

            timeoffset.tv_sec = trunc(td);
            td -= timeoffset.tv_sec;
            td *= 1000000;
            timeoffset.tv_usec = trunc(td);

            BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                    "BWCTL_DEBUG_TIMEOFFSET: sec=%c%lu, usec=%lu",
                    (sign_timeoffset > 0)?'+':'-',
                    timeoffset.tv_sec,timeoffset.tv_usec);
        }
    }

    return 0;
}

static struct timespec *
_BWLGetTimespec(
        BWLContext	ctx,
        struct timespec	*ts,
        uint32_t	*esterr,
        int		*sync
        )
{
    struct timeval  tod;
    static long	    syncfuzz = 0;
    static double   *dbptr = NULL;
    uint32_t        maxerr;

    /*
     * By default, assume the clock is unsynchronized, but that it
     * is still acurate to within 1 second (1000000 usec's).
     */
    *sync = 0;
    maxerr = (uint32_t)1000000;

    if(gettimeofday(&tod,NULL) != 0){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"gettimeofday(): %M");
        return NULL;
    }

    /* assign localtime */
    ts->tv_sec = tod.tv_sec;
    ts->tv_nsec = tod.tv_usec * 1000;	/* convert to nsecs */

    /*
     * If ntp system calls are available use them to determine
     * time error.
     */
#ifdef HAVE_SYS_TIMEX_H
    if( !ntpsyscall_fails){
        struct timex	ntp_conf;
	int n;

        memset(&ntp_conf,0,sizeof(ntp_conf));
        n = ntp_adjtime(&ntp_conf);

        /*
         * Check sync flag
         */
        if(n < 0){
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,"ntp_adjtime(): %M");
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "NTP: BWCTL will not be able to verify synchronization on this system");
            ntpsyscall_fails = 1;
        }
        else if(ntp_conf.status & STA_UNSYNC){
            /*
             * Report the unsync state - but only at level "info".
             * This is reported at level "warning" at initialization.
             */
            BWLError(ctx,BWLErrINFO,BWLErrUNKNOWN,"NTP: Status UNSYNC!");
            if( !(BWLContextConfigGetV(ctx,BWLAllowUnsync))){
                BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                        "allowunsync is not set, failing.");
                return NULL;
            }
        }
        else{
            long    sec;

            *sync = 1;
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

            maxerr = (uint32_t)ntp_conf.maxerror;
        }

    }
#endif

    /*
     * See if SyncFuzz was set.
     * Used to increase tolerance for incomplete NTP configs.
     */
    if(!dbptr){
        dbptr = (double*)BWLContextConfigGetV(ctx,BWLSyncFuzz);
        if(dbptr){
            /*
             * BWLSyncFuzz is specified as a double (sec)
             * ntp errors are long (usec) convert.
             */
            syncfuzz = *dbptr * 1000000;
        }
        dbptr = (void*)1; /* not a valid pointer - just non-null */
    }

    /*
     * Set estimated error
     */
    *esterr = maxerr + syncfuzz;

    /*
     * Make sure a non-zero error is always returned - perfection
     * is not allowed. ;)
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
    struct timespec ts;
    uint32_t	    errest;
    int		    sync;

    if(!tstamp)
        return NULL;

    if(!_BWLGetTimespec(ctx,&ts,&errest,&sync))
        return NULL;

    /* type conversion */
    return BWLTimespecToTimeStamp(tstamp,&ts,&errest,NULL);
}

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
        uint8_t	        buf[8],
        BWLTimeStamp	*tstamp
        )
{
    uint32_t    t32;

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
        uint8_t         buf[2],
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
        uint8_t	        buf[8]
        )
{
    uint32_t	t32;

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
        uint8_t	        buf[2]
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
 * Function:	BWLSetTimeStampError
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
void
BWLSetTimeStampError(
        BWLTimeStamp	*tstamp,
        BWLNum64	val
        )
{
    BWLNum64	err;
    /*
     * Just in the unlikely event that val is represented
     * by a type larger than 64 bits...
     * (This ensures that scale will not overflow the
     * 6 bits available to it.)
     */
    err = val & (uint64_t)0xFFFFFFFFFFFFFFFFULL;

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

    return;
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
    uint8_t	scale;

    if(!tstamp)
        return 0;

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
        uint32_t	*errest,	/* usec's */
        uint32_t	*last_errest
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
            BWLSetTimeStampError(tstamp,BWLUsecToNum64(*errest));
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
