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
**	File:		protocol.c
**
**	Author:		Jeff W. Boote
**
**	Date:		Tue Sep 16 14:26:45 MDT 2003
**
**	Description:	This file contains the private functions that
**			speak the bwlib protocol directly.
**			(i.e. read and write the data and save it
**			to structures for the rest of the api to deal
**			with.)
**
**			The idea is to basically keep all network ordering
**			architecture dependant things in this file. And
**			hopefully to minimize the impact of any changes
**			to the actual protocol message formats.
**
**			The message templates are here for convienent
**			reference for byte offsets in the code - for
**			explainations of the fields please see the
**			relevant specification document.
**			(currently draft-ietf-ippm-owdp-03.txt)
**
**			(ease of referenceing byte offsets is also why
**			the &buf[BYTE] notation is being used.)
*/

#include <I2util/util.h>

#include <bwlibP.h>

/*
 * 	ServerGreeting message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                                                               |
 *	04|                      Unused (12 octets)                       |
 *	08|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	12|                            Modes                              |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                     Challenge (16 octets)                     |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *        Note: The last byte of 'Modes' is set to 
 *        BWL_MODE_TESTER_NEGOTIATION_VERSION.
 */
BWLErrSeverity
_BWLWriteServerGreeting(
	BWLControl	cntrl,
	uint32_t	avail_modes,
	uint8_t	*challenge,	/* [16] */
	int		*retn_on_err
	)
{
	/*
	 * buf_aligned it to ensure uint32_t alignment, but I use
	 * buf for actuall assignments to make the array offsets agree with
	 * the byte offsets shown above.
	 */
	uint8_t	*buf = (uint8_t*)cntrl->msg;

	if(!_BWLStateIsInitial(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLWriteServerGreeting:called in wrong state.");
		return BWLErrFATAL;
	}

	/*
	 * Set unused bits to 0.
	 */
	memset(buf,0,12);

	*((uint32_t *)&buf[12]) = htonl(avail_modes | 
					BWL_MODE_TESTER_NEGOTIATION_VERSION);
	memcpy(&buf[16],challenge,16);
	if(I2Writeni(cntrl->sockfd,buf,32,retn_on_err) != 32){
		return BWLErrFATAL;
	}

	cntrl->state = _BWLStateSetup;

	return BWLErrOK;
}

BWLErrSeverity
_BWLReadServerGreeting(
	BWLControl	cntrl,
	uint32_t	*mode,		/* modes available - returned	*/
	uint8_t	*challenge	/* [16] : challenge - returned	*/
)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	int		intr = 0;
	int		*retn_on_intr = &intr;

	if(cntrl->retn_on_intr){
		retn_on_intr = cntrl->retn_on_intr;
	}

	if(!_BWLStateIsInitial(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadServerGreeting:called in wrong state.");
		return BWLErrFATAL;
	}

	if(I2Readni(cntrl->sockfd,buf,32,retn_on_intr) != 32){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"Read failed:(%s)",strerror(errno));
		return (int)BWLErrFATAL;
	}

	*mode = ntohl(*((uint32_t *)&buf[12]));
	/*
	 * Get tester negotiation byte and clear it for subsequent
	 * operations on the mode field.
	 */
	cntrl->tester_negotiation_version = 
		*mode & BWL_MODE_TESTER_NEGOTIATION_MASK;
	*mode &= ~BWL_MODE_TESTER_NEGOTIATION_MASK;

	memcpy(challenge,&buf[16],16);

	cntrl->state = _BWLStateSetup;

	return BWLErrOK;
}

/*
 *
 *
 * 	ClientGreeting message format:
 *
 * 	size: 68 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                             Mode                              |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                                                               |
 *	08|                     Username (16 octets)                      |
 *	12|                                                               |
 *	16|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	20|                                                               |
 *	24|                       Token (32 octets)                       |
 *	28|                                                               |
 *	32|                                                               |
 *	36|                                                               |
 *	40|                                                               |
 *	44|                                                               |
 *	48|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	52|                                                               |
 *	56|                     Client-IV (16 octets)                     |
 *	60|                                                               |
 *	64|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *        Note: The last byte of 'Mode' is set to 
 *        cntrl->tester_negotiation_version, which is the
 *        BWL_MODE_TESTER_NEGOTIATION_VERSION from the server.
 */
BWLErrSeverity
_BWLWriteClientGreeting(
	BWLControl	cntrl,
	uint8_t	*token	/* [32]	*/
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	int		intr=0;
	int		*retn_on_intr = &intr;

	if(cntrl->retn_on_intr){
		retn_on_intr = cntrl->retn_on_intr;
	}

	if(!_BWLStateIsSetup(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLWriteClientGreeting:called in wrong state.");
		return BWLErrFATAL;
	}

	*(uint32_t *)&buf[0] = htonl(cntrl->mode | 
				     cntrl->tester_negotiation_version);

	if(cntrl->mode & BWL_MODE_DOCIPHER){
		memcpy(&buf[4],cntrl->userid,16);
		memcpy(&buf[20],token,32);
		memcpy(&buf[52],cntrl->writeIV,16);
	}else{
		memset(&buf[4],0,64);
	}

	if(I2Writeni(cntrl->sockfd, buf, 68,retn_on_intr) != 68)
		return BWLErrFATAL;

	return BWLErrOK;
}

BWLErrSeverity
_BWLReadClientGreeting(
	BWLControl	cntrl,
	uint32_t	*mode,
	uint8_t	*token,		/* [32] - return	*/
	uint8_t	*clientIV,	/* [16] - return	*/
	int		*retn_on_intr
	)
{
	ssize_t		len;
	uint8_t	*buf = (uint8_t*)cntrl->msg;

	if(!_BWLStateIsSetup(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadClientGreeting: called in wrong state.");
		return BWLErrFATAL;
	}

	if((len = I2Readni(cntrl->sockfd,buf,68,retn_on_intr)) != 68){
		if((len < 0) && *retn_on_intr && (errno == EINTR)){
			return BWLErrFATAL;
		}
		/*
		 * if len == 0 - this is just a socket close, no error
		 * should be printed.
		 */
		if(len != 0){
			BWLError(cntrl->ctx,BWLErrFATAL,errno,"I2Readni(): %M");
		}
		return BWLErrFATAL;
	}

	*mode = ntohl(*(uint32_t *)&buf[0]);
	/*
	 * Get tester negotiation byte and clear it for subsequent
	 * operations on the mode field.
	 */
	cntrl->tester_negotiation_version = 
		*mode & BWL_MODE_TESTER_NEGOTIATION_MASK;
	*mode &= ~BWL_MODE_TESTER_NEGOTIATION_MASK;

	memcpy(cntrl->userid_buffer,&buf[4],16);
	memcpy(token,&buf[20],32);
	memcpy(clientIV,&buf[52],16);

	return BWLErrOK;
}

static BWLAcceptType
GetAcceptType(
	BWLControl	cntrl,
	uint8_t	val
	)
{
	switch(val){
		case BWL_CNTRL_ACCEPT:
			return BWL_CNTRL_ACCEPT;
		case BWL_CNTRL_REJECT:
			return BWL_CNTRL_REJECT;
		case BWL_CNTRL_FAILURE:
			return BWL_CNTRL_FAILURE;
		case BWL_CNTRL_UNSUPPORTED:
			return BWL_CNTRL_UNSUPPORTED;
		default:
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
					"GetAcceptType:Invalid val %u",val);
			return BWL_CNTRL_INVALID;
	}
}

/*
 * 	ServerOK message format:
 *
 * 	size: 48 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                Tester availability bit-mask                   |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                      Unused (11 octets)                       |
 *	08|                                                               |
 *	  +                                               +-+-+-+-+-+-+-+-+
 *	12|                                               |   Accept      |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                     Server-IV (16 octets)                     |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	32|                      Uptime (Timestamp)                       |
 *	36|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	40|              Integrity Zero Padding (8 octets)                |
 *	44|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
BWLErrSeverity
_BWLWriteServerOK(
	BWLControl      	cntrl,
	BWLAcceptType   	code,
	BWLNum64        	uptime,
	BWLTesterAvailability	avail_testers,
	int		*retn_on_intr
	)
{
	ssize_t		len;
	BWLTimeStamp	tstamp;
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	int		ival=0;
	int		*intr=&ival;

	if(!_BWLStateIsSetup(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLWriteServerOK:called in wrong state.");
		return BWLErrFATAL;
	}

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/* Available testers bit-mask. */
	*(uint32_t*)&buf[0] = htonl(avail_testers);
	/* 11 unused bytes */
	memset(&buf[4],0,11);
	*(uint8_t *)&buf[15] = code & 0xff;
	memcpy(&buf[16],cntrl->writeIV,16);
	if((len = I2Writeni(cntrl->sockfd,buf,32,intr)) != 32){
		if((len < 0) && *intr && (errno == EINTR)){
			return BWLErrFATAL;
		}
		return BWLErrFATAL;
	}

	if(code == BWL_CNTRL_ACCEPT){
		/*
		 * Uptime should be encrypted if encr/auth mode so use Block
		 * func.
		 */
		tstamp.tstamp = uptime;
		_BWLEncodeTimeStamp(&buf[0],&tstamp);
		memset(&buf[8],0,8);
		if(_BWLSendBlocksIntr(cntrl,buf,1,intr) != 1){
			if((len < 0) && *intr && (errno == EINTR)){
				return BWLErrFATAL;
			}
			return BWLErrFATAL;
		}
		cntrl->state = _BWLStateRequest;
	}
	else{
		cntrl->state = _BWLStateInvalid;
		memset(&buf[0],0,16);
		if((len = I2Writeni(cntrl->sockfd,buf,16,intr)) != 16){
			if((len < 0) && *intr && (errno == EINTR)){
				return BWLErrFATAL;
			}
			return BWLErrFATAL;
		}
	}

	return BWLErrOK;
}

BWLErrSeverity
_BWLReadServerOK(
	BWLControl	        cntrl,
	BWLAcceptType	        *acceptval,	/* ret	*/
	BWLTesterAvailability	*avail_testers 	/* ret	*/
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;

	if(!_BWLStateIsSetup(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadServerOK:called in wrong state.");
		return BWLErrFATAL;
	}

	if(I2Readn(cntrl->sockfd,buf,32) != 32){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"Read failed:(%s)",strerror(errno));
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	*acceptval = GetAcceptType(cntrl,buf[15]);
	if(*acceptval == BWL_CNTRL_INVALID){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	if(avail_testers){
		*avail_testers = ntohl(*(uint32_t *)&buf[0]);
	}

	memcpy(cntrl->readIV,&buf[16],16);

	cntrl->state = _BWLStateUptime;

	return BWLErrOK;
}

BWLErrSeverity
_BWLReadServerUptime(
	BWLControl	cntrl,
	BWLNum64	*uptime	/* ret	*/
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	BWLTimeStamp	tstamp;

	if(!_BWLStateIs(_BWLStateUptime,cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadServerUptime: called in wrong state.");
		return BWLErrFATAL;
	}

	if(_BWLReceiveBlocks(cntrl,buf,1) != 1){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
			"_BWLReadServerUptime: Unable to read from socket.");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	if(memcmp(&buf[8],cntrl->zero,8)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadServerUptime: Invalid zero padding");
		return BWLErrFATAL;
	}

	_BWLDecodeTimeStamp(&tstamp,&buf[0]);
	*uptime = tstamp.tstamp;

	cntrl->state = _BWLStateRequest;

	return BWLErrOK;
}

/*
 * This function is called on the server side to read the first block
 * of client requests. The remaining read request messages MUST be called
 * next!.
 * It is also called by the client side from BWLStopSessionWait and
 * BWLStopSession
 */
BWLRequestType
BWLReadRequestType(
	BWLControl	cntrl,
	int		*retn_on_intr
	)
{
	uint8_t	msgtype;
	int		n;
	int		ival=0;
	int		*intr = &ival;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if(!_BWLStateIsRequest(cntrl) || _BWLStateIsReading(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLReadRequestType: called in wrong state.");
		return BWLReqInvalid;
	}

	/* Read one block so we can peek at the message type */
	n = _BWLReceiveBlocksIntr(cntrl,(uint8_t*)cntrl->msg,1,intr);
	if(n != 1){
		cntrl->state = _BWLStateInvalid;
		if((n < 0) && *intr && (errno == EINTR)){
			return BWLReqInvalid;
		}
		return BWLReqSockClose;
	}

	msgtype = *(uint8_t*)cntrl->msg;

	/*
	 * StopSession(3) message is only allowed during active tests,
	 * and it is the only message allowed during active tests.
	 */
	if((_BWLStateIs(_BWLStateTest,cntrl) && (msgtype != 3)) ||
			(!_BWLStateIs(_BWLStateTest,cntrl) && (msgtype == 3))){
		cntrl->state = _BWLStateInvalid;
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"BWLReadRequestType: Invalid request.");
		return BWLReqInvalid;
	}

	switch(msgtype){
		/*
		 * TestRequest
		 */
		case	1:
			cntrl->state |= _BWLStateTestRequest;
			break;
		case	2:
			cntrl->state |= _BWLStateStartSession;
			break;
		case	3:
			cntrl->state |= _BWLStateStopSession;
			break;
		case	4:
			cntrl->state |= _BWLStateTimeRequest;
			break;
		default:
			cntrl->state = _BWLStateInvalid;
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLReadRequestType: Unknown msg:%d",msgtype);
			return BWLReqInvalid;
	}

	return (BWLRequestType)msgtype;
}

/*
 * 	TimeRequest message format:
 *
 * 	size:32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|      4        |                                               |
 *	  +-+-+-+-+-+-+-+-+                                               |
 *	04|                        Unused                                 |
 *	08|                                                               |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *      20|                Integrity Zero Padding (16 octets)             |
 *      24|                                                               |
 *      28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
BWLErrSeverity
_BWLWriteTimeRequest(
	BWLControl	cntrl
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;

	if(!_BWLStateIsRequest(cntrl) || _BWLStateIsPending(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLWriteTimeRequest: called in wrong state.");
		return BWLErrFATAL;
	}

	buf[0] = 4;	/* Request-Time message # */
	memset(&buf[1],0,31);

	if(_BWLSendBlocks(cntrl,buf,2) != 2){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	cntrl->state |= _BWLStateTimeResponse;

	return BWLErrOK;
}

BWLErrSeverity
_BWLReadTimeRequest(
	BWLControl	cntrl,
	int		*retn_on_intr
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	int		ival=0;
	int		*intr=&ival;

	if(!_BWLStateIs(_BWLStateTimeRequest,cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadTimeRequest: called in wrong state.");
		return BWLErrFATAL;
	}

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_BWLReceiveBlocksIntr(cntrl,&buf[16],1,intr) != 1){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
		"_BWLReadTimeRequest: Unable to read from socket.");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	/*
	 * Check integrity bits.
	 */
	if(memcmp(cntrl->zero,&buf[16],16) != 0){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadTimeRequest: Invalid MBZ bits");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	cntrl->state &= ~_BWLStateTimeRequest;
	cntrl->state |= _BWLStateTimeResponse;

	return BWLErrOK;
}

/*
 * 	TimeResponse message format:
 *
 * 	size:32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                          Timestamp                            |
 *	04|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|        Error Estimate         |                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *	12|                            UNUSED                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *      20|                Integrity Zero Padding (16 octets)             |
 *      24|                                                               |
 *      28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
BWLErrSeverity
_BWLWriteTimeResponse(
	BWLControl	cntrl,
	BWLTimeStamp	*tstamp,
	int		*ret_on_intr
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	int		ival=0;
	int		*intr=&ival;

	if(!_BWLStateIs(_BWLStateTimeResponse,cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLWriteTimeResponse: called in wrong state.");
		return BWLErrFATAL;
	}

	if(ret_on_intr)
		intr = ret_on_intr;

	/*
	 * zero everything
	 */
	memset(&buf[0],0,32);

	/*
	 * Encode time and time  error estimate
	 */
	_BWLEncodeTimeStamp(&buf[0],tstamp);
	if(!_BWLEncodeTimeStampErrEstimate(&buf[8],tstamp)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
						"Invalid Timestamp Error");
		return BWLErrFATAL;
	}

	/*
	 * Send the TimeResponse message
	 */
	if(_BWLSendBlocksIntr(cntrl,buf,2,intr) != 2){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	cntrl->state &= ~_BWLStateTimeResponse;

	return BWLErrOK;
}
BWLErrSeverity
_BWLReadTimeResponse(
	BWLControl	cntrl,
	BWLTimeStamp	*tstamp
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;

	if(!_BWLStateIs(_BWLStateTimeResponse,cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadTimeResponse: called in wrong state.");
		return BWLErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_BWLReceiveBlocks(cntrl,&buf[0],2) != 2){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
			"_BWLReadTimeResponse: Unable to read from socket.");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	/*
	 * Check integrity bits.
	 */
	if(memcmp(cntrl->zero,&buf[16],16) != 0){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadTimeRequest: Invalid MBZ bits");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	/*
	 * Decode time and time error estimate
	 */
	_BWLDecodeTimeStamp(tstamp,&buf[0]);
	if(!_BWLDecodeTimeStampErrEstimate(tstamp,&buf[8])){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	cntrl->state &= ~_BWLStateTimeResponse;

	return BWLErrOK;
}

/*
 * 	TestRequest message format:
 *
 * 	size:112(+16) octets (+16 octets added if tester negotiation supported)
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|      1        |  UDP  | IPVN  | Conf-Sender   | Conf-Receiver |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                            Duration                           |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                            Req Time                           |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                          Latest Time                          |
 *	20|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	24|        Time Error Estimate    |         Recv Port             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	28|                        Sender Address                         |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	32|              Sender Address (cont.) or Unused                 |
 *	36|                                                               |
 *	40|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	44|                        Receiver Address                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	48|              Receiver Address (cont.) or Unused               |
 *	52|                                                               |
 *	56|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	60|                                                               |
 *	64|                        SID (16 octets)                        |
 *	68|                                                               |
 *	72|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	76|                          Bandwidth                            |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	80|                          Buffer Length                        |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	84|                          Window Size                          |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	88|                        Report Interval                        |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	92|    Dynamic    |      TOS      |   nParallel   |      MBZ      |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	96|                   Tester selection bit-mask                   |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     100|                                                               |
 *     104|                            Unused                             |
 *     108|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     112|                                                               |
 *     116|                Integrity Zero Padding (16 octets)             |
 *     120|                                                               |
 *     124|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *	  Dynamic is a bit mask.
 *	  BWL_DYNAMIC_WINSIZE = 0x1
 *	  If this bit is set, the "Window Size" parameter is only used if
 *	  the server can't determine a better dynamic one.
 *
 *        The block with 'Tester selection bit-mask' and 12 unused
 *        bytes is written only when the mode byte previously returned
 *        by the server indicates that the current tester negotiation
 *        version is supported (BWL_MODE_TESTER_NEGOTIATION_VERSION).
 */
BWLErrSeverity
_BWLWriteTestRequest(
	BWLControl	cntrl,
	BWLTestSession	tsession
)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	BWLTestSpec	*tspec = &tsession->test_spec;
	BWLTimeStamp	tstamp;
	BWLAddr		sender;
	BWLAddr		receiver;
	uint8_t		version;
	uint32_t	message_len;
	uint32_t	blocks;
	BWLBoolean	tester_negotiation;

	/*
	 * Ensure cntrl is in correct state.
	 */
	if(!_BWLStateIsRequest(cntrl) || _BWLStateIsPending(cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLWriteTestRequest:called in wrong state.");
		return BWLErrFATAL;
	}

	/*
	 * Interpret addresses
	 */
	sender = tspec->sender;
	receiver = tspec->receiver;

	if(sender->saddr->sa_family != receiver->saddr->sa_family){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
					"Address Family mismatch");
		return BWLErrFATAL;
	}

	/*
	 * Addresses are consistant. Can we deal with what we
	 * have been given? (We only support AF_INET and AF_INET6.)
	 */
	switch (sender->saddr->sa_family){
		case AF_INET:
			version = 4;
			break;
#ifdef	AF_INET6
		case AF_INET6:
			version = 6;
			break;
#endif
		default:
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid IP Address Family");
			return BWLErrFATAL;
	}

	/* Is there support for tester negotiation as in this version? */
	/* If so, the tester selection block will be written. */
	tester_negotiation = cntrl->tester_negotiation_version >=
		BWL_MODE_TESTER_NEGOTIATION_VERSION;
	if (tester_negotiation){
		message_len = 8*_BWL_RIJNDAEL_BLOCK_SIZE;
	}
	else { 
		message_len = 7*_BWL_RIJNDAEL_BLOCK_SIZE;
	}

	/*
	 * Initialize buffer
	 */
	memset(&buf[0],0,message_len);

	buf[0] = 1;	/* Request-Session message # */
	buf[1] = version & 0xF;	/* version */
	if(tspec->udp){	/* udp */
		buf[1] |= 0x10;
	}
	buf[2] = (tsession->conf_sender)?1:0;
	buf[3] = (tsession->conf_receiver)?1:0;

	/*
	 * slots and npackets... convert to network byte order.
	 */
	*(uint32_t*)&buf[4] = htonl(tspec->duration);
	_BWLEncodeTimeStamp(&buf[8],&tspec->req_time);
	tstamp.tstamp = tspec->latest_time;
	_BWLEncodeTimeStamp(&buf[16],&tstamp);
	if(!_BWLEncodeTimeStampErrEstimate(&buf[24],&tspec->req_time)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid req_time time errest");
		return BWLErrFATAL;
	}
	*(uint16_t*)&buf[26] = htons(tsession->recv_port);

	/*
	 * Now set addr values. (sockaddr vars will already have
	 * values in network byte order.)
	 */
	switch(version){
	struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
	struct sockaddr_in6	*saddr6;
		case 6:
			/* sender address */
			saddr6 = (struct sockaddr_in6*)sender->saddr;
			memcpy(&buf[28],saddr6->sin6_addr.s6_addr,16);

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver->saddr;
			memcpy(&buf[44],saddr6->sin6_addr.s6_addr,16);

			break;
#endif
		case 4:
			/* sender address */
			saddr4 = (struct sockaddr_in*)sender->saddr;
			*(uint32_t*)&buf[28] = saddr4->sin_addr.s_addr;

			/* receiver address */
			saddr4 = (struct sockaddr_in*)receiver->saddr;
			*(uint32_t*)&buf[44] = saddr4->sin_addr.s_addr;

			break;
		default:
			/*
			 * This can't happen, but default keeps compiler
			 * warnings away.
			 */
			abort();
			break;
	}

	memcpy(&buf[60],tsession->sid,16);
	*(uint32_t*)&buf[76] = htonl(tspec->bandwidth);
	*(uint32_t*)&buf[80] = htonl(tspec->len_buffer);
	*(uint32_t*)&buf[84] = htonl(tspec->window_size);
	*(uint32_t*)&buf[88] = htonl(tspec->report_interval);

	if(tspec->dynamic_window_size){
		buf[92] |= _BWL_DYNAMIC_WINDOW_SIZE;
	}

        if(tspec->tos){
            buf[93] = tspec->tos;
        }

	buf[94] = tspec->parallel_streams;

	if(tester_negotiation){
		*(uint32_t*)&buf[96] = htonl(tspec->tester);
	}
	/*
	 * Now - send the request! 112(+4) octets == 7(+1) blocks.
	 */
	blocks = message_len / _BWL_RIJNDAEL_BLOCK_SIZE;
	if(_BWLSendBlocks(cntrl,buf,blocks) != blocks){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	cntrl->state |= _BWLStateTestAccept;

	return BWLErrOK;
}

/*
 * Function:	_BWLReadTestRequest
 *
 * Description:	
 * 	This function reads a test request off the wire and encodes
 * 	the information in a TestSession record.
 *
 * 	The acceptval pointer will be non-null and will return a value.
 * 	(i.e. if there is a memory allocation error, it will be set to
 * 	BWL_CNTRL_FAILURE. If there is invalid data in the TestRequest
 * 	it will be set to BWL_CNTRL_REJECT.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLErrSeverity
_BWLReadTestRequest(
	BWLControl	cntrl,
	int		*retn_on_intr,
	BWLTestSession	*test_session,
	BWLAcceptType	*accept_ret
)
{
    uint8_t                 *buf = (uint8_t*)cntrl->msg;
    BWLTimeStamp            tstamp;
    BWLErrSeverity          err_ret=BWLErrFATAL;
    struct sockaddr_storage sendaddr_rec;
    struct sockaddr_storage recvaddr_rec;
    socklen_t               addrlen = sizeof(sendaddr_rec);
    BWLAddr                 SendAddr=NULL;
    BWLAddr                 RecvAddr=NULL;
    uint8_t                 ipvn;
    BWLSID                  sid;
    BWLTestSpec             tspec;
    BWLTestSession          tsession;
    int                     ival=0;
    int                     *intr=&ival;
    uint16_t                recv_port;
    BWLBoolean              conf_sender;
    BWLBoolean              conf_receiver;
    uint32_t                blocks=_BWL_TEST_REQUEST_BLK_LEN; /* 8 */
    uint32_t                padding_pos;
    BWLBoolean	tester_negotiation;

    if(!_BWLStateIs(_BWLStateTestRequest,cntrl)){
        BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                "_BWLReadTestRequest: called in wrong state.");
        return BWLErrFATAL;
    }

    memset(&sendaddr_rec,0,addrlen);
    memset(&recvaddr_rec,0,addrlen);
    memset(&tspec,0,sizeof(tspec));
    memset(sid,0,sizeof(sid));

    /*
     * Initialize BWLAcceptType
     */
    *accept_ret = BWL_CNTRL_INVALID;

    /*
     * If caller wants to participate in interrupts, use the passed in addr.
     */
    if(retn_on_intr){
        intr = retn_on_intr;
    }

    /*
     * Check if tester negotiation has been requested.
     */
    tester_negotiation =  cntrl->tester_negotiation_version >=
	    BWL_MODE_TESTER_NEGOTIATION_VERSION;
    if(!tester_negotiation){
	    blocks--;
    }
    padding_pos = (blocks -1) * _BWL_RIJNDAEL_BLOCK_SIZE;

    /*
     * Already read the first block - read the rest for this message
     * type.
     */
    if(_BWLReceiveBlocksIntr(cntrl,&buf[16],blocks-1,intr) != (blocks-1)){
        BWLError(cntrl->ctx,BWLErrFATAL,errno,
                "_BWLReadTestRequest: Unable to read from socket.");
        goto error;
    }

    if(memcmp(cntrl->zero,&buf[padding_pos],_BWL_RIJNDAEL_BLOCK_SIZE)){
        BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                "_BWLReadTestRequest: Invalid zero padding");
        goto error;
    }

    /*
     * Decode the parameters that are used for initial request AND
     * for reservation update.
     */
    _BWLDecodeTimeStamp(&tspec.req_time,&buf[8]);
    if(!_BWLDecodeTimeStampErrEstimate(&tspec.req_time,&buf[24])){
        BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                "_BWLReadTestRequest: Invalid time errest");
        goto error;
    }
    _BWLDecodeTimeStamp(&tstamp,&buf[16]);
    tspec.latest_time = tstamp.tstamp;
    recv_port = ntohs(*(uint16_t*)&buf[26]);

    /*
     * copy sid (will be ignored if this is an initial receive request)
     */
    memcpy(sid,&buf[60],16);

    if(*test_session){
        tsession = *test_session;
        if(memcmp(sid,tsession->sid,16) != 0){
            BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "_BWLReadTestRequest: sid mismatch");
            goto error;
        }
        tsession->test_spec.req_time = tspec.req_time;
        tsession->test_spec.latest_time = tspec.latest_time;
        if(!tsession->conf_receiver){
            tsession->recv_port = recv_port;
        }
    }
    else{
        /*
         * If *test_session is NULL, than there are currently no
         * outstanding reservations. Therefore, this is a new request
         * so decode it.
         */

        ipvn = buf[1] & 0xF;
        tspec.udp = (buf[1]>>4)?True:False;

        tspec.duration = ntohl(*(uint32_t*)&buf[4]);

        switch(buf[2]){
            case 0:
                conf_sender = False;
                break;
            case 1:
            default:
                conf_sender = True;
                break;
        }
        switch(buf[3]){
            case 0:
                conf_receiver = False;
                break;
            case 1:
            default:
                conf_receiver = True;
                break;
        }

        if(conf_sender == conf_receiver){
            BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "_BWLReadTestRequest: Invalid req(send/recv?)");
            goto error;
        }

        if(conf_receiver){
            recv_port = 0;
        }

        switch(ipvn){
            struct sockaddr_in    *saddr4;
#ifdef    AF_INET6
            struct sockaddr_in6    *saddr6;
            case 6:
            if(addrlen < (socklen_t)sizeof(struct sockaddr_in6)){
                BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                        "_BWLReadTestRequest: socklen not large enough (%d < %d)",
                        addrlen,
                        sizeof(struct sockaddr_in6));
                goto error;
            }
            addrlen = sizeof(struct sockaddr_in6);

            /* sender address and port */
            saddr6 = (struct sockaddr_in6*)&sendaddr_rec;
            saddr6->sin6_family = AF_INET6;
            memcpy(saddr6->sin6_addr.s6_addr,&buf[28],16);
            saddr6->sin6_port = 0;

            /* receiver address and port  */
            saddr6 = (struct sockaddr_in6*)&recvaddr_rec;
            saddr6->sin6_family = AF_INET6;
            memcpy(saddr6->sin6_addr.s6_addr,&buf[44],16);
            saddr6->sin6_port = 0;

            break;
#endif
            case 4:
            if(addrlen < (socklen_t)sizeof(struct sockaddr_in)){
                BWLError(cntrl->ctx,BWLErrFATAL,
                        BWLErrINVALID,
                        "_BWLReadTestRequest: socklen not large enough (%d < %d)",
                        addrlen,
                        sizeof(struct sockaddr_in));
                goto error;
            }
            addrlen = sizeof(struct sockaddr_in);

            /* sender address and port  */
            saddr4 = (struct sockaddr_in*)&sendaddr_rec;
            saddr4->sin_family = AF_INET;
            saddr4->sin_addr.s_addr = *(uint32_t*)&buf[28];
            saddr4->sin_port = 0;

            /* receiver address and port  */
            saddr4 = (struct sockaddr_in*)&recvaddr_rec;
            saddr4->sin_family = AF_INET;
            saddr4->sin_addr.s_addr = *(uint32_t*)&buf[44];
            saddr4->sin_port = 0;

            break;
            default:
            BWLError(cntrl->ctx,BWLErrWARNING,BWLErrINVALID,
                    "_BWLReadTestRequest: Unsupported IP version (%d)",
                    ipvn);
            goto error;
        }

#ifdef    HAVE_STRUCT_SOCKADDR_SA_LEN
        ((struct sockaddr *)&sendaddr_rec)->sa_len =
            ((struct sockaddr *)&recvaddr_rec)->sa_len = addrlen;
#endif
        /*
         * Prepare the address buffers.
         * (Don't bother checking for null return - it will be checked
         * by _BWLTestSessionAlloc.)
         */
        SendAddr = BWLAddrBySAddr(cntrl->ctx,
                (struct sockaddr*)&sendaddr_rec,addrlen,
                (tspec.udp)?SOCK_DGRAM:SOCK_STREAM);
        RecvAddr = BWLAddrBySAddr(cntrl->ctx,
                (struct sockaddr*)&recvaddr_rec,addrlen,
                (tspec.udp)?SOCK_DGRAM:SOCK_STREAM);

        tspec.bandwidth = ntohl(*(uint32_t*)&buf[76]);
        tspec.len_buffer = ntohl(*(uint32_t*)&buf[80]);
        tspec.window_size = ntohl(*(uint32_t*)&buf[84]);
        tspec.report_interval = ntohl(*(uint32_t*)&buf[88]);

        tspec.dynamic_window_size = buf[92] & _BWL_DYNAMIC_WINDOW_SIZE;
        tspec.tos = buf[93];

	tspec.parallel_streams = buf[94];

	if(tester_negotiation){
		tspec.tester = ntohl(*(uint32_t*)&buf[96]);
	}

        /*
         * Allocate a record for this test.
         */
        if( !(tsession = _BWLTestSessionAlloc(cntrl,conf_sender,
                        SendAddr,RecvAddr,recv_port,&tspec))){
            err_ret = BWLErrWARNING;
            *accept_ret = BWL_CNTRL_FAILURE;
            goto error;
        }

        /*
         * copy sid into tsession - if the sid still needs to be
         * generated - it still will be in sapi.c:BWLProcessTestRequest
         */
        memcpy(tsession->sid,&buf[60],16);
    }


    *test_session = tsession;
    *accept_ret = BWL_CNTRL_ACCEPT;

    cntrl->state &= ~_BWLStateTestRequest;
    cntrl->state |= _BWLStateTestAccept;

    return BWLErrOK;

error:
    if(tsession){
        _BWLTestSessionFree(tsession,BWL_CNTRL_FAILURE);
    }else{
        BWLAddrFree(SendAddr);
        BWLAddrFree(RecvAddr);
    }

    if(err_ret < BWLErrWARNING){
        cntrl->state = _BWLStateInvalid;
    }

    return err_ret;
}

/*
 *
 * 	TestAccept message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|    Accept     |  Unused       |            Port               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                                                               |
 *	08|                        SID (16 octets)                        |
 *	12|                                                               |
 *	16|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	20|                       Reservation Time                        |
 *	24|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	28|                      Zero Padding (4 octets)                  |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
BWLErrSeverity
_BWLWriteTestAccept(
	BWLControl	cntrl,
	int		*intr,
	BWLAcceptType	acceptval,
	BWLTestSession	tsession
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	BWLTimeStamp	tstamp;

	if(!_BWLStateIs(_BWLStateTestAccept,cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLWriteTestAccept called in wrong state.");
		return BWLErrFATAL;
	}

	memset(buf,0,32);

	buf[0] = acceptval & 0xff;
	if(tsession->conf_receiver){
		*(uint16_t *)&buf[2] = htons(tsession->recv_port);
	}
	memcpy(&buf[4],tsession->sid,16);
	tstamp.tstamp = tsession->reserve_time;
	_BWLEncodeTimeStamp(&buf[20],&tstamp);

	if(_BWLSendBlocksIntr(cntrl,buf,2,intr) != 2){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	cntrl->state &= ~_BWLStateTestAccept;

	return BWLErrOK;
}

BWLErrSeverity
_BWLReadTestAccept(
	BWLControl	cntrl,
	BWLAcceptType	*acceptval,
	BWLTestSession	tsession
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	BWLTimeStamp	tstamp;

	if(!_BWLStateIs(_BWLStateTestAccept,cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLReadTestAccept called in wrong state.");
		return BWLErrFATAL;
	}

	/*
	 * Get the servers response.
	 */
	if(_BWLReceiveBlocks(cntrl,buf,2) != 2){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
			"_BWLReadTestAccept:Unable to read from socket.");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	/*
	 * Check zero padding first.
	 */
	if(memcmp(&buf[28],cntrl->zero,4)){
		cntrl->state = _BWLStateInvalid;
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"Invalid Accept-Session message received");
		return BWLErrFATAL;
	}

	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == BWL_CNTRL_INVALID){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	if(tsession->conf_receiver){
		tsession->recv_port = ntohs(*(uint16_t*)&buf[2]);
		memcpy(tsession->sid,&buf[4],16);
	}

	_BWLDecodeTimeStamp(&tstamp,&buf[20]);
	tsession->reserve_time = tstamp.tstamp;

	cntrl->state &= ~_BWLStateTestAccept;

	return BWLErrOK;
}

/*
 *
 * 	StartSession message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|      2        |    Unused     |            DataPort           |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                      Unused (12 octets)                       |
 *	08|                                                               |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                    Zero Padding (16 octets)                   |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
BWLErrSeverity
_BWLWriteStartSession(
	BWLControl	cntrl,
	uint16_t	dataport
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;

	if(!_BWLStateIsRequest(cntrl) || _BWLStateIsPending(cntrl) ||
			!cntrl->tests){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLWriteStartSession: called in wrong state.");
		return BWLErrFATAL;
	}

	/* initialize buffer */
	memset(&buf[0],0,32);

	buf[0] = 2;	/* start-session identifier	*/
	/*
	 * If conf_sender, than need to "set" the dataport.
	 */
	if(cntrl->tests->conf_sender){
		*(uint16_t*)&buf[2] = htons(dataport);
	}

	if(_BWLSendBlocks(cntrl,buf,2) != 2){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	cntrl->state |= _BWLStateStartAck;
	cntrl->state |= _BWLStateTest;
	return BWLErrOK;
}

BWLErrSeverity
_BWLReadStartSession(
	BWLControl	cntrl,
	uint16_t	*dataport,
	int		*retn_on_intr
)
{
	int		n;
	uint8_t	*buf = (uint8_t*)cntrl->msg;

	if(!_BWLStateIs(_BWLStateStartSession,cntrl) || !cntrl->tests){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLReadStartSession called in wrong state.");
		return BWLErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	n = _BWLReceiveBlocksIntr(cntrl,&buf[16],
			_BWL_STOP_SESSIONS_BLK_LEN-1,retn_on_intr);

	if((n < 0) && *retn_on_intr && (errno == EINTR)){
		return BWLErrFATAL;
	}

	if(n != (_BWL_STOP_SESSIONS_BLK_LEN-1)){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
			"_BWLReadStartSession: Unable to read from socket.");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLReadTestRequest: Invalid zero padding");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	if(buf[0] != 2){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"_BWLReadStartSession: Not a StartSession message...");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	if(cntrl->tests->conf_sender){
		*dataport = ntohs(*(uint16_t*)&buf[2]);
	}
	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_BWLStateStartSession;
	cntrl->state |= _BWLStateStartAck;
	cntrl->state |= _BWLStateTest;

	return BWLErrOK;
}

/*
 *
 * 	StartAck message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|     Accept    |    Unused     |            DataPort           |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                      Unused (12 octets)                       |
 *	08|                                                               |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                    Zero Padding (16 octets)                   |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
BWLErrSeverity
_BWLWriteStartAck(
	BWLControl	cntrl,
	int		*retn_on_intr,
	uint16_t	dataport,
	BWLAcceptType	acceptval
	)
{
	int		n;
	uint8_t	*buf = (uint8_t*)cntrl->msg;

	if(!_BWLStateIs(_BWLStateStartAck,cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLWriteStartAck called in wrong state.");
		return BWLErrFATAL;
	}

	memset(&buf[0],0,32);

	buf[0] = acceptval & 0xff;

	if(cntrl->tests->conf_receiver){
		*(uint16_t*)&buf[2] = htons(dataport);
	}

	n = _BWLSendBlocksIntr(cntrl,buf,_BWL_CONTROL_ACK_BLK_LEN,retn_on_intr);

	if((n < 0) && *retn_on_intr && (errno == EINTR)){
		return BWLErrFATAL;
	}

	if(n != _BWL_CONTROL_ACK_BLK_LEN){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	/*
	 * StartAck has been sent, leave that state.
	 */
	cntrl->state &= ~_BWLStateStartAck;

	/*
	 * Test was denied - go back to Request state.
	 */
	if(_BWLStateIs(_BWLStateTest,cntrl) && (acceptval != BWL_CNTRL_ACCEPT)){
		cntrl->state &= ~_BWLStateTest;
	}

	return BWLErrOK;
}

BWLErrSeverity
_BWLReadStartAck(
	BWLControl	cntrl,
	uint16_t	*dataport,
	BWLAcceptType	*acceptval
)
{
	uint8_t		*buf = (uint8_t*)cntrl->msg;

	*acceptval = BWL_CNTRL_INVALID;

	if(!_BWLStateIs(_BWLStateStartAck,cntrl)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLReadStartAck called in wrong state.");
		return BWLErrFATAL;
	}

	if(_BWLReceiveBlocks(cntrl,&buf[0],_BWL_CONTROL_ACK_BLK_LEN) != 
					(_BWL_CONTROL_ACK_BLK_LEN)){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
			"_BWLReadStartAck: Unable to read from socket.");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLReadStartAck: Invalid zero padding");
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}
	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == BWL_CNTRL_INVALID){
		cntrl->state = _BWLStateInvalid;
		return BWLErrFATAL;
	}

	if(cntrl->tests->conf_receiver){
		*dataport = ntohs(*(uint16_t*)&buf[2]);
	}

	/*
	 * received StartAck - leave that state.
	 */
	cntrl->state &= ~_BWLStateStartAck;

	/* If StartSession was rejected get back into StateRequest */
	if (_BWLStateIsTest(cntrl) && (*acceptval != BWL_CNTRL_ACCEPT)){
		cntrl->state &= ~_BWLStateTest;
		cntrl->state |= _BWLStateRequest;
	}


	return BWLErrOK;
}

/*
 *
 * 	StopSession message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|      3        |    Accept     |                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *	04|                       Unused (6 octets)                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                       N-bytes following                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	12|                       Unused (4 octets)                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                    Zero Padding (16 octets)                   |
 *	24|                                                               |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The following is appended ONLY if (N-bytes != 0)
 *
 *	  ... ASCII TEST RESULTS ... (last block is zero padded)
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                                                               |
 *	04|                    Zero Padding (16 octets)                   |
 *	08|                                                               |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
BWLErrSeverity
_BWLWriteStopSession(
	BWLControl	cntrl,
	int		*retn_on_intr,
	BWLAcceptType	acceptval,
	FILE		*fp
	)
{
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	struct stat	sbuf;
	uint32_t	fsize = 0;

	if(!( _BWLStateIs(_BWLStateRequest,cntrl) &&
				_BWLStateIs(_BWLStateTest,cntrl))){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLWriteStopSession called in wrong state.");
		return BWLErrFATAL;
	}

	memset(&buf[0],0,32);

	buf[0] = 3;
	if(fp){
		/*
		 * Find out how much data we need to send.
		 */
		if(fstat(fileno(fp),&sbuf) || fseeko(fp,0,SEEK_SET)){
			acceptval = BWL_CNTRL_FAILURE;
			goto datadone;
		}
		fsize = sbuf.st_size;

		/*
		 * check for overflow.
		 */
		if(sbuf.st_size != (off_t)fsize){
			fsize = 0;
			BWLError(cntrl->ctx,BWLErrWARNING,BWLErrUNKNOWN,
				"_BWLWriteStopSession: Invalid data file");
			acceptval = BWL_CNTRL_FAILURE;
			goto datadone;
		}

		*(uint32_t*)&buf[8] = htonl(fsize);
	}

datadone:
	buf[1] = acceptval & 0xff;

	if(_BWLSendBlocksIntr(cntrl,buf,2,retn_on_intr) != 2){
		return BWLErrFATAL;
	}

	if(!fsize){
		return BWLErrOK;
	}

	/*
	 * Send data with trailing zero block
	 */

	while(fsize >= _BWL_RIJNDAEL_BLOCK_SIZE){
		if(fread(buf,1,_BWL_RIJNDAEL_BLOCK_SIZE,fp) !=
						_BWL_RIJNDAEL_BLOCK_SIZE){
			return _BWLFailControlSession(cntrl,BWLErrFATAL);
		}
		if(_BWLSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
			return _BWLFailControlSession(cntrl,BWLErrFATAL);
		}
		fsize -= _BWL_RIJNDAEL_BLOCK_SIZE;
	}

	if(fsize > 0){
		memset(buf,0,_BWL_RIJNDAEL_BLOCK_SIZE);
		if(fread(buf,1,fsize,fp) != fsize){
			return _BWLFailControlSession(cntrl,BWLErrFATAL);
		}
		if(_BWLSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
			return _BWLFailControlSession(cntrl,BWLErrFATAL);
		}
	}

	/*
	 * Send a final block of zero
	 */
	memset(buf,0,_BWL_RIJNDAEL_BLOCK_SIZE);
	if(_BWLSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}

	return BWLErrOK;
}

BWLErrSeverity
_BWLReadStopSession(
	BWLControl	cntrl,
	int		*retn_on_intr,
	BWLAcceptType	*acceptval,
	FILE		*fp
)
{
	int		n;
	uint8_t	*buf = (uint8_t*)cntrl->msg;
	BWLAcceptType	aval;
	uint32_t	fsize;

	if(!(_BWLStateIs(_BWLStateRequest,cntrl) &&
					_BWLStateIs(_BWLStateTest,cntrl))){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLReadStopSession called in wrong state.");
		return BWLErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if((n = _BWLReceiveBlocksIntr(cntrl,&buf[16],1,retn_on_intr)) != 1){
		if((n < 0) && *retn_on_intr && (errno == EINTR)){
			return BWLErrFATAL;
		}
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
			"_BWLReadStopSession: Unable to read from socket.");
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLReadStopSession: Invalid zero padding");
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}
	aval = GetAcceptType(cntrl,buf[1]);
	if(acceptval)
		*acceptval = aval;

	if(aval == BWL_CNTRL_INVALID){
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}

	fsize = ntohl(*(uint32_t*)&buf[8]);

	if(!fsize){
		goto end;
	}

	/*
	 * Read test results and write to fp, if not null.
	 */
	while(fsize >= _BWL_RIJNDAEL_BLOCK_SIZE){

		if(_BWLReceiveBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
			return _BWLFailControlSession(cntrl,BWLErrFATAL);
		}

		if(fp && (fwrite(buf,_BWL_RIJNDAEL_BLOCK_SIZE,1,fp) != 1)){
			return _BWLFailControlSession(cntrl,BWLErrFATAL);
		}

		fsize -= _BWL_RIJNDAEL_BLOCK_SIZE;
	}

	if(fsize > 0){

		if(_BWLReceiveBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
			return _BWLFailControlSession(cntrl,BWLErrFATAL);
		}

		if(fp && (fwrite(buf,fsize,1,fp) != 1)){
			return _BWLFailControlSession(cntrl,BWLErrFATAL);
		}
	}

	/*
	 * Integrity Zero block
	 */
	if(_BWLReceiveBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}

	if(memcmp(cntrl->zero,buf,16)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLReadStopSession: Invalid zero padding");
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}

end:
	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_BWLStateStopSession;
	cntrl->state |= _BWLStateRequest;

	return BWLErrOK;
}
