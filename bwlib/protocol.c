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
**			speak the ipcntrl protocol directly.
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

#include <ipcntrlP.h>

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
 */
IPFErrSeverity
_IPFWriteServerGreeting(
	IPFControl	cntrl,
	u_int32_t	avail_modes,
	u_int8_t	*challenge,	/* [16] */
	int		*retn_on_err
	)
{
	/*
	 * buf_aligned it to ensure u_int32_t alignment, but I use
	 * buf for actuall assignments to make the array offsets agree with
	 * the byte offsets shown above.
	 */
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIsInitial(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteServerGreeting:called in wrong state.");
		return IPFErrFATAL;
	}

	/*
	 * Set unused bits to 0.
	 */
	memset(buf,0,12);

	*((u_int32_t *)&buf[12]) = htonl(avail_modes);
	memcpy(&buf[16],challenge,16);
	if(I2Writeni(cntrl->sockfd,buf,32,retn_on_err) != 32){
		return IPFErrFATAL;
	}

	cntrl->state = _IPFStateSetup;

	return IPFErrOK;
}

IPFErrSeverity
_IPFReadServerGreeting(
	IPFControl	cntrl,
	u_int32_t	*mode,		/* modes available - returned	*/
	u_int8_t	*challenge	/* [16] : challenge - returned	*/
)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIsInitial(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadServerGreeting:called in wrong state.");
		return IPFErrFATAL;
	}

	if(I2Readn(cntrl->sockfd,buf,32) != 32){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"Read failed:(%s)",strerror(errno));
		return (int)IPFErrFATAL;
	}

	*mode = ntohl(*((u_int32_t *)&buf[12]));
	memcpy(challenge,&buf[16],16);

	cntrl->state = _IPFStateSetup;

	return IPFErrOK;
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
 */
IPFErrSeverity
_IPFWriteClientGreeting(
	IPFControl	cntrl,
	u_int8_t	*token	/* [32]	*/
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIsSetup(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteClientGreeting:called in wrong state.");
		return IPFErrFATAL;
	}

	*(u_int32_t *)&buf[0] = htonl(cntrl->mode);

	if(cntrl->mode & IPF_MODE_DOCIPHER){
		memcpy(&buf[4],cntrl->userid,16);
		memcpy(&buf[20],token,32);
		memcpy(&buf[52],cntrl->writeIV,16);
	}else{
		memset(&buf[4],0,64);
	}

	if(I2Writen(cntrl->sockfd, buf, 68) != 68)
		return IPFErrFATAL;

	return IPFErrOK;
}

IPFErrSeverity
_IPFReadClientGreeting(
	IPFControl	cntrl,
	u_int32_t	*mode,
	u_int8_t	*token,		/* [32] - return	*/
	u_int8_t	*clientIV,	/* [16] - return	*/
	int		*retn_on_intr
	)
{
	ssize_t		len;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIsSetup(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadClientGreeting: called in wrong state.");
		return IPFErrFATAL;
	}

	if((len = I2Readni(cntrl->sockfd,buf,68,retn_on_intr)) != 68){
		if((len < 0) && *retn_on_intr && (errno == EINTR)){
			return IPFErrFATAL;
		}
		/*
		 * if len == 0 - this is just a socket close, no error
		 * should be printed.
		 */
		if(len != 0){
			IPFError(cntrl->ctx,IPFErrFATAL,errno,"I2Readni(): %M");
		}
		return IPFErrFATAL;
	}

	*mode = ntohl(*(u_int32_t *)&buf[0]);
	memcpy(cntrl->userid_buffer,&buf[4],16);
	memcpy(token,&buf[20],32);
	memcpy(clientIV,&buf[52],16);

	return IPFErrOK;
}

static IPFAcceptType
GetAcceptType(
	IPFControl	cntrl,
	u_int8_t	val
	)
{
	switch(val){
		case IPF_CNTRL_ACCEPT:
			return IPF_CNTRL_ACCEPT;
		case IPF_CNTRL_REJECT:
			return IPF_CNTRL_REJECT;
		case IPF_CNTRL_FAILURE:
			return IPF_CNTRL_FAILURE;
		case IPF_CNTRL_UNSUPPORTED:
			return IPF_CNTRL_UNSUPPORTED;
		default:
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
					"GetAcceptType:Invalid val %u",val);
			return IPF_CNTRL_INVALID;
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
 *	00|                                                               |
 *	04|                      Unused (15 octets)                       |
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
IPFErrSeverity
_IPFWriteServerOK(
	IPFControl	cntrl,
	IPFAcceptType	code,
	IPFNum64	uptime,
	int		*retn_on_intr
	)
{
	ssize_t		len;
	IPFTimeStamp	tstamp;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	int		ival=0;
	int		*intr=&ival;

	if(!_IPFStateIsSetup(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteServerOK:called in wrong state.");
		return IPFErrFATAL;
	}

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	memset(&buf[0],0,15);
	*(u_int8_t *)&buf[15] = code & 0xff;
	memcpy(&buf[16],cntrl->writeIV,16);
	if((len = I2Writeni(cntrl->sockfd,buf,32,intr)) != 32){
		if((len < 0) && *intr && (errno == EINTR)){
			return IPFErrFATAL;
		}
		return IPFErrFATAL;
	}

	if(code == IPF_CNTRL_ACCEPT){
		/*
		 * Uptime should be encrypted if encr/auth mode so use Block
		 * func.
		 */
		tstamp.ipftime = uptime;
		_IPFEncodeTimeStamp(&buf[0],&tstamp);
		memset(&buf[8],0,8);
		if(_IPFSendBlocksIntr(cntrl,buf,1,intr) != 1){
			if((len < 0) && *intr && (errno == EINTR)){
				return IPFErrFATAL;
			}
			return IPFErrFATAL;
		}
		cntrl->state = _IPFStateRequest;
	}
	else{
		cntrl->state = _IPFStateInvalid;
		memset(&buf[0],0,16);
		if((len = I2Writeni(cntrl->sockfd,buf,16,intr)) != 16){
			if((len < 0) && *intr && (errno == EINTR)){
				return IPFErrFATAL;
			}
			return IPFErrFATAL;
		}
	}

	return IPFErrOK;
}

IPFErrSeverity
_IPFReadServerOK(
	IPFControl	cntrl,
	IPFAcceptType	*acceptval	/* ret	*/
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIsSetup(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadServerOK:called in wrong state.");
		return IPFErrFATAL;
	}

	if(I2Readn(cntrl->sockfd,buf,32) != 32){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"Read failed:(%s)",strerror(errno));
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	*acceptval = GetAcceptType(cntrl,buf[15]);
	if(*acceptval == IPF_CNTRL_INVALID){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	memcpy(cntrl->readIV,&buf[16],16);

	cntrl->state = _IPFStateUptime;

	return IPFErrOK;
}

IPFErrSeverity
_IPFReadServerUptime(
	IPFControl	cntrl,
	IPFNum64	*uptime	/* ret	*/
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	IPFTimeStamp	tstamp;

	if(!_IPFStateIs(_IPFStateUptime,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadServerUptime: called in wrong state.");
		return IPFErrFATAL;
	}

	if(_IPFReceiveBlocks(cntrl,buf,1) != 1){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"_IPFReadServerUptime: Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(memcmp(&buf[8],cntrl->zero,8)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadServerUptime: Invalid zero padding");
		return IPFErrFATAL;
	}

	_IPFDecodeTimeStamp(&tstamp,&buf[0]);
	*uptime = tstamp.ipftime;

	cntrl->state = _IPFStateRequest;

	return IPFErrOK;
}

/*
 * This function is called on the server side to read the first block
 * of client requests. The remaining read request messages MUST be called
 * next!.
 * It is also called by the client side from IPFStopSessionWait and
 * IPFStopSession
 */
IPFRequestType
IPFReadRequestType(
	IPFControl	cntrl,
	int		*retn_on_intr
	)
{
	u_int8_t	msgtype;
	int		n;
	int		ival=0;
	int		*intr = &ival;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if(!_IPFStateIsRequest(cntrl) || _IPFStateIsReading(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFReadRequestType:called in wrong state.");
		return IPFReqInvalid;
	}

	/* Read one block so we can peek at the message type */
	n = _IPFReceiveBlocksIntr(cntrl,(u_int8_t*)cntrl->msg,1,intr);
	if(n != 1){
		cntrl->state = _IPFStateInvalid;
		if((n < 0) && *intr && (errno == EINTR)){
			return IPFReqInvalid;
		}
		return IPFReqSockClose;
	}

	msgtype = *(u_int8_t*)cntrl->msg;

	/*
	 * StopSession(3) message is only allowed during active tests,
	 * and it is the only message allowed during active tests.
	 */
	if((_IPFStateIs(_IPFStateTest,cntrl) && (msgtype != 3)) ||
			(!_IPFStateIs(_IPFStateTest,cntrl) && (msgtype == 3))){
		cntrl->state = _IPFStateInvalid;
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"IPFReadRequestType: Invalid request.");
		return IPFReqInvalid;
	}

	switch(msgtype){
		/*
		 * TestRequest
		 */
		case	1:
			cntrl->state |= _IPFStateTestRequest;
			break;
		case	2:
			cntrl->state |= _IPFStateStartSession;
			break;
		case	3:
			cntrl->state |= _IPFStateStopSession;
			break;
		case	4:
			cntrl->state |= _IPFStateTimeRequest;
			break;
		default:
			cntrl->state = _IPFStateInvalid;
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFReadRequestType: Unknown msg:%d",msgtype);
			return IPFReqInvalid;
	}

	return (IPFRequestType)msgtype;
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
IPFErrSeverity
_IPFWriteTimeRequest(
	IPFControl	cntrl
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIsRequest(cntrl) || _IPFStateIsPending(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFWriteTimeRequest: called in wrong state.");
		return IPFErrFATAL;
	}

	buf[0] = 4;	/* Request-Time message # */
	memset(&buf[1],0,31);

	if(_IPFSendBlocks(cntrl,buf,2) != 2){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	cntrl->state |= _IPFStateTimeResponse;

	return IPFErrOK;
}
IPFErrSeverity
_IPFReadTimeRequest(
	IPFControl	cntrl,
	int		*retn_on_intr
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	int		ival=0;
	int		*intr=&ival;

	if(!_IPFStateIs(_IPFStateTimeRequest,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTimeRequest: called in wrong state.");
		return IPFErrFATAL;
	}

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_IPFReceiveBlocksIntr(cntrl,&buf[16],1,intr) != 1){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
		"_IPFReadTimeRequest: Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * Check integrity bits.
	 */
	if(memcmp(cntrl->zero,&buf[16],16) != 0){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTimeRequest: Invalid MBZ bits");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	cntrl->state &= ~_IPFStateTimeRequest;
	cntrl->state |= _IPFStateTimeResponse;

	return IPFErrOK;
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
IPFErrSeverity
_IPFWriteTimeResponse(
	IPFControl	cntrl,
	IPFTimeStamp	*tstamp,
	int		*ret_on_intr
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	int		ival=0;
	int		*intr=&ival;

	if(!_IPFStateIs(cntrl,_IPFStateTimeResponse)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteTimeResponse: called in wrong state.");
		return IPFErrFATAL;
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
	_IPFEncodeTimeStamp(&buf[0],&tstamp);
	if(!_IPFEncodeTimeStampErrEstimate(&buf[8],&tstamp)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
						"Invalid Timestamp Error");
		return IPFErrFATAL;
	}

	/*
	 * Send the TimeResponse message
	 */
	if(_IPFSendBlocksIntr(cntrl,buf,2,intr) != 2){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	cntrl->state &= ~_IPFStateTimeResponse;

	return IPFErrOK;
}
IPFErrSeverity
_IPFReadTimeResponse(
	IPFControl	cntrl,
	IPFTimeStamp	*tstamp
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIs(_IPFStateTimeResponse,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTimeResponse: called in wrong state.");
		return IPFErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_IPFReceiveBlocks(cntrl,&buf[0],2) != 2){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"_IPFReadTimeResponse: Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * Check integrity bits.
	 */
	if(memcmp(cntrl->zero,&buf[16],16) != 0){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTimeRequest: Invalid MBZ bits");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * Decode time and time error estimate
	 */
	_IPFDecodeTimeStamp(tstamp,&buf[0]);
	if(!_IPFDecodeTimeStampErrEstimate(tstamp,&buf[12])){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	cntrl->state &= ~_IPFStateTimeResponse;

	return IPFErrOK;
}

/*
 * 	TestRequest message format:
 *
 * 	size:112 octets
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
 *	24|        Time Error Estimate    |         Receiver Port         |
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
 *	92|                                MBZ                            |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	96|                                                               |
 *     100|                Integrity Zero Padding (16 octets)             |
 *     104|                                                               |
 *     108|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
IPFErrSeverity
_IPFWriteTestRequest(
	IPFControl	cntrl,
	IPFBoolean	sender,
	IPFSID		sid,
	IPFTestSpec	*test_spec
)
{
	/*
	 * Ensure cntrl is in correct state.
	 */
	if(!_IPFStateIsRequest(cntrl) || _IPFStateIsPending(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteTestRequest:called in wrong state.");
		return IPFErrFATAL;
	}

#if	TODO
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	u_int32_t	buf_len = sizeof(cntrl->msg);
	u_int32_t	i;

	/*
	 * Encode test request variables that were passed in into
	 * the "buf" in the format required by V5 of ipcntrl spec section 4.3.
	 */
	if((_IPFEncodeTestRequestPreamble(cntrl->ctx,cntrl->msg,&buf_len,
				sender,receiver,server_conf_sender,
				server_conf_receiver,sid,test_spec) != 0) ||
							(buf_len != 112)){
		return IPFErrFATAL;
	}

	/*
	 * Now - send the request! 112 octets == 7 blocks.
	 */
	if(_IPFSendBlocks(cntrl,buf,7) != 7){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * Send slots
	 */
	for(i=0;i<test_spec->nslots;i++){
		if(_IPFEncodeSlot(cntrl->msg,&test_spec->slots[i]) != IPFErrOK){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFWriteTestRequest: Invalid slot record");
			cntrl->state = _IPFStateInvalid;
			return IPFErrFATAL;
		}
		if(_IPFSendBlocks(cntrl,buf,1) != 1){
			cntrl->state = _IPFStateInvalid;
			return IPFErrFATAL;
		}
	}

	/*
	 * Send 1 block of Integrity Zero Padding.
	 */
	if(_IPFSendBlocks(cntrl,cntrl->zero,1) != 1){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

#endif
	cntrl->state |= _IPFStateTestAccept;

	return IPFErrOK;
}
#if	NOT
int
_IPFEncodeTestRequestPreamble(
		IPFContext	ctx,
		u_int32_t	*msg,
		u_int32_t	*len_ret,
		struct sockaddr	*sender,
		struct sockaddr	*receiver,
		IPFBoolean	server_conf_sender, 
		IPFBoolean	server_conf_receiver,
		IPFSID		sid,
		IPFTestSpec	*tspec
		)
{
	u_int8_t	*buf = (u_int8_t*)msg;
	u_int8_t	version;
	IPFTimeStamp	tstamp;

	if(*len_ret < 112){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFEncodeTestRequestPreamble:Buffer too small");
		*len_ret = 0;
		return IPFErrFATAL;
	}
	*len_ret = 0;

	/*
	 * Check validity of input variables.
	 */

	/* valid "conf" setup? */
	if(!server_conf_sender && !server_conf_receiver){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
		"_IPFEncodeTestRequestPreamble:Request for empty config?");
		return IPFErrFATAL;
	}

	/* consistant addresses? */
	if(sender->sa_family != receiver->sa_family){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
					"Address Family mismatch");
		return IPFErrFATAL;
	}

	/*
	 * Addresses are consistant. Can we deal with what we
	 * have been given? (We only support AF_INET and AF_INET6.)
	 */
	switch (sender->sa_family){
		case AF_INET:
			version = 4;
			break;
#ifdef	AF_INET6
		case AF_INET6:
			version = 6;
			break;
#endif
		default:
			IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid IP Address Family");
			return 1;
	}

	/*
	 * Do we have "valid" schedule variables?
	 */
	if((tspec->npackets < 1) || (tspec->nslots < 1) || !tspec->slots){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid test distribution parameters");
		return IPFErrFATAL;
	}

	/*
	 * set simple values
	 */
	buf[0] = 1;	/* Request-Session message # */
	buf[1] = version & 0xF;
	buf[2] = (server_conf_sender)?1:0;
	buf[3] = (server_conf_receiver)?1:0;

	/*
	 * slots and npackets... convert to network byte order.
	 */
	*(u_int32_t*)&buf[4] = htonl(tspec->nslots);
	*(u_int32_t*)&buf[8] = htonl(tspec->npackets);

	/*
	 * Now set addr values. (sockaddr vars should already have
	 * values in network byte order.)
	 */
	switch(version){
	struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
	struct sockaddr_in6	*saddr6;
		case 6:
			/* sender address  and port */
			saddr6 = (struct sockaddr_in6*)sender;
			memcpy(&buf[16],saddr6->sin6_addr.s6_addr,16);
			*(u_int16_t*)&buf[12] = saddr6->sin6_port;

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver;
			memcpy(&buf[32],saddr6->sin6_addr.s6_addr,16);
			*(u_int16_t*)&buf[14] = saddr6->sin6_port;

			break;
#endif
		case 4:
			/* sender address and port  */
			saddr4 = (struct sockaddr_in*)sender;
			*(u_int32_t*)&buf[16] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[12] = saddr4->sin_port;

			/* receiver address and port  */
			saddr4 = (struct sockaddr_in*)receiver;
			*(u_int32_t*)&buf[32] = saddr4->sin_addr.s_addr;
			*(u_int16_t*)&buf[14] = saddr4->sin_port;

			break;
		default:
			/*
			 * This can't happen, but default keeps compiler
			 * warnings away.
			 */
			abort();
			break;
	}

	if(sid)
		memcpy(&buf[48],sid,16);

	*(u_int32_t*)&buf[64] = htonl(tspec->packet_size_padding);

	/*
	 * timestamps...
	 */
	tstamp.ipftime = tspec->start_time;
	_IPFEncodeTimeStamp(&buf[68],&tstamp);
	tstamp.ipftime = tspec->loss_timeout;
	_IPFEncodeTimeStamp(&buf[76],&tstamp);

	*(u_int32_t*)&buf[84] = htonl(tspec->typeP);

	/*
	 * Set MBZ and Integrity Zero Padding
	 */
	memset(&buf[88],0,24);

	*len_ret = 112;

	return 0;
}
IPFErrSeverity
_IPFDecodeTestRequestPreamble(
	IPFContext	ctx,
	u_int32_t	*msg,
	u_int32_t	msg_len,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	socklen_t	*socklen,
	u_int8_t	*ipvn,
	IPFBoolean	*server_conf_sender,
	IPFBoolean	*server_conf_receiver,
	IPFSID		sid,
	IPFTestSpec	*tspec
)
{
	u_int8_t	*buf = (u_int8_t*)msg;
	u_int8_t	zero[_IPF_RIJNDAEL_BLOCK_SIZE];
	IPFTimeStamp	tstamp;

	if(msg_len != 112){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFDecodeTestRequestPreamble:Invalid message size");
		return IPFErrFATAL;
	}

	memset(zero,0,_IPF_RIJNDAEL_BLOCK_SIZE);
	if(memcmp(zero,&buf[96],_IPF_RIJNDAEL_BLOCK_SIZE)){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFDecodeTestRequestPreamble:Invalid zero padding");
		return IPFErrFATAL;
	}


	*ipvn = buf[1] & 0xF;
	tspec->nslots = ntohl(*(u_int32_t*)&buf[4]);
	tspec->npackets = ntohl(*(u_int32_t*)&buf[8]);

	switch(buf[2]){
		case 0:
			*server_conf_sender = False;
			break;
		case 1:
		default:
			*server_conf_sender = True;
			break;
	}
	switch(buf[3]){
		case 0:
			*server_conf_receiver = False;
			break;
		case 1:
		default:
			*server_conf_receiver = True;
			break;
	}

	if(!*server_conf_sender && !*server_conf_receiver){
			IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
		"_IPFDecodeTestRequestPreamble:Invalid null request");
			return IPFErrWARNING;
	}

	switch(*ipvn){
	struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
	struct sockaddr_in6	*saddr6;
		case 6:
			if(*socklen < sizeof(struct sockaddr_in6)){
				IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
	"_IPFDecodeTestRequestPreamble: socklen not large enough (%d < %d)",
					*socklen,sizeof(struct sockaddr_in6));
				*socklen = 0;
				return IPFErrFATAL;
			}
			*socklen = sizeof(struct sockaddr_in6);

			/* sender address  and port */
			saddr6 = (struct sockaddr_in6*)sender;
			saddr6->sin6_family = AF_INET6;
			memcpy(saddr6->sin6_addr.s6_addr,&buf[16],16);
			if(*server_conf_sender)
				saddr6->sin6_port = 0;
			else
				saddr6->sin6_port = *(u_int16_t*)&buf[12];

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver;
			saddr6->sin6_family = AF_INET6;
			memcpy(saddr6->sin6_addr.s6_addr,&buf[32],16);
			if(*server_conf_receiver)
				saddr6->sin6_port = 0;
			else
				saddr6->sin6_port = *(u_int16_t*)&buf[14];

			break;
#endif
		case 4:
			if(*socklen < sizeof(struct sockaddr_in)){
				*socklen = 0;
				IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
	"_IPFDecodeTestRequestPreamble: socklen not large enough (%d < %d)",
					*socklen,sizeof(struct sockaddr_in));
				return IPFErrFATAL;
			}
			*socklen = sizeof(struct sockaddr_in);

			/* sender address and port  */
			saddr4 = (struct sockaddr_in*)sender;
			saddr4->sin_family = AF_INET;
			saddr4->sin_addr.s_addr = *(u_int32_t*)&buf[16];
			if(*server_conf_sender)
				saddr4->sin_port = 0;
			else
				saddr4->sin_port = *(u_int16_t*)&buf[12];

			/* receiver address and port  */
			saddr4 = (struct sockaddr_in*)receiver;
			saddr4->sin_family = AF_INET;
			saddr4->sin_addr.s_addr = *(u_int32_t*)&buf[32];
			if(*server_conf_receiver)
				saddr4->sin_port = 0;
			else
				saddr4->sin_port = *(u_int16_t*)&buf[14];

			break;
		default:
			IPFError(ctx,IPFErrWARNING,IPFErrINVALID,
		"_IPFDecodeTestRequestPreamble: Unsupported IP version (%d)",
									*ipvn);
			return IPFErrWARNING;
	}

#ifdef	HAVE_STRUCT_SOCKADDR_SA_LEN
	sender->sa_len = receiver->sa_len = *socklen;
#endif

	memcpy(sid,&buf[48],16);

	tspec->packet_size_padding = ntohl(*(u_int32_t*)&buf[64]);

	_IPFDecodeTimeStamp(&tstamp,&buf[68]);
	tspec->start_time = tstamp.ipftime;
	_IPFDecodeTimeStamp(&tstamp,&buf[76]);
	tspec->loss_timeout = tstamp.ipftime;

	tspec->typeP = ntohl(*(u_int32_t*)&buf[84]);

	/*
	 * This implementation currently only supports type-P descriptors
	 * for valid DSCP types. (A valid DSCP value will be all 0's except
	 * the last 6 bits.)
	 */
	if(*server_conf_sender && (tspec->typeP & ~0x3F)){
		IPFError(ctx,IPFErrWARNING,IPFErrINVALID,
		"_IPFDecodeTestRequestPreamble: Unsupported type-P value (%u)",
								tspec->typeP);
		return IPFErrWARNING;
	}

	return IPFErrOK;
}


/*
 * 	Encode/Decode Slot
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|    Slot Type  |                                               |
 *	  +-+-+-+-+-+-+-+-+              MBZ                              +
 *	04|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                 Slot Parameter (Timestamp)                    |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*
 * Function:	_IPFEncodeSlot
 *
 * Description:	
 * 	This function is used to encode a slot record in a single block
 * 	in the format needed to send a slot over the wire.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
IPFErrSeverity
_IPFEncodeSlot(
	u_int32_t	msg[4],	/* 1 block 32bit aligned */
	IPFSlot		*slot
	)
{
	u_int8_t	*buf = (u_int8_t*)msg;
	IPFTimeStamp	tstamp;

	/*
	 * Initialize block to zero
	 */
	memset(buf,0,16);

	switch(slot->slot_type){
		case IPFSlotRandExpType:
			buf[0] = 0;
			tstamp.ipftime = slot->rand_exp.mean;
			break;
		case IPFSlotLiteralType:
			buf[0] = 1;
			tstamp.ipftime = slot->literal.offset;
			break;
		default:
			return IPFErrFATAL;
	}
	_IPFEncodeTimeStamp(&buf[8],&tstamp);

	return IPFErrOK;
}
/*
 * Function:	_IPFDecodeSlot
 *
 * Description:	
 * 	This function is used to read a slot in protocol format into a
 * 	slot structure record.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
IPFErrSeverity
_IPFDecodeSlot(
	IPFSlot		*slot,
	u_int32_t	msg[4] /* 1 block 32bit aligned */
	)
{
	u_int8_t	*buf = (u_int8_t*)msg;
	IPFTimeStamp	tstamp;

	_IPFDecodeTimeStamp(&tstamp,&buf[8]);
	switch(buf[0]){
		case 0:
			slot->slot_type = IPFSlotRandExpType;
			slot->rand_exp.mean = tstamp.ipftime;
			break;
		case 1:
			slot->slot_type = IPFSlotLiteralType;
			slot->literal.offset = tstamp.ipftime;
			break;
		default:
			return IPFErrFATAL;
	}

	return IPFErrOK;
}
#endif


#if	NOT
/*
 * Function:	_IPFReadTestRequestSlots
 *
 * Description:	
 * 	This function reads nslot slot descriptions off of the socket.
 * 	If slots is non-null, each slot description is decoded and
 * 	placed in the "slots" array. It is assumed to be of at least
 * 	length "nslots". If "slots" is NULL, then nslots are read
 * 	off the socket and discarded.
 *
 * 	The _IPFDecodeSlot function is called to decode each individual
 * 	slot. Then the last block of integrity zero padding is checked
 * 	to complete the reading of the TestRequest.
 *
 * 	The formats are as follows:
 *
 * 	size: Each Slot is 16 octets. All slots are followed by 16 octets
 * 	of Integrity Zero Padding.
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|    Slot Type  |                                               |
 *	  +-+-+-+-+-+-+-+-+              MBZ                              +
 *	04|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                 Slot Parameter (Timestamp)                    |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	  ...
 *	  ...
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                                                               |
 *      04|                Integrity Zero Padding (16 octets)             |
 *      08|                                                               |
 *      12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static IPFErrSeverity
_IPFReadTestRequestSlots(
	IPFControl	cntrl,
	int		*intr,
	u_int32_t	nslots,
	IPFSlot		*slots
)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	u_int32_t	i;
	int		len;

	if(!_IPFStateIs(_IPFStateTestRequestSlots,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTestRequestSlots called in wrong state.");
		return IPFErrFATAL;
	}

	for(i=0;i<nslots;i++){

		/*
		 * Read slot into buffer.
		 */
		if((len = _IPFReceiveBlocksIntr(cntrl,&buf[0],1,intr)) != 1){
			cntrl->state = _IPFStateInvalid;
			if((len < 0) && *intr && (errno==EINTR)){
				return IPFErrFATAL;
			}
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"_IPFReadTestRequestSlots: Read Error: %M");
			return IPFErrFATAL;
		}

		/*
		 * slots will be null if we are just reading the slots
		 * to get the control connection in the correct state
		 * to respond with a denied Accept message.
		 */
		if(!slots){
			continue;
		}

		/*
		 * Decode slot from buffer into slot record.
		 */
		if(_IPFDecodeSlot(&slots[i],cntrl->msg) != IPFErrOK){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadTestRequestSlots: Invalid Slot");
			cntrl->state = _IPFStateInvalid;
			return IPFErrFATAL;
		}

	}

	/*
	 * Now read Integrity Zero Padding
	 */
	if((len=_IPFReceiveBlocksIntr(cntrl,&buf[0],1,intr)) != 1){
		cntrl->state = _IPFStateInvalid;
		if((len<0) && *intr && (errno == EINTR)){
			return IPFErrFATAL;
		}
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"_IPFReadTestRequestSlots: Read Error: %M");
		return IPFErrFATAL;
	}

	/*
	 * Now check the integrity.
	 */
	if(memcmp(cntrl->zero,&buf[0],_IPF_RIJNDAEL_BLOCK_SIZE) != 0){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTestRequestSlots:Invalid zero padding");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * TestRequestSlots are read, now ready to send TestAccept message.
	 */
	cntrl->state &= ~_IPFStateTestRequestSlots;

	return IPFErrOK;
}
#endif

/*
 * Function:	AddrBySAddrRef
 *
 * Description:	
 * 	Construct an IPFAddr record given a sockaddr struct.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static IPFAddr
AddrBySAddrRef(
	IPFContext	ctx,
	struct sockaddr	*saddr,
	socklen_t	saddrlen
	)
{
	IPFAddr		addr;
	struct addrinfo	*ai=NULL;
	int		gai;

	if(!saddr){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"AddrBySAddrRef:Invalid saddr");
		return NULL;
	}

	if(!(addr = _IPFAddrAlloc(ctx)))
		return NULL;

	if(!(ai = malloc(sizeof(struct addrinfo)))){
		IPFError(addr->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"malloc():%s",strerror(errno));
		(void)IPFAddrFree(addr);
		return NULL;
	}

	if(!(addr->saddr = malloc(saddrlen))){
		IPFError(addr->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"malloc():%s",strerror(errno));
		(void)IPFAddrFree(addr);
		(void)free(ai);
		return NULL;
	}
	memcpy(addr->saddr,saddr,saddrlen);
	ai->ai_addr = addr->saddr;
	addr->saddrlen = saddrlen;
	ai->ai_addrlen = saddrlen;

	ai->ai_flags = 0;
	ai->ai_family = saddr->sa_family;
	ai->ai_socktype = SOCK_DGRAM;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default.	*/
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->so_type = SOCK_DGRAM;
	addr->so_protocol = IPPROTO_IP;

	if( (gai = getnameinfo(addr->saddr,addr->saddrlen,
				addr->node,sizeof(addr->node),
				addr->port,sizeof(addr->port),
				NI_NUMERICHOST | NI_NUMERICSERV)) != 0){
		IPFError(addr->ctx,IPFErrWARNING,IPFErrUNKNOWN,
				"getnameinfo(): %s",gai_strerror(gai));
		strncpy(addr->node,"unknown",sizeof(addr->node));
		strncpy(addr->port,"unknown",sizeof(addr->port));
	}
	addr->node_set = True;
	addr->port_set = True;

	return addr;
}

/*
 * Function:	_IPFReadTestRequest
 *
 * Description:	
 * 	This function reads a test request off the wire and encodes
 * 	the information in a TestSession record.
 *
 * 	If it is called in a server context, the acceptval pointer will
 * 	be non-null and will be set. (i.e. if there is a memory allocation
 * 	error, it will be set to IPF_CNTRL_FAILURE. If there is invalid
 * 	data in the TestRequest it will be set to IPF_CNTRL_REJECT.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
IPFErrSeverity
_IPFReadTestRequest(
	IPFControl	cntrl,
	int		*retn_on_intr __attribute__((unused)),
	IPFTestSession	*test_session __attribute__((unused)),
	IPFAcceptType	*accept_ret __attribute__((unused))
)
{
	if(!_IPFStateIs(_IPFStateTestRequest,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTestRequest: called in wrong state.");
		return IPFErrFATAL;
	}

#if	NOT
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	IPFErrSeverity	err_ret=IPFErrOK;
	struct sockaddr_storage	sendaddr_rec;
	struct sockaddr_storage	recvaddr_rec;
	socklen_t	addrlen = sizeof(sendaddr_rec);
	IPFAddr		SendAddr=NULL;
	IPFAddr		RecvAddr=NULL;
	u_int8_t	ipvn;
	IPFBoolean	conf_sender;
	IPFBoolean	conf_receiver;
	IPFSID		sid;
	IPFTestSpec	tspec;
	int		rc;
	IPFTestSession	tsession;
	IPFAcceptType	accept_mem;
	IPFAcceptType	*accept_ptr = &accept_mem;
	int		ival=0;
	int		*intr=&ival;

	*test_session = NULL;
	memset(&sendaddr_rec,0,addrlen);
	memset(&recvaddr_rec,0,addrlen);
	memset(&tspec,0,sizeof(tspec));
	memset(sid,0,sizeof(sid));


	/*
	 * Setup an IPFAcceptType return in the event this function is
	 * called in a "server" context.
	 */
	if(accept_ret)
		accept_ptr = accept_ret;
	*accept_ptr = IPF_CNTRL_ACCEPT;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * If this was called from the client side, we need to read
	 * one block of data into the cntrl buffer. (Server side already
	 * did this to determine the message type - client is doing this
	 * as part of a fetch session.
	 */
	if(!accept_ret && (_IPFReceiveBlocksIntr(cntrl,&buf[0],1,intr) != 1)){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"_IPFReadTestRequest: Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		*accept_ptr = IPF_CNTRL_INVALID;
		return IPFErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_IPFReceiveBlocksIntr(cntrl,&buf[16],_IPF_TEST_REQUEST_BLK_LEN-1,
				intr) != (_IPF_TEST_REQUEST_BLK_LEN-1)){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
		"_IPFReadTestRequest: Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		*accept_ptr = IPF_CNTRL_INVALID;
		return IPFErrFATAL;
	}

	/*
	 * Now - fill in the Addr records, ipvn, server_conf varaibles,
	 * sid and "tspec" with the values in the msg buffer.
	 */
	if( (err_ret = _IPFDecodeTestRequestPreamble(cntrl->ctx,cntrl->msg,
			_IPF_TEST_REQUEST_BLK_LEN*_IPF_RIJNDAEL_BLOCK_SIZE,
			(struct sockaddr*)&sendaddr_rec,
			(struct sockaddr*)&recvaddr_rec,&addrlen,&ipvn,
			&conf_sender,&conf_receiver,sid,&tspec)) != IPFErrOK){
		/*
		 * INFO/WARNING indicates a request that we cannot honor.
		 * FATAL indicates inproper formatting, and probable
		 * control connection corruption.
		 */
		if(err_ret < IPFErrWARNING){
			cntrl->state = _IPFStateInvalid;
			*accept_ptr = IPF_CNTRL_INVALID;
			return IPFErrFATAL;
		}else if(accept_ret){
			/*
			 * only return in server context
			 */
			*accept_ptr = IPF_CNTRL_UNSUPPORTED;
			return IPFErrFATAL;
		}
	}

	/*
	 * TestRequest Preamble is read, now ready to read slots.
	 */
	cntrl->state &= ~_IPFStateTestRequest;
	cntrl->state |= _IPFStateTestRequestSlots;

	/*
	 * Prepare the address buffers.
	 * (Don't bother checking for null return - it will be checked
	 * by _IPFTestSessionAlloc.)
	 */
	SendAddr = AddrBySAddrRef(cntrl->ctx,(struct sockaddr*)&sendaddr_rec,
								addrlen);
	RecvAddr = AddrBySAddrRef(cntrl->ctx,(struct sockaddr*)&recvaddr_rec,
								addrlen);

	/*
	 * Allocate a record for this test.
	 */
	if( !(tsession = _IPFTestSessionAlloc(cntrl,SendAddr,conf_sender,
					RecvAddr,conf_receiver,&tspec))){
		err_ret = IPFErrWARNING;
		*accept_ptr = IPF_CNTRL_FAILURE;
		goto error;
	}

	/*
	 * copy sid into tsession - if the sid still needs to be
	 * generated - it still will be in sapi.c:IPFProcessTestRequest
	 */
	memcpy(tsession->sid,sid,sizeof(sid));

	/*
	 * Allocate memory for slots...
	 */
	if(tsession->test_spec.nslots > _IPFSLOT_BUFSIZE){
		/*
		 * Will check for memory allocation failure after
		 * reading slots from socket. (We can gracefully
		 * decline the request even if we can't allocate memory
		 * to hold the slots this way.)
		 */
		tsession->test_spec.slots =
			calloc(tsession->test_spec.nslots,sizeof(IPFSlot));
	}else{
		tsession->test_spec.slots = tsession->slot_buffer;
	}

	/*
	 * Now, read the slots of the control socket.
	 */
	if( (rc = _IPFReadTestRequestSlots(cntrl,intr,
					tsession->test_spec.nslots,
					tsession->test_spec.slots)) < IPFErrOK){
		cntrl->state = _IPFStateInvalid;
		err_ret = (IPFErrSeverity)rc;
		*accept_ptr = IPF_CNTRL_INVALID;
		goto error;
	}

	/*
	 * We were unable to save the slots - server should decline the request.
	 */
	if(!tsession->test_spec.slots){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"calloc(%d,IPFSlot): %M",
					tsession->test_spec.nslots);
		*accept_ptr = IPF_CNTRL_FAILURE;
		err_ret = IPFErrFATAL;
		goto error;
	}

	/*
	 * In the server context, we are going to _IPFStateTestAccept.
	 * In the client "fetching" context we are ready to read the
	 * record header and the records.
	 */
	if(accept_ret){
		cntrl->state |= _IPFStateTestAccept;
	}else{
		cntrl->state |= _IPFStateFetching;
	}

	*test_session = tsession;

	return IPFErrOK;

error:
	if(tsession){
		_IPFTestSessionFree(tsession,IPF_CNTRL_FAILURE);
	}else{
		IPFAddrFree(SendAddr);
		IPFAddrFree(RecvAddr);
	}

	return err_ret;
#endif

	return IPFErrFATAL;
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
 *	20|                                                               |
 *	24|                      Zero Padding (12 octets)                 |
 *	28|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
IPFErrSeverity
_IPFWriteTestAccept(
	IPFControl	cntrl,
	int		*intr,
	IPFAcceptType	acceptval,
	u_int16_t	port,
	IPFSID		sid
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIs(_IPFStateTestAccept,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFWriteTestAccept called in wrong state.");
		return IPFErrFATAL;
	}

	buf[0] = acceptval & 0xff;
	*(u_int16_t *)&buf[2] = htons(port);
	if(sid)
		memcpy(&buf[4],sid,16);
	memset(&buf[20],0,12);

	if(_IPFSendBlocksIntr(cntrl,buf,2,intr) != 2){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	cntrl->state &= ~_IPFStateTestAccept;

	return IPFErrOK;
}

IPFErrSeverity
_IPFReadTestAccept(
	IPFControl	cntrl,
	IPFAcceptType	*acceptval,
	u_int16_t	*port,
	IPFSID		sid
	)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIs(_IPFStateTestAccept,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadTestAccept called in wrong state.");
		return IPFErrFATAL;
	}

	/*
	 * Get the servers response.
	 */
	if(_IPFReceiveBlocks(cntrl,buf,2) != 2){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"_IPFReadTestAccept:Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * Check zero padding first.
	 */
	if(memcmp(&buf[20],cntrl->zero,12)){
		cntrl->state = _IPFStateInvalid;
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid Accept-Session message received");
		return IPFErrFATAL;
	}

	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == IPF_CNTRL_INVALID){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(port)
		*port = ntohs(*(u_int16_t*)&buf[2]);

	if(sid)
		memcpy(sid,&buf[4],16);

	cntrl->state &= ~_IPFStateTestAccept;

	return IPFErrOK;
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
 *	00|      2        |                                               |
 *	  +-+-+-+-+-+-+-+-+                                               +
 *	04|                      Unused (15 octets)                       |
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
IPFErrSeverity
_IPFWriteStartSession(
	IPFControl	cntrl
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIsRequest(cntrl) || _IPFStateIsPending(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteStartSession:called in wrong state.");
		return IPFErrFATAL;
	}

	buf[0] = 2;	/* start-session identifier	*/
#ifndef	NDEBUG
	memset(&buf[1],0,15);	/* Unused	*/
#endif
	memset(&buf[16],0,16);	/* Zero padding */

	if(_IPFSendBlocks(cntrl,buf,2) != 2){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	cntrl->state |= _IPFStateControlAck;
	cntrl->state |= _IPFStateTest;
	return IPFErrOK;
}

IPFErrSeverity
_IPFReadStartSession(
	IPFControl	cntrl,
	int		*retn_on_intr
)
{
	int		n;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIs(_IPFStateStartSession,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadStartSession called in wrong state.");
		return IPFErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	n = _IPFReceiveBlocksIntr(cntrl,&buf[16],
			_IPF_STOP_SESSIONS_BLK_LEN-1,retn_on_intr);

	if((n < 0) && *retn_on_intr && (errno == EINTR)){
		return IPFErrFATAL;
	}

	if(n != (_IPF_STOP_SESSIONS_BLK_LEN-1)){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"_IPFReadStartSession:Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadTestRequest:Invalid zero padding");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(buf[0] != 2){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadStartSession:Not a StartSession message...");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_IPFStateStartSession;
	cntrl->state |= _IPFStateControlAck;
	cntrl->state |= _IPFStateTest;

	return IPFErrOK;
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
 *	04|                       Unused (14 octets)                      |
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
IPFErrSeverity
_IPFWriteStopSession(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	acceptval
	)
{
	int		n;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!(_IPFStateIs(_IPFStateRequest,cntrl) &&
				_IPFStateIs(_IPFStateTest,cntrl))){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFWriteStopSession called in wrong state.");
		return IPFErrFATAL;
	}

	buf[0] = 3;
	buf[1] = acceptval & 0xff;
#ifndef	NDEBUG
	memset(&buf[2],0,14);	/* Unused	*/
#endif
	memset(&buf[16],0,16);	/* Zero padding */

	n = _IPFSendBlocks(cntrl,buf,2);
	if((n < 0) && *retn_on_intr && (errno == EINTR)){
		return IPFErrFATAL;
	}
	if(n != 2)
		return IPFErrFATAL;
	return IPFErrOK;
}

IPFErrSeverity
_IPFReadStopSession(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	*acceptval
)
{
	int		n;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	IPFAcceptType	aval;

	if(!(_IPFStateIs(_IPFStateRequest,cntrl) &&
					_IPFStateIs(_IPFStateTest,cntrl))){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadStopSession called in wrong state.");
		return IPFErrFATAL;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if((n = _IPFReceiveBlocksIntr(cntrl,&buf[16],
				_IPF_STOP_SESSIONS_BLK_LEN-1,retn_on_intr)) !=
						(_IPF_STOP_SESSIONS_BLK_LEN-1)){
		if((n < 0) && *retn_on_intr && (errno == EINTR)){
			return IPFErrFATAL;
		}
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"_IPFReadStopSession:Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadStopSession:Invalid zero padding");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}
	aval = GetAcceptType(cntrl,buf[1]);
	if(acceptval)
		*acceptval = aval;

	if(aval == IPF_CNTRL_INVALID){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_IPFStateStopSession;
	cntrl->state |= _IPFStateRequest;

	return IPFErrOK;
}

/*
 *
 * 	ControlAck message format:
 *
 * 	size: 32 octets
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|     Accept    |                                               |
 *	  +-+-+-+-+-+-+-+-+                                               +
 *	04|                      Unused (15 octets)                       |
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
IPFErrSeverity
_IPFWriteControlAck(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	acceptval
	)
{
	int		n;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIs(_IPFStateControlAck,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFWriteControlAck called in wrong state.");
		return IPFErrFATAL;
	}

	buf[0] = acceptval & 0xff;
#ifndef	NDEBUG
	memset(&buf[1],0,15);	/* Unused	*/
#endif
	memset(&buf[16],0,16);	/* Zero padding */

	n = _IPFSendBlocksIntr(cntrl,buf,_IPF_CONTROL_ACK_BLK_LEN,retn_on_intr);

	if((n < 0) && *retn_on_intr && (errno == EINTR)){
		return IPFErrFATAL;
	}

	if(n != _IPF_CONTROL_ACK_BLK_LEN){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * ControlAck has been sent, leave that state.
	 */
	cntrl->state &= ~_IPFStateControlAck;

	/*
	 * Test was denied - go back to Request state.
	 */
	if(_IPFStateIs(_IPFStateTest,cntrl) && (acceptval != IPF_CNTRL_ACCEPT)){
		cntrl->state &= ~_IPFStateTest;
	}

	return IPFErrOK;
}

IPFErrSeverity
_IPFReadControlAck(
	IPFControl	cntrl,
	IPFAcceptType	*acceptval
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	*acceptval = IPF_CNTRL_INVALID;

	if(!_IPFStateIs(_IPFStateControlAck,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadControlAck called in wrong state.");
		return IPFErrFATAL;
	}

	if(_IPFReceiveBlocks(cntrl,&buf[0],_IPF_CONTROL_ACK_BLK_LEN) != 
					(_IPF_CONTROL_ACK_BLK_LEN)){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"_IPFReadControlAck:Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadControlAck:Invalid zero padding");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}
	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == IPF_CNTRL_INVALID){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * received ControlAck - leave that state.
	 */
	cntrl->state &= ~_IPFStateControlAck;

	/* If StartSession was rejected get back into StateRequest */
	if (_IPFStateIsTest(cntrl) && (*acceptval != IPF_CNTRL_ACCEPT)){
		cntrl->state &= ~_IPFStateTest;
		cntrl->state |= _IPFStateRequest;
	}


	return IPFErrOK;
}
