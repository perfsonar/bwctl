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

	if(!_IPFStateIs(_IPFStateTimeResponse,cntrl)){
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
	_IPFEncodeTimeStamp(&buf[0],tstamp);
	if(!_IPFEncodeTimeStampErrEstimate(&buf[8],tstamp)){
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
	socklen_t	saddrlen,
	int		socktype
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
	ai->ai_socktype = socktype;
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
	IPFTestSession	tsession
)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	IPFTestSpec	*tspec = &tsession->test_spec;
	IPFTimeStamp	tstamp;
	IPFAddr		sender;
	IPFAddr		receiver;
	u_int8_t	version;

	/*
	 * Ensure cntrl is in correct state.
	 */
	if(!_IPFStateIsRequest(cntrl) || _IPFStateIsPending(cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteTestRequest:called in wrong state.");
		return IPFErrFATAL;
	}

	/*
	 * Interpret addresses
	 */
	sender = tspec->sender;
	receiver = tspec->receiver;

	if(sender->saddr->sa_family != receiver->saddr->sa_family){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
					"Address Family mismatch");
		return IPFErrFATAL;
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
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid IP Address Family");
			return IPFErrFATAL;
	}

	/*
	 * Initialize buffer
	 */
	memset(&buf[0],0,112);

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
	*(u_int32_t*)&buf[4] = htonl(tspec->duration);
	_IPFEncodeTimeStamp(&buf[8],&tspec->req_time);
	tstamp.ipftime = tspec->latest_time;
	_IPFEncodeTimeStamp(&buf[16],&tstamp);
	if(!_IPFEncodeTimeStampErrEstimate(&buf[24],&tspec->req_time)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid req_time time errest");
		return IPFErrFATAL;
	}
	*(u_int16_t*)&buf[26] = htons(tsession->recv_port);

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
			saddr6 = (struct sockaddr_in6*)sender;
			memcpy(&buf[28],saddr6->sin6_addr.s6_addr,16);

			/* receiver address and port  */
			saddr6 = (struct sockaddr_in6*)receiver;
			memcpy(&buf[44],saddr6->sin6_addr.s6_addr,16);

			break;
#endif
		case 4:
			/* sender address */
			saddr4 = (struct sockaddr_in*)sender;
			*(u_int32_t*)&buf[28] = saddr4->sin_addr.s_addr;

			/* receiver address */
			saddr4 = (struct sockaddr_in*)receiver;
			*(u_int32_t*)&buf[44] = saddr4->sin_addr.s_addr;

			break;
		default:
			/*
			 * This can't happen, but default keeps compiler
			 * warnings away.
			 */
			abort();
			break;
	}

	memcpy(&buf[48],tsession->sid,16);
	*(u_int32_t*)&buf[76] = htonl(tspec->bandwidth);
	*(u_int32_t*)&buf[80] = htonl(tspec->len_buffer);
	*(u_int32_t*)&buf[84] = htonl(tspec->window_size);
	*(u_int32_t*)&buf[88] = htonl(tspec->report_interval);

	/*
	 * Set MBZ and Integrity Zero Padding
	 */
	memset(&buf[92],0,20);

	/*
	 * Now - send the request! 112 octets == 7 blocks.
	 */
	if(_IPFSendBlocks(cntrl,buf,7) != 7){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	cntrl->state |= _IPFStateTestAccept;

	return IPFErrOK;
}

/*
 * Function:	_IPFReadTestRequest
 *
 * Description:	
 * 	This function reads a test request off the wire and encodes
 * 	the information in a TestSession record.
 *
 * 	The acceptval pointer will be non-null and will return a value.
 * 	(i.e. if there is a memory allocation error, it will be set to
 * 	IPF_CNTRL_FAILURE. If there is invalid data in the TestRequest
 * 	it will be set to IPF_CNTRL_REJECT.)
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
	int		*retn_on_intr,
	IPFTestSession	*test_session,
	IPFAcceptType	*accept_ret
)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	IPFTimeStamp	tstamp;
	IPFErrSeverity	err_ret=IPFErrFATAL;
	struct sockaddr_storage	sendaddr_rec;
	struct sockaddr_storage	recvaddr_rec;
	socklen_t	addrlen = sizeof(sendaddr_rec);
	IPFAddr		SendAddr=NULL;
	IPFAddr		RecvAddr=NULL;
	u_int8_t	ipvn;
	IPFSID		sid;
	IPFTestSpec	tspec;
	IPFTestSession	tsession;
	int		ival=0;
	int		*intr=&ival;
	u_int16_t	recv_port;
	IPFBoolean	conf_sender;
	IPFBoolean	conf_receiver;

	if(!_IPFStateIs(_IPFStateTestRequest,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTestRequest: called in wrong state.");
		return IPFErrFATAL;
	}

	memset(&sendaddr_rec,0,addrlen);
	memset(&recvaddr_rec,0,addrlen);
	memset(&tspec,0,sizeof(tspec));
	memset(sid,0,sizeof(sid));


	/*
	 * Initialize IPFAcceptType
	 */
	*accept_ret = IPF_CNTRL_INVALID;

	/*
	 * If caller wants to participate in interrupts, use the passed in addr.
	 */
	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * Already read the first block - read the rest for this message
	 * type.
	 */
	if(_IPFReceiveBlocksIntr(cntrl,&buf[16],_IPF_TEST_REQUEST_BLK_LEN-1,
				intr) != (_IPF_TEST_REQUEST_BLK_LEN-1)){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
		"_IPFReadTestRequest: Unable to read from socket.");
		goto error;
	}


	if(memcmp(cntrl->zero,&buf[96],_IPF_RIJNDAEL_BLOCK_SIZE)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadTestRequest: Invalid zero padding");
		goto error;
	}

	/*
	 * Decode the parameters that are used for initial request AND
	 * for reservation update.
	 */
	_IPFDecodeTimeStamp(&tspec.req_time,&buf[8]);
	if(!_IPFDecodeTimeStampErrEstimate(&tspec.req_time,&buf[24])){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadTestRequest: Invalid time errest");
		goto error;
	}
	_IPFDecodeTimeStamp(&tstamp,&buf[16]);
	tspec.latest_time = tstamp.ipftime;
	recv_port = ntohs(*(u_int16_t*)&buf[26]);

	/*
	 * copy sid (will be ignored if this is an initial receive request)
	 */
	memcpy(sid,&buf[60],16);

	if(*test_session){
		tsession = *test_session;
		if(memcmp(sid,tsession->sid,sizeof(sid)) != 0){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadTestRequest: sid mismatch");
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

		tspec.duration = *(u_int32_t*)&buf[4];

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
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadTestRequest: Invalid req(send/recv?)");
			goto error;
		}

		switch(ipvn){
		struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
		struct sockaddr_in6	*saddr6;
			case 6:
				if(addrlen < sizeof(struct sockaddr_in6)){
					IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
		"_IPFReadTestRequest: socklen not large enough (%d < %d)",
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
				memcpy(saddr6->sin6_addr.s6_addr,&buf[32],16);
				saddr6->sin6_port = 0;

				break;
#endif
			case 4:
				if(addrlen < sizeof(struct sockaddr_in)){
					IPFError(cntrl->ctx,IPFErrFATAL,
						IPFErrINVALID,
		"_IPFReadTestRequest: socklen not large enough (%d < %d)",
						addrlen,
						sizeof(struct sockaddr_in));
					goto error;
				}
				addrlen = sizeof(struct sockaddr_in);

				/* sender address and port  */
				saddr4 = (struct sockaddr_in*)&sendaddr_rec;
				saddr4->sin_family = AF_INET;
				saddr4->sin_addr.s_addr = *(u_int32_t*)&buf[16];
				saddr4->sin_port = 0;

				/* receiver address and port  */
				saddr4 = (struct sockaddr_in*)&recvaddr_rec;
				saddr4->sin_family = AF_INET;
				saddr4->sin_addr.s_addr = *(u_int32_t*)&buf[32];
				saddr4->sin_port = 0;

				break;
			default:
				IPFError(cntrl->ctx,IPFErrWARNING,IPFErrINVALID,
			"_IPFReadTestRequest: Unsupported IP version (%d)",
									ipvn);
				goto error;
		}

#ifdef	HAVE_STRUCT_SOCKADDR_SA_LEN
		((struct sockaddr *)&sendaddr_rec)->sa_len =
		((struct sockaddr *)&recvaddr_rec)->sa_len = addrlen;
#endif
		/*
		 * Prepare the address buffers.
		 * (Don't bother checking for null return - it will be checked
		 * by _IPFTestSessionAlloc.)
		 */
		SendAddr = AddrBySAddrRef(cntrl->ctx,
				(struct sockaddr*)&sendaddr_rec,addrlen,
				(tspec.udp)?SOCK_DGRAM:SOCK_STREAM);
		RecvAddr = AddrBySAddrRef(cntrl->ctx,
				(struct sockaddr*)&recvaddr_rec,addrlen,
				(tspec.udp)?SOCK_DGRAM:SOCK_STREAM);

		tspec.bandwidth = ntohl(*(u_int32_t*)&buf[76]);
		tspec.len_buffer = ntohl(*(u_int32_t*)&buf[80]);
		tspec.window_size = ntohl(*(u_int32_t*)&buf[84]);
		tspec.report_interval = ntohl(*(u_int32_t*)&buf[88]);

		/*
		 * Allocate a record for this test.
		 */
		if( !(tsession = _IPFTestSessionAlloc(cntrl,conf_sender,
					SendAddr,RecvAddr,recv_port,&tspec))){
			err_ret = IPFErrWARNING;
			*accept_ret = IPF_CNTRL_FAILURE;
			goto error;
		}

		/*
		 * copy sid into tsession - if the sid still needs to be
		 * generated - it still will be in sapi.c:IPFProcessTestRequest
		 */
		memcpy(tsession->sid,&buf[48],16);

	}


	*test_session = tsession;
	*accept_ret = IPF_CNTRL_ACCEPT;

	cntrl->state &= ~_IPFStateTestRequest;
	cntrl->state |= _IPFStateTestAccept;

	return IPFErrOK;

error:
	if(tsession){
		_IPFTestSessionFree(tsession,IPF_CNTRL_FAILURE);
	}else{
		IPFAddrFree(SendAddr);
		IPFAddrFree(RecvAddr);
	}

	if(err_ret < IPFErrWARNING){
		cntrl->state = _IPFStateInvalid;
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
IPFErrSeverity
_IPFWriteTestAccept(
	IPFControl	cntrl,
	int		*intr,
	IPFAcceptType	acceptval,
	IPFTestSession	tsession
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	IPFTimeStamp	tstamp;

	if(!_IPFStateIs(_IPFStateTestAccept,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFWriteTestAccept called in wrong state.");
		return IPFErrFATAL;
	}

	memset(buf,0,32);

	buf[0] = acceptval & 0xff;
	if(tsession->conf_receiver){
		*(u_int16_t *)&buf[2] = htons(tsession->recv_port);
	}
	memcpy(&buf[4],tsession->sid,16);
	tstamp.ipftime = tsession->reserve_time;
	_IPFEncodeTimeStamp(&buf[20],&tstamp);

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
	IPFTestSession	tsession
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	IPFTimeStamp	tstamp;

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
	if(memcmp(&buf[28],cntrl->zero,4)){
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

	if(tsession->conf_receiver){
		tsession->recv_port = ntohs(*(u_int16_t*)&buf[2]);
		memcpy(tsession->sid,&buf[4],16);
	}

	_IPFDecodeTimeStamp(&tstamp,&buf[20]);
	tsession->reserve_time = tstamp.ipftime;

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
IPFErrSeverity
_IPFWriteStartSession(
	IPFControl	cntrl,
	u_int16_t	dataport
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIsRequest(cntrl) || _IPFStateIsPending(cntrl) ||
			!cntrl->tests){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteStartSession: called in wrong state.");
		return IPFErrFATAL;
	}

	/* initialize buffer */
	memset(&buf[0],0,32);

	buf[0] = 2;	/* start-session identifier	*/
	/*
	 * If conf_sender, than need to "set" the dataport.
	 */
	if(cntrl->tests->conf_sender){
		*(u_int16_t*)&buf[2] = htons(dataport);
	}

	if(_IPFSendBlocks(cntrl,buf,2) != 2){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	cntrl->state |= _IPFStateStartAck;
	cntrl->state |= _IPFStateTest;
	return IPFErrOK;
}

IPFErrSeverity
_IPFReadStartSession(
	IPFControl	cntrl,
	u_int16_t	*dataport,
	int		*retn_on_intr
)
{
	int		n;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIs(_IPFStateStartSession,cntrl) || !cntrl->tests){
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
			"_IPFReadStartSession: Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadTestRequest: Invalid zero padding");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(buf[0] != 2){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFReadStartSession: Not a StartSession message...");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(cntrl->tests->conf_sender){
		*dataport = ntohs(*(u_int16_t*)&buf[2]);
	}
	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_IPFStateStartSession;
	cntrl->state |= _IPFStateStartAck;
	cntrl->state |= _IPFStateTest;

	return IPFErrOK;
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
IPFErrSeverity
_IPFWriteStartAck(
	IPFControl	cntrl,
	int		*retn_on_intr,
	u_int16_t	dataport,
	IPFAcceptType	acceptval
	)
{
	int		n;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;

	if(!_IPFStateIs(_IPFStateStartAck,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFWriteStartAck called in wrong state.");
		return IPFErrFATAL;
	}

	memset(&buf[0],0,32);

	buf[0] = acceptval & 0xff;

	if(cntrl->tests->conf_receiver){
		*(u_int16_t*)&buf[2] = htons(dataport);
	}

	n = _IPFSendBlocksIntr(cntrl,buf,_IPF_CONTROL_ACK_BLK_LEN,retn_on_intr);

	if((n < 0) && *retn_on_intr && (errno == EINTR)){
		return IPFErrFATAL;
	}

	if(n != _IPF_CONTROL_ACK_BLK_LEN){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	/*
	 * StartAck has been sent, leave that state.
	 */
	cntrl->state &= ~_IPFStateStartAck;

	/*
	 * Test was denied - go back to Request state.
	 */
	if(_IPFStateIs(_IPFStateTest,cntrl) && (acceptval != IPF_CNTRL_ACCEPT)){
		cntrl->state &= ~_IPFStateTest;
	}

	return IPFErrOK;
}

IPFErrSeverity
_IPFReadStartAck(
	IPFControl	cntrl,
	u_int16_t	*dataport,
	IPFAcceptType	*acceptval
)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	*acceptval = IPF_CNTRL_INVALID;

	if(!_IPFStateIs(_IPFStateStartAck,cntrl)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadStartAck called in wrong state.");
		return IPFErrFATAL;
	}

	if(_IPFReceiveBlocks(cntrl,&buf[0],_IPF_CONTROL_ACK_BLK_LEN) != 
					(_IPF_CONTROL_ACK_BLK_LEN)){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"_IPFReadStartAck: Unable to read from socket.");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadStartAck: Invalid zero padding");
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}
	*acceptval = GetAcceptType(cntrl,buf[0]);
	if(*acceptval == IPF_CNTRL_INVALID){
		cntrl->state = _IPFStateInvalid;
		return IPFErrFATAL;
	}

	if(cntrl->tests->conf_receiver){
		*dataport = ntohs(*(u_int16_t*)&buf[2]);
	}

	/*
	 * received StartAck - leave that state.
	 */
	cntrl->state &= ~_IPFStateStartAck;

	/* If StartSession was rejected get back into StateRequest */
	if (_IPFStateIsTest(cntrl) && (*acceptval != IPF_CNTRL_ACCEPT)){
		cntrl->state &= ~_IPFStateTest;
		cntrl->state |= _IPFStateRequest;
	}


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
 *	04|                       Unused (6 octets)                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                       N-bytes following                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	12|                       Unused (4 octets)                       |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                                                               |
 *	20|                    Zero Padding (20 octets)                   |
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
IPFErrSeverity
_IPFWriteStopSession(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	acceptval,
	FILE		*fp
	)
{
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	struct stat	sbuf;
	u_int32_t	fsize = 0;

	if(!(_IPFStateIs(_IPFStateRequest,cntrl) &&
				_IPFStateIs(_IPFStateTest,cntrl))){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFWriteStopSession called in wrong state.");
		return IPFErrFATAL;
	}

	memset(&buf[0],0,32);

	buf[0] = 3;
	if(fp){
		/*
		 * Find out how much data we need to send.
		 */
		if(fstat(fileno(fp),&sbuf) || fseeko(fp,0,SEEK_SET)){
			acceptval = IPF_CNTRL_FAILURE;
			goto datadone;
		}
		fsize = sbuf.st_size;

		/*
		 * check for overflow.
		 */
		if(sbuf.st_size != (off_t)fsize){
			fsize = 0;
			IPFError(cntrl->ctx,IPFErrWARNING,IPFErrUNKNOWN,
				"_IPFWriteStopSession: Invalid data file");
			acceptval = IPF_CNTRL_FAILURE;
			goto datadone;
		}

		*(u_int32_t*)&buf[8] = htonl(fsize);
	}

datadone:
	buf[1] = acceptval & 0xff;

	if(_IPFSendBlocksIntr(cntrl,buf,2,retn_on_intr) != 2){
		return IPFErrFATAL;
	}

	if(!fsize){
		return IPFErrOK;
	}

	/*
	 * Send data with trailing zero block
	 */

	while(fsize >= _IPF_RIJNDAEL_BLOCK_SIZE){
		if(fread(buf,1,_IPF_RIJNDAEL_BLOCK_SIZE,fp) !=
						_IPF_RIJNDAEL_BLOCK_SIZE){
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}
		if(_IPFSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}
		fsize -= _IPF_RIJNDAEL_BLOCK_SIZE;
	}

	if(fsize > 0){
		memset(buf,0,_IPF_RIJNDAEL_BLOCK_SIZE);
		if(fread(buf,1,fsize,fp) != fsize){
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}
		if(_IPFSendBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}
	}

	if(_IPFSendBlocksIntr(cntrl,cntrl->zero,1,retn_on_intr) != 1){
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	return IPFErrOK;
}

IPFErrSeverity
_IPFReadStopSession(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	*acceptval,
	FILE		*fp
)
{
	int		n;
	u_int8_t	*buf = (u_int8_t*)cntrl->msg;
	IPFAcceptType	aval;
	u_int32_t	fsize;

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
			"_IPFReadStopSession: Unable to read from socket.");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	if(memcmp(cntrl->zero,&buf[16],16)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadStopSession: Invalid zero padding");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}
	aval = GetAcceptType(cntrl,buf[1]);
	if(acceptval)
		*acceptval = aval;

	if(aval == IPF_CNTRL_INVALID){
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	fsize = ntohl(*(u_int32_t*)&buf[8]);

	if(!fsize){
		return IPFErrOK;
	}

	/*
	 * Read test results and write to fp, if not null.
	 */
	while(fsize >= _IPF_RIJNDAEL_BLOCK_SIZE){

		if(_IPFReceiveBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}

		if(fp && (fwrite(buf,_IPF_RIJNDAEL_BLOCK_SIZE,1,fp) != 1)){
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}

		fsize -= _IPF_RIJNDAEL_BLOCK_SIZE;
	}

	if(fsize > 0){

		if(_IPFReceiveBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}

		if(fp && (fwrite(buf,fsize,1,fp) != 1)){
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}
	}

	/*
	 * Integrity Zero block
	 */
	if(_IPFReceiveBlocksIntr(cntrl,buf,1,retn_on_intr) != 1){
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	if(memcmp(cntrl->zero,buf,16)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFReadStopSession: Invalid zero padding");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	/*
	 * The control connection is now ready to send the response.
	 */
	cntrl->state &= ~_IPFStateStopSession;
	cntrl->state |= _IPFStateRequest;

	return IPFErrOK;
}
