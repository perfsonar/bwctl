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
**	File:		api.c
**
**	Author:		Jeff W. Boote
**
**	Date:		Tue Sep 16 14:24:49 MDT 2003
**
**	Description:	
*/
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>

#include "./ipcntrlP.h"

#ifndef EFTYPE
#define	EFTYPE	ENOSYS
#endif

IPFAddr
_IPFAddrAlloc(
	IPFContext	ctx
)
{
	IPFAddr	addr = calloc(1,sizeof(struct IPFAddrRec));

	if(!addr){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			":calloc(1,%d):%M",sizeof(struct IPFAddrRec));
		return NULL;
	}

	addr->ctx = ctx;

	addr->node_set = 0;
	strncpy(addr->node,"unknown",sizeof(addr->node));
	addr->port_set = 0;
	strncpy(addr->port,"unknown",sizeof(addr->port));
	addr->ai_free = 0;
	addr->ai = NULL;

	addr->saddr = NULL;
	addr->saddrlen = 0;

	addr->fd_user = 0;
	addr->fd= -1;

	return addr;
}

IPFErrSeverity
IPFAddrFree(
	IPFAddr	addr
)
{
	IPFErrSeverity	err = IPFErrOK;

	if(!addr)
		return err;

	if(addr->ai){
		if(!addr->ai_free){
			freeaddrinfo(addr->ai);
		}else{
			struct addrinfo	*ai, *next;

			ai = addr->ai;
			while(ai){
				next = ai->ai_next;

				if(ai->ai_addr) free(ai->ai_addr);
				if(ai->ai_canonname) free(ai->ai_canonname);
				free(ai);

				ai = next;
			}
		}
		addr->ai = NULL;
		addr->saddr = NULL;
	}

	if((addr->fd >= 0) && !addr->fd_user){
		if(close(addr->fd) < 0){
			IPFError(addr->ctx,IPFErrWARNING,
					errno,":close(%d)",addr->fd);
			err = IPFErrWARNING;
		}
	}

	free(addr);

	return err;
}

IPFAddr
IPFAddrByNode(
	IPFContext	ctx,
	const char	*node
)
{
	IPFAddr		addr;
	char		buff[MAXHOSTNAMELEN+1];
	const char	*nptr=node;
	char		*pptr=NULL;
	char		*s1,*s2;

	if(!node)
		return NULL;

	if(!(addr=_IPFAddrAlloc(ctx)))
		return NULL;

	strncpy(buff,node,MAXHOSTNAMELEN);

	/*
	 * Pull off port if specified. If syntax doesn't match URL like
	 * node:port - ipv6( [node]:port) - then just assume whole string
	 * is nodename and let getaddrinfo report problems later.
	 * (This service syntax is specified by rfc2396 and rfc2732.)
	 */

	/*
	 * First try ipv6 syntax since it is more restrictive.
	 */
	if( (s1 = strchr(buff,'['))){
		s1++;
		if(strchr(s1,'[')) goto NOPORT;
		if(!(s2 = strchr(s1,']'))) goto NOPORT;
		*s2++='\0';
		if(strchr(s2,']')) goto NOPORT;
		if(*s2++ != ':') goto NOPORT;
		nptr = s1;
		pptr = s2;
	}
	/*
	 * Now try ipv4 style.
	 */
	else if( (s1 = strchr(buff,':'))){
		*s1++='\0';
		if(strchr(s1,':')) goto NOPORT;
		nptr = buff;
		pptr = s1;
	}


NOPORT:
	strncpy(addr->node,nptr,MAXHOSTNAMELEN);
	addr->node_set = 1;

	if(pptr){
		strncpy(addr->port,pptr,MAXHOSTNAMELEN);
		addr->port_set = 1;
	}

	return addr;
}

static struct addrinfo*
_IPFCopyAddrRec(
	IPFContext		ctx,
	const struct addrinfo	*src
)
{
	struct addrinfo	*dst = calloc(1,sizeof(struct addrinfo));

	if(!dst){
		IPFError(ctx,IPFErrFATAL,errno,
				":calloc(1,sizeof(struct addrinfo))");
		return NULL;
	}

	*dst = *src;

	if(src->ai_addr){
		dst->ai_addr = malloc(src->ai_addrlen);
		if(!dst->ai_addr){
			IPFError(ctx,IPFErrFATAL,errno,
				"malloc(%u):%s",src->ai_addrlen,
				strerror(errno));
			free(dst);
			return NULL;
		}
		memcpy(dst->ai_addr,src->ai_addr,src->ai_addrlen);
		dst->ai_addrlen = src->ai_addrlen;
	}
	else
		dst->ai_addrlen = 0;

	if(src->ai_canonname){
		int	len = strlen(src->ai_canonname);

		if(len > MAXHOSTNAMELEN){
			IPFError(ctx,IPFErrWARNING,
					IPFErrUNKNOWN,
					":Invalid canonname!");
			dst->ai_canonname = NULL;
		}else{
			dst->ai_canonname = malloc(sizeof(char)*(len+1));
			if(!dst->ai_canonname){
				IPFError(ctx,IPFErrWARNING,
					errno,":malloc(sizeof(%d)",len+1);
				dst->ai_canonname = NULL;
			}else
				strcpy(dst->ai_canonname,src->ai_canonname);
		}
	}

	dst->ai_next = NULL;

	return dst;
}

IPFAddr
IPFAddrByAddrInfo(
	IPFContext		ctx,
	const struct addrinfo	*ai
)
{
	IPFAddr	addr = _IPFAddrAlloc(ctx);
	struct addrinfo	**aip;

	if(!addr)
		return NULL;

	addr->ai_free = 1;
	aip = &addr->ai;

	while(ai){
		*aip = _IPFCopyAddrRec(ctx,ai);
		if(!*aip){
			IPFAddrFree(addr);
			return NULL;
		}
		aip = &(*aip)->ai_next;
		ai = ai->ai_next;
	}

	return addr;
}

IPFAddr
IPFAddrBySockFD(
	IPFContext	ctx,
	int		fd
)
{
	IPFAddr	addr = _IPFAddrAlloc(ctx);

	if(!addr)
		return NULL;

	addr->fd_user = 1;
	addr->fd = fd;

	return addr;
}

IPFAddr
_IPFAddrCopy(
	IPFAddr		from
	)
{
	IPFAddr		to;
	struct addrinfo	**aip;
	struct addrinfo	*ai;
	
	if(!from)
		return NULL;
	
	if( !(to = _IPFAddrAlloc(from->ctx)))
		return NULL;

	if(from->node_set){
		strncpy(to->node,from->node,sizeof(to->node));
		to->node_set = True;
	}

	if(from->port_set){
		strncpy(to->port,from->port,sizeof(to->port));
		to->port_set = True;
	}

	to->ai_free = 1;
	aip = &to->ai;
	ai = from->ai;

	while(ai){
		*aip = _IPFCopyAddrRec(from->ctx,ai);
		if(!*aip){
			IPFAddrFree(to);
			return NULL;
		}
		if(ai->ai_addr == from->saddr){
			to->saddr = (*aip)->ai_addr;
			to->saddrlen = (*aip)->ai_addrlen;
		}

		aip = &(*aip)->ai_next;
		ai = ai->ai_next;
	}

	to->fd = from->fd;

	if(to->fd > -1)
		to->fd_user = True;

	return to;
}

int
IPFAddrFD(
	IPFAddr	addr
	)
{
	if(!addr || (addr->fd < 0))
		return -1;

	return addr->fd;
}

socklen_t
IPFAddrSockLen(
	IPFAddr	addr
	)
{
	if(!addr || !addr->saddr)
		return 0;

	return addr->saddrlen;
}

/*
 * Function:	IPFGetContext
 *
 * Description:	
 * 	Returns the context pointer that was referenced when the
 * 	given control connection was created.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
IPFContext
IPFGetContext(
	IPFControl	cntrl
	)
{
	return cntrl->ctx;
}

/*
 * Function:	IPFGetMode
 *
 * Description:	
 * 	Returns the "mode" of the control connection.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
IPFSessionMode
IPFGetMode(
	IPFControl	cntrl
	)
{
	return cntrl->mode;
}

/*
 * Function:	IPFControlFD
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
int
IPFControlFD(
	IPFControl	cntrl
	)
{
	return cntrl->sockfd;
}

/*
 * Function:	IPFGetRTTBound
 *
 * Description:	Returns a very rough estimate of the upper-bound rtt to
 * 		the server.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * 		bound or 0 if unavailable
 * Side Effect:	
 */
IPFNum64
IPFGetRTTBound(
	IPFControl	cntrl
	)
{
	return cntrl->rtt_bound;
}

/*
 * Function:	_IPFFailControlSession
 *
 * Description:	
 * 	Simple convienience to set the state and return the failure at
 * 	the same time.
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
_IPFFailControlSession(
	IPFControl	cntrl,
	int		level
	)
{
	cntrl->state = _IPFStateInvalid;
	return (IPFErrSeverity)level;
}

/*
 * Function:	_IPFTestSessionAlloc
 *
 * Description:	
 * 	This function is used to allocate/initialize the memory record used
 * 	to maintain state information about a "configured" test.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
IPFTestSession
_IPFTestSessionAlloc(
	IPFControl	cntrl,
	IPFAddr		sender,
	IPFBoolean	conf_sender,
	IPFAddr		receiver,
	IPFBoolean	conf_receiver,
	IPFTestSpec	*test_spec
)
{
	IPFTestSession	test;

	/*
	 * Address records must exist.
	 */
	if(!sender || ! receiver){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"_IPFTestSessionAlloc:Invalid Addr arg");
		return NULL;
	}

	if(!(test = calloc(1,sizeof(IPFTestSessionRec)))){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"calloc(1,IPFTestSessionRec): %M");
		return NULL;
	}

	/*
	 * Initialize address records and test description record fields.
	 */
	test->cntrl = cntrl;
	test->sender = sender;
	test->conf_sender = conf_sender;
	test->receiver = receiver;
	test->conf_receiver = conf_receiver;
	memcpy(&test->test_spec,test_spec,sizeof(IPFTestSpec));

	/*
	 * Allocate memory for slot records if they won't fit in the
	 * pre-allocated "buffer" already associated with the TestSession
	 * record. Then copy the slot records.
	 * (From the server side, slots will be 0 at this point - the
	 * SessionRecord is allocated before reading the slots off the
	 * socket so the SessionRecord slot "buffer" can potentially be used.)
	 */
	if(test->test_spec.slots){
		if(test->test_spec.nslots > _IPFSLOT_BUFSIZE){
			if(!(test->test_spec.slots =
						calloc(test->test_spec.nslots,
							sizeof(IPFSlot)))){
				IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
						"calloc(%d,IPFSlot): %M",
						test->test_spec.nslots);
				free(test);
				return NULL;
			}
		}else{
			test->test_spec.slots = test->slot_buffer;
		}
		memcpy(test->test_spec.slots,test_spec->slots,
					test_spec->nslots*sizeof(IPFSlot));
	}

	return test;
}

/*
 * Function:	_IPFTestSessionFree
 *
 * Description:	
 * 	This function is used to free the memory associated with a "configured"
 * 	test session.
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
_IPFTestSessionFree(
	IPFTestSession	tsession,
	IPFAcceptType	aval
)
{
	IPFTestSession	*sptr;
	IPFErrSeverity	err=IPFErrOK;

	if(!tsession){
		return IPFErrOK;
	}

	/*
	 * remove this tsession from the cntrl->tests lists.
	 */
	for(sptr = &tsession->cntrl->tests;*sptr;sptr = &(*sptr)->next){
		if(*sptr == tsession){
			*sptr = tsession->next;
			break;
		}
	}

	if(tsession->endpoint){
		(void)_IPFEndpointStop(tsession->endpoint,aval,&err);
	}

	if(tsession->closure){
		_IPFCallTestComplete(tsession,aval);
	}

	IPFAddrFree(tsession->sender);
	IPFAddrFree(tsession->receiver);

	if(tsession->sctx){
		IPFScheduleContextFree(tsession->sctx);
	}

	if(tsession->test_spec.slots &&
			(tsession->test_spec.slots != tsession->slot_buffer)){
		free(tsession->test_spec.slots);
	}

	free(tsession);

	return err;
}


/*
 * Function:	_IPFCreateSID
 *
 * Description:	
 * 	Generate a "unique" SID from addr(4)/time(8)/random(4) values.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * 	0 on success
 * Side Effect:	
 */
int
_IPFCreateSID(
	IPFTestSession	tsession
	)
{
	IPFTimeStamp	tstamp;
	u_int8_t	*aptr;

#ifdef	AF_INET6
	if(tsession->receiver->saddr->sa_family == AF_INET6){
		struct sockaddr_in6	*s6;

		s6 = (struct sockaddr_in6*)tsession->receiver->saddr;
		/* point at last 4 bytes of addr */
		aptr = &s6->sin6_addr.s6_addr[12];
	}else
#endif
	if(tsession->receiver->saddr->sa_family == AF_INET){
		struct sockaddr_in	*s4;

		s4 = (struct sockaddr_in*)tsession->receiver->saddr;
		aptr = (u_int8_t*)&s4->sin_addr;
	}
	else{
		IPFError(tsession->cntrl->ctx,IPFErrFATAL,IPFErrUNSUPPORTED,
				"_IPFCreateSID:Unknown address family");
		return 1;
	}

	memcpy(&tsession->sid[0],aptr,4);

	(void)IPFGetTimeOfDay(&tstamp);
	_IPFEncodeTimeStamp(&tsession->sid[4],&tstamp);

	if(I2RandomBytes(tsession->cntrl->ctx->rand_src,&tsession->sid[12],4)
									!= 0){
		return 1;
	}

	return 0;
}

IPFErrSeverity
IPFStopSessions(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	*acceptval_ret	/* in/out	*/
		)
{
	IPFErrSeverity	err,err2=IPFErrOK;
	IPFRequestType	msgtype;
	IPFAcceptType	aval=IPF_CNTRL_ACCEPT;
	IPFAcceptType	*acceptval=&aval;
	int		ival=0;
	int		*intr=&ival;

	if(acceptval_ret){
		acceptval = acceptval_ret;
	}

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * TODO: v6 - fetch "last" sequence sent/received for encoding
	 * in StopSession message.
	 * (To do this - this loop needs to call "stop" on each endpoint,
	 * but not free the structures. Somehow "stop" needs to fetch the
	 * last sequence number from the endpoint when it exits. Receive
	 * is easy... Send it not as simple. Should I create a socketpair
	 * before forking off sender endpoints so the last seq number
	 * can be sent up the pipe?)
	 */

	while(cntrl->tests){
		err = _IPFTestSessionFree(cntrl->tests,*acceptval);
		err2 = MIN(err,err2);
	}

	/*
	 * If acceptval would have been "success", but stopping of local
	 * endpoints failed, send failure acceptval instead and return error.
	 * (The endpoint_stop_func should have reported the error.)
	 */
	if(!*acceptval && (err2 < IPFErrWARNING)){
		*acceptval = IPF_CNTRL_FAILURE;
	}

	err = (IPFErrSeverity)_IPFWriteStopSessions(cntrl,intr,*acceptval);
	if(err < IPFErrWARNING)
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	err2 = MIN(err,err2);

	msgtype = IPFReadRequestType(cntrl,intr);
	if(msgtype == IPFReqSockClose){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
				"IPFStopSessions:Control socket closed: %M");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}
	if(msgtype != IPFReqStopSessions){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid protocol message received...");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	err = _IPFReadStopSessions(cntrl,acceptval,intr);

	/*
	 * TODO: v6 - use "last seq number" messages from
	 * in StopSession message to remove "missing" packets from the
	 * end of session files. The "last seq number" in the file should
	 * be MIN(last seq number sent,last seq number in file{missing or not}).
	 */

	cntrl->state &= ~_IPFStateTest;

	return MIN(err,err2);
}

IPFPacketSizeT
IPFTestPayloadSize(
		IPFSessionMode	mode, 
		u_int32_t	padding
		)
{
	IPFPacketSizeT msg_size;

	switch (mode) {
	case IPF_MODE_OPEN:
		msg_size = 14;
		break;
	case IPF_MODE_AUTHENTICATED:
	case IPF_MODE_ENCRYPTED:
		msg_size = 32;
		break;
	default:
		return 0;
		/* UNREACHED */
	}

	return msg_size + padding;
}

/*
 * Function:	IPFTestPacketRate
 *
 * Description:	
 * 	This function returns the # packets/ second as a double.
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
IPFTestPacketRate(
	IPFContext	ctx,
	IPFTestSpec	*tspec
		)
{
	IPFNum64	duration = IPFULongToNum64(0);
	u_int32_t	i;

	if(!tspec){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFTestPacketRate: Invalid tspec arg");
		return 0;
	}

	if(!tspec->nslots || !tspec->slots){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
			"IPFTestPacketRate: Invalid empty test specification");
		return 0;
	}

	for(i=0;i<tspec->nslots;i++){
		duration = IPFNum64Add(duration,tspec->slots[i].any.mean_delay);
	}

	return (double)tspec->nslots / IPFNum64ToDouble(duration);
}

/* These lengths assume no IP options. */
#define IPF_IP4_HDR_SIZE	20	/* rfc 791 */
#define IPF_IP6_HDR_SIZE	40	/* rfc 2460 */
#define IPF_UDP_HDR_SIZE	8	/* rfc 768 */

/*
** Given the protocol family, OWAMP mode and packet padding,
** compute the size of resulting full IP packet.
*/
IPFPacketSizeT
IPFTestPacketSize(
		int		af,    /* AF_INET, AF_INET6 */
		IPFSessionMode	mode, 
		u_int32_t	padding
		)
{
	IPFPacketSizeT payload_size, header_size;

	switch (af) {
	case AF_INET:
		header_size = IPF_IP4_HDR_SIZE + IPF_UDP_HDR_SIZE;
		break;
	case AF_INET6:
		header_size = IPF_IP6_HDR_SIZE + IPF_UDP_HDR_SIZE;
		break;
	default:
		return 0;
		/* UNREACHED */
	}

	if(!(payload_size = IPFTestPayloadSize(mode,padding)))
			return 0;

	return payload_size + header_size;
}

/*
 * Function:	IPFTestPacketBandwidth
 *
 * Description:	
 * 	returns the average bandwidth requirements of the given test using
 * 	the given address family, and authentication mode.
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
IPFTestPacketBandwidth(
	IPFContext	ctx,
	int		af,
	IPFSessionMode	mode, 
	IPFTestSpec	*tspec
	)
{
	if(!tspec){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFTestPacketBandwidth: Invalid tspec arg");
		return 0;
	}

	return IPFTestPacketRate(ctx,tspec) *
			IPFTestPacketSize(af,mode,tspec->packet_size_padding);
}

/*
 * Function:	IPFSessionStatus
 *
 * Description:	
 * 	This function returns the "status" of the test session identified
 * 	by the sid. "send" indicates which "side" of the test to retrieve
 * 	information about.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	True if status was available, False otherwise.
 * 		aval contains the actual "status":
 * 			<0	Test is not yet complete
 * 			>=0	Valid IPFAcceptType - see enum for meaning.
 * Side Effect:	
 */
IPFBoolean
IPFSessionStatus(
		IPFControl	cntrl,
		IPFSID		sid,
		IPFAcceptType	*aval
		)
{
	IPFTestSession	tsession;
	IPFErrSeverity	err;

	/*
	 * First find the tsession record for this test.
	 */
	for(tsession=cntrl->tests;tsession;tsession=tsession->next)
		if(memcmp(sid,tsession->sid,sizeof(IPFSID)) == 0)
			goto found;

	return False;

found:
	if(tsession->endpoint){
		return _IPFEndpointStatus(tsession->endpoint,aval,&err);
	}

	return False;
}

int
IPFSessionsActive(
		IPFControl	cntrl,
		IPFAcceptType	*aval
		)
{
	IPFTestSession	tsession;
	IPFAcceptType	laval;
	IPFAcceptType	raval = 0;
	int		n=0;
	IPFErrSeverity	err;

	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if((tsession->endpoint) &&
				_IPFEndpointStatus(tsession->endpoint,
								&laval,&err)){
			if(laval < 0)
				n++;
			else
				raval = MAX(laval,raval);
		}
	}

	if(aval)
		*aval = raval;

	return n;
}

int
IPFStopSessionsWait(
	IPFControl	cntrl,
	IPFNum64	*wake,
	int		*retn_on_intr,
	IPFAcceptType	*acceptval_ret,
	IPFErrSeverity	*err_ret
	)
{
	struct timeval	currtime;
	struct timeval	reltime;
	struct timeval	*waittime = NULL;
	fd_set		readfds;
	fd_set		exceptfds;
	int		rc;
	int		msgtype;
	IPFErrSeverity	err2=IPFErrOK;
	IPFAcceptType	aval;
	IPFAcceptType	*acceptval=&aval;
	int		ival=0;
	int		*intr=&ival;

	*err_ret = IPFErrOK;
	if(acceptval_ret){
		acceptval = acceptval_ret;
	}
	*acceptval = IPF_CNTRL_ACCEPT;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if(!cntrl || cntrl->sockfd < 0){
		*err_ret = IPFErrFATAL;
		return -1;
	}

	/*
	 * If there are no active sessions, get the status and return.
	 */
	if(!IPFSessionsActive(cntrl,acceptval) || (*acceptval)){
		/*
		 * Sessions are complete - send StopSessions message.
		 */
		*err_ret = IPFStopSessions(cntrl,intr,acceptval);
		return 0;
	}

	if(wake){
		IPFTimeStamp	wakestamp;

		/*
		 * convert abs wake time to timeval
		 */
		wakestamp.ipftime = *wake;
		IPFTimestampToTimeval(&reltime,&wakestamp);

		/*
		 * get current time.
		 */
		if(gettimeofday(&currtime,NULL) != 0){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"gettimeofday():%M");
			return -1;
		}

		/*
		 * compute relative wake time from current time and abs wake.
		 */
		if(tvalcmp(&currtime,&reltime,<)){
			tvalsub(&reltime,&currtime);
		}
		else{
			tvalclear(&reltime);
		}

		waittime = &reltime;
	}


	FD_ZERO(&readfds);
	FD_SET(cntrl->sockfd,&readfds);
	FD_ZERO(&exceptfds);
	FD_SET(cntrl->sockfd,&exceptfds);
AGAIN:
	rc = select(cntrl->sockfd+1,&readfds,NULL,&exceptfds,waittime);

	if(rc < 0){
		if(errno != EINTR){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"select():%M");
			*err_ret = IPFErrFATAL;
			return -1;
		}
		if(waittime || *intr){
			return 2;
		}

		/*
		 * If there are tests still happening, and no tests have
		 * ended in error - go back to select and wait for the
		 * rest of the tests to complete.
		 */
		if(IPFSessionsActive(cntrl,acceptval) && !*acceptval){
			goto AGAIN;
		}

		/*
		 * Sessions are complete - send StopSessions message.
		 */
		*err_ret = IPFStopSessions(cntrl,intr,acceptval);

		return 0;
	}
	if(rc == 0)
		return 1;

	if(!FD_ISSET(cntrl->sockfd,&readfds) &&
					!FD_ISSET(cntrl->sockfd,&exceptfds)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"select():cntrl fd not ready?:%M");
		*err_ret = _IPFFailControlSession(cntrl,IPFErrFATAL);
		return -1;
	}

	msgtype = IPFReadRequestType(cntrl,intr);
	if(msgtype == 0){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
			"IPFStopSessionsWait: Control socket closed: %M");
		*err_ret = _IPFFailControlSession(cntrl,IPFErrFATAL);
		return -1;
	}
	if(msgtype != 3){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid protocol message received...");
		*err_ret = _IPFFailControlSession(cntrl,IPFErrFATAL);
		return -1;
	}

	*err_ret = _IPFReadStopSessions(cntrl,intr,acceptval);
	if(*err_ret != IPFErrOK){
		cntrl->state = _IPFStateInvalid;
		return -1;
	}

	while(cntrl->tests){
		err2 = _IPFTestSessionFree(cntrl->tests,*acceptval);
		*err_ret = MIN(*err_ret,err2);
	}

	if(*err_ret < IPFErrWARNING){
		*acceptval = IPF_CNTRL_FAILURE;
	}

	err2 = _IPFWriteStopSessions(cntrl,intr,*acceptval);
	cntrl->state &= ~_IPFStateTest;

	*err_ret = MIN(*err_ret, err2);
	return 0;
}

/*
 * Function:	IPFAddrNodeName
 *
 * Description:	
 * 	This function gets a char* node name for a given IPFAddr.
 * 	The len parameter is an in/out parameter.
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
IPFAddrNodeName(
	IPFAddr	addr,
	char	*buf,
	size_t	*len
	)
{
	assert(buf);
	assert(len);
	assert(*len > 0);

	if(!addr){
		goto bail;
	}

	if(!addr->node_set && addr->saddr &&
			getnameinfo(addr->saddr,addr->saddrlen,
				addr->node,sizeof(addr->node),
				addr->port,sizeof(addr->port),
				NI_NUMERICHOST|NI_NUMERICSERV) == 0){
		addr->node_set = 1;
		addr->port_set = 1;
	}

	if(addr->node_set){
		*len = MIN(*len,sizeof(addr->node));
		strncpy(buf,addr->node,*len);
		return;
	}

bail:
	*len = 0;
	buf[0] = '\0';
	return;
}

/*
 * Function:	IPFAddrNodeService
 *
 * Description:	
 * 	This function gets a char* service name for a given IPFAddr.
 * 	The len parameter is an in/out parameter.
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
IPFAddrNodeService(
	IPFAddr	addr,
	char	*buf,
	size_t	*len
	)
{
	assert(buf);
	assert(len);
	assert(*len > 0);

	if(!addr){
		goto bail;
	}

	if(!addr->port_set && addr->saddr &&
			getnameinfo(addr->saddr,addr->saddrlen,
				addr->node,sizeof(addr->node),
				addr->port,sizeof(addr->port),
				NI_NUMERICHOST|NI_NUMERICSERV) == 0){
		addr->node_set = 1;
		addr->port_set = 1;
	}

	if(addr->port_set){
		*len = MIN(*len,sizeof(addr->port));
		strncpy(buf,addr->port,*len);
		return;
	}

bail:
	*len = 0;
	buf[0] = '\0';
	return;
}

/*
 * Functions for writing and reading headers. The format varies
 * according to the version. In all cases the files starts
 * with 4 bytes of magic number, 4 bytes of version, and
 * 4 bytes of total header length (version and header length
 * fields given in network byte order). The rest depends on
 * the version as follows:
 *
 * Version 0: nothing - data records follow "hdr length".
 * Version 2: Session Request as per version 5 of the protocol (use hdr len
 * 	to skip session request, or read it using the format described
 * 	below. (All values are in network byte order.)
 *
 * File format is as follows:
 *
 * 
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|       "O"     |       "w"     |       "A"     |       \0      |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                        Version                                |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                      hdr length (unsigned 64bit)              |
 *	12|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                        Finished                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	20|                                                               |
 *	  ...                 TestRequestPreamble (protocol.c)          ...
 *     128|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     132|	                                                          |
 *     136|                   Slot(1) definitions (16 octets each)        |
 *     140|                                                               |
 *     144|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     148:(148+(16*(nslots-1)) (16 octets for each additional slot)
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	  |                                                               |
 *	  |                   Zero Integrity Padding (16 octets)          |
 *	  |                                                               |
 *	  |                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Then individual packet records start. (hdr_len should point to here.)
 * The format for individual packet records is:
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                   Sequence Number                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                                                               |
 *	08|                   Send Timestamp                              |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	12|  Send Error Estimate          |                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *	16|                   Recv Timestamp                              |
 *	  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	20|                               |       Recv Error Estimate     |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/*
 * Function:	IPFWriteDataHeader
 *
 * Description:	
 *	Write data header to the file.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
int
IPFWriteDataHeader(
	IPFContext		ctx,
	FILE			*fp,
	IPFSessionHeader	hdr
	)
{
	static char	magic[] = _IPF_MAGIC_FILETYPE;
	u_int32_t	ver;
	u_int32_t	finished = 2; /* 2 means unknown */
	u_int64_t	hdr_len;
	u_int64_t	hdr_len_net;
	u_int8_t	*ptr;
	off_t		hdr_off;
			/* use u_int32_t for proper alignment */
	u_int32_t	msg[_IPF_TEST_REQUEST_PREAMBLE_SIZE/sizeof(u_int32_t)];
	u_int32_t	len = sizeof(msg);
	u_int32_t	i;

	if(hdr){
		if(_IPFEncodeTestRequestPreamble(ctx,msg,&len,
				(struct sockaddr*)&hdr->addr_sender,
				(struct sockaddr*)&hdr->addr_receiver,
				hdr->conf_sender,hdr->conf_receiver,
				hdr->sid,&hdr->test_spec) != 0){
			return 1;
		}
		ver = htonl(2);
		/*
		 * Compute the offset to the data records:
		 * 	MAGIC+Version+HdrLen+Finished+TestRequestPramble+Slots
		 */
		hdr_len = sizeof(magic)+sizeof(ver)+sizeof(hdr_len)+
			sizeof(finished)+len+16*(hdr->test_spec.nslots+1);
	}
	else{
		len = 0;
		ver = htonl(0);
		hdr = NULL;
		hdr_len = sizeof(magic)+sizeof(ver)+sizeof(hdr_len);
	}


	hdr_off = (off_t)hdr_len;
	if(hdr_len != (u_int64_t)hdr_off){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
	"IPFWriteDataHeader: Header too large for format representation (%llu)",
							hdr_len);
		return 1;
	}
	ptr = (u_int8_t*)&hdr_len_net;
	/*
	 * copy low-order word (net order) to last 4 bytes of hdr_len_net
	 */
	*(u_int32_t*)&ptr[4] = htonl((hdr_len & 0xFFFFFFFFUL));
	/*
	 * copy high-order word (net order) to first 4 bytes of hdr_len_net
	 */
	hdr_len >>= 32;
	*(u_int32_t*)&ptr[0] = htonl((hdr_len & 0xFFFFFFFFUL));

	/*
	 * write magic
	 */
	if(fwrite(magic, 1, sizeof(magic), fp) != sizeof(magic)){
		return 1;
	}

	/*
	 * write version
	 */
	if(fwrite(&ver, 1, sizeof(ver), fp) != sizeof(ver)){
		return 1;
	}

	/*
	 * write hdr_len - first high order word, then low order word.
	 * Each word in network byte order.
	 */
	if(fwrite(&hdr_len_net,1,sizeof(hdr_len_net),fp)!=sizeof(hdr_len_net)){
		return 1;
	}

	/*
	 * write dynmic header
	 */
	if(len > 0){
		/*
		 * write finished
		 */
		if(hdr){
			switch(hdr->finished){
				case 0:
				case 1:
					finished = hdr->finished;
					break;
				default:
					break;
			}
		}
		finished = htonl(finished);
		if(fwrite(&finished,1,sizeof(finished),fp) != sizeof(finished)){
			return 1;
		}

		/*
		 * write TestRequest preamble
		 */
		if(fwrite(msg,1,len,fp) != len){
			return 1;
		}

		/*
		 * write slots
		 */
		for(i=0;i<hdr->test_spec.nslots;i++){
			/*
			 * Each slot is one block (16 bytes)
			 */
			if(_IPFEncodeSlot(msg,&hdr->test_spec.slots[i]) !=
								IPFErrOK){
				IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFWriteDataHeader: Invalid slot record");
				return 1;
			}
			if(fwrite(msg,1,16,fp) != 16){
				return 1;
			}
		}
		/*
		 * write 16 Zero Integrity bytes
		 */
		memset(msg,0,16);
		if(fwrite(msg,1,16,fp) != 16){
			return 1;
		}
	}

	fflush(fp);
	return 0;
}

/*
 * Function:	IPFTestDiskspace
 *
 * Description:	
 * 	Returns the size of file a given testspec will require.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
u_int64_t
IPFTestDiskspace(
	IPFTestSpec	*tspec
	)
{
	static char	magic[] = _IPF_MAGIC_FILETYPE;
	u_int32_t	ver;
	u_int32_t	finished;
	u_int64_t	hdr_len;

	hdr_len = sizeof(magic)+sizeof(ver)+sizeof(hdr_len)+
			sizeof(finished)+_IPF_TEST_REQUEST_PREAMBLE_SIZE+
			16*(tspec->nslots+1);
	return hdr_len + tspec->npackets*_IPF_TESTREC_SIZE;
}

/*
 * Function:	_IPFWriteDataHeaderFinished
 *
 * Description:	
 *	Write a new "finished" word into the file. This function seeks to
 *	the correct offset for a version 2 file.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
int
_IPFWriteDataHeaderFinished(
	IPFContext		ctx,
	FILE			*fp,
	u_int32_t		finished
	)
{
	int		err;
	off_t		offset;
	static char	magic[] = _IPF_MAGIC_FILETYPE;
	u_int32_t	ver;
	u_int64_t	hdr_len;

	if(finished > 2){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
			"_IPFWriteDataHeaderFinished: Invalid \"finished\"");
		return 1;
	}

	if(fflush(fp) != 0){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fflush(): %M");
		errno = err;
		return 1;
	}

	offset = sizeof(magic)+sizeof(ver)+sizeof(hdr_len);
	if(fseeko(fp,offset,SEEK_SET)){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fseeko(): %M");
		errno = err;
		return 1;
	}

	finished = htonl(finished);
	if(fwrite(&finished,1,sizeof(finished),fp) != sizeof(finished)){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fwrite(): %M");
		errno = err;
		return 1;
	}

	if(fflush(fp) != 0){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fflush(): %M");
		errno = err;
		return 1;
	}

	return 0;
}

/*
 * Function:	IPFWriteDataRecord
 *
 * Description:	
 * 	Write a single data record described by rec to file fp.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
int
IPFWriteDataRecord(
	IPFContext	ctx,
	FILE		*fp,
	IPFDataRec	*rec
	)
{
	u_int8_t	buf[_IPF_TESTREC_SIZE];

	if(!_IPFEncodeDataRecord(buf,rec)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"IPFWriteDataRecord: Unable to encode data record");
		return -1;
	}

	/*
	 * write data record
	 */
	if(fwrite(buf,1,_IPF_TESTREC_SIZE,fp) != _IPF_TESTREC_SIZE){
		IPFError(ctx,IPFErrFATAL,errno,
			"IPFWriteDataRecord: fwrite(): %M");
		return -1;
	}

	return 0;
}

/*
 * Function:	_IPFReadDataHeaderInitial
 *
 * Description:	
 * 	Read the "header" of the ipf file and determine the layout
 * 	and validity of the file.
 * 	The fp will be placed at the beginning of the TestRequest
 * 	data for version 2 files, and at the beginning of the data records
 * 	for version 0 files.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	non-zero on failure (errno will be set too.)
 * Side Effect:	
 */
int
_IPFReadDataHeaderInitial(
	IPFContext	ctx,
	FILE		*fp,
	u_int32_t	*ver,
	u_int32_t	*fin,
	off_t		*hdr_off,
	struct stat	*stat_buf
	)
{
	static char	magic[] = _IPF_MAGIC_FILETYPE;
	char		read_magic[sizeof(magic)];
	u_int64_t	hlen,hlen_net;
	u_int8_t	*ptr;
	u_int32_t	t32;
	int		err;
	off_t		treq_size;

	/*
	 * Stat the file to get the size and check that it is really there.
	 */
	if(fstat(fileno(fp),stat_buf) < 0){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fstat(): %M");
		errno = err;
		return 1;
	}

	/*
	 * Position fp to beginning of file.
	 */
	if(fseeko(fp,0,SEEK_SET)){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fseeko(): %M");
		errno = err;
		return 1;
	}

	/*
	 * File must be at least as big as the initial header information.
	 * 16 bytes is magic+version+hdr_length
	 */
	if(stat_buf->st_size < (off_t)16){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"_IPFReadDataHeaderInitial: Invalid ipf file");
		/*
		 * TODO: Check validity of this errno... May need to
		 * use ENOSYS...
		 */
		errno = EFTYPE;
		return 1;
	}

	/*
	 * Read and check "magic".
	 * 4 bytes
	 */
	if(fread(read_magic, 1, 4, fp) != 4){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fread(): %M");
		errno = err;
		return 1;
	}
	if(memcmp(read_magic,magic,4) != 0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
		"_IPFReadDataHeaderInitial: Invalid ipf file:wrong magic");
		/*
		 * TODO: Check validity of this errno... May need to
		 * use ENOSYS...
		 */
		errno = EFTYPE;
		return 1;
	}

	/*
	 * Get the file "version".
	 * 4 byte "network long" quantity
	 */
	if(fread(ver, 1, 4, fp) != 4){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fread(): %M");
		errno = err;
		return 1;
	}
	*ver = ntohl(*ver);

	/*
	 * This code only supports version 0 and 2 ipf files.
	 */
	if((*ver != 0) && (*ver != 2)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
		"_IPFReadDataHeaderInitial: Unknown file version (%d)",*ver);
		errno = ENOSYS;
		return 1;
	}

	/*
	 * Read the header length. 8 byte/64 bit field. network byte order.
	 * (Defined by rfc791 - Appendix B.)
	 */
	if(fread(&hlen_net, 1, 8, fp) != 8){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fread(): %M");
		errno = err;
		return 1;
	}

	/*
	 * - Decode the 64 bit header length -
	 *
	 * ptr will use hlen_net as a 64 bit buffer.
	 */
	ptr = (u_int8_t*)&hlen_net;

	/*
	 * High order 4 bytes
	 */
	t32 = ntohl(*(u_int32_t*)&ptr[0]);
	hlen = t32 & 0xFFFFFFFF;
	hlen <<= 32;
	/*
	 * Low order 4 bytes
	 */
	t32 = ntohl(*(u_int32_t*)&ptr[4]);
	hlen |= (t32 & 0xFFFFFFFF);

	/*
	 * place 64 bit data in off_t variable - then ensure the value is
	 * representable on this system.
	 */
	*hdr_off = (off_t)hlen;
	if(hlen != (u_int64_t)*hdr_off){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"_IPFReadDataHeaderInitial: Header too larger (%llu)",
			hlen);
		/*
		 * TODO: Check validity of this errno... May need to
		 * use ENOSYS...
		 */
		errno = EOVERFLOW;
		return 1;
	}

	if(*ver != 0){
		/*
		 * Get the file "finished" status. Just tells us what
		 * the recv process thought about the status.
		 * 0: questionable termination
		 * 1: completed normal test
		 * 2: in-progress or unknown (recv died?)
		 *
		 * 4 byte "network long" quantity
		 */
		if(fread(fin,1,4,fp) != 4){
			err = errno;
			IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fread(): %M");
			errno = err;
			return 0;
		}
		*fin = ntohl(*fin);
		/*
		 * Compute the size for the test req portion within the file for
		 * a sanity check. 20 offset to begining of TestRequest.
		 */
		treq_size = *hdr_off - 20;
	}
	else{
		*fin = 2; /* unknown */
		treq_size = 0;
	}


	/*
	 * Ensure the file is valid with respect to the reported header
	 * size.
	 */
	if((*hdr_off > stat_buf->st_size) ||
					(treq_size % _IPF_RIJNDAEL_BLOCK_SIZE)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"_IPFReadDataHeaderInitial: corrupt header");
		/*
		 * TODO: Check validity of this errno... May need to
		 * use ENOSYS...
		 */
		errno = EFTYPE;
		return 1;
	}

	return 0;
}

/*
 * Function:	IPFReadDataHeader
 *
 * Description:	
 * Version 0: nothing - data records follow.
 * Version 2: Session Request as per version 5 of the protocol
 * 	This function does NOT read the slots into the hdr_ret->test_spec.
 * 	A separate function IPFReadDataHeaderSlots has been provided to do
 * 	that. (Memory for the slots must be provided by the caller.)
 *
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
u_int32_t
IPFReadDataHeader(
	IPFContext		ctx,
	FILE			*fp,
	off_t			*hdr_len,
	IPFSessionHeader	hdr_ret
	)
{
	int		err;
	u_int32_t	ver;
	u_int32_t	fin;
	off_t		hdr_off;
	struct stat	stat_buf;
			/* buffer for TestRequest 32 bit aligned */
	u_int32_t	msg[_IPF_TEST_REQUEST_PREAMBLE_SIZE/sizeof(u_int32_t)];

	if(hdr_len)
		*hdr_len = 0;
	if(hdr_ret)
		hdr_ret->header = 0;

	if(_IPFReadDataHeaderInitial(ctx,fp,&ver,&fin,&hdr_off,&stat_buf)){
		return 0;
	}

	/*
	 * return hdr_off in hdr_len if it is not NULL.
	 */
	if(hdr_len)
		*hdr_len = hdr_off;

	/*
	 * Decode the header if present(version 2), and wanted (hdr_ret).
	 */
	if((ver==2) && hdr_ret){

		hdr_ret->finished = fin;

		/*
		 * read TestRequestPreamble
		 */
		if(fread(msg,1,_IPF_TEST_REQUEST_PREAMBLE_SIZE,fp) !=
					_IPF_TEST_REQUEST_PREAMBLE_SIZE){
			err = errno;
			IPFError(ctx,IPFErrFATAL,errno,"fread(): %M");
			errno = err;
			return 0;
		}

		hdr_ret->addr_len = sizeof(hdr_ret->addr_sender);
		/*
		 * Now decode it into the hdr_ret variable.
		 */
		if(_IPFDecodeTestRequestPreamble(ctx,msg,
				_IPF_TEST_REQUEST_PREAMBLE_SIZE,
				(struct sockaddr*)&hdr_ret->addr_sender,
				(struct sockaddr*)&hdr_ret->addr_receiver,
				&hdr_ret->addr_len,&hdr_ret->ipvn,
				&hdr_ret->conf_sender,&hdr_ret->conf_receiver,
				hdr_ret->sid,&hdr_ret->test_spec) != IPFErrOK){
			/*
			 * TODO: Check validity of this errno... May need to
			 * use ENOSYS...
			 */
			errno = EFTYPE;
			return 0;
		}

		hdr_ret->header = True;
	}

	if(hdr_ret){
		hdr_ret->version = ver;
		hdr_ret->rec_size = _IPF_TESTREC_SIZE;
	}

	/*
	 * Forward fp to data records.
	 */
	if(fseeko(fp,hdr_off,SEEK_SET)){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fseeko(): %M");
		errno = err;
		return 0;
	}
	return (stat_buf.st_size-hdr_off)/_IPF_TESTREC_SIZE;
}

/*
 * Function:	IPFReadDataHeaderSlots
 *
 * Description:	
 * 	This function will read all the slot records out of the
 * 	file fp. slots is assumed to be an array of IPFSlot records of
 * 	length nslots.
 *
 * 	This function will position the fp to the beginning of the data
 * 	records.
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
IPFReadDataHeaderSlots(
	IPFContext		ctx,
	FILE			*fp,
	u_int32_t		nslots,
	IPFSlot			*slots
	)
{
	int		err;
	u_int32_t	ver;
	u_int32_t	fin;
	u_int32_t	fileslots;
	u_int32_t	i;
	off_t		hdr_off;
	off_t		slot_off = 132; /* see above layout of bytes */
	struct stat	stat_buf;
			/* buffer for Slots 32 bit aligned */
	u_int32_t	msg[16/sizeof(u_int32_t)];
	u_int32_t	zero[16/sizeof(u_int32_t)];

	/*
	 * validate array.
	 */
	assert(slots);

	/*
	 * Stat the file and get the "initial" fields from the header.
	 */
	if(_IPFReadDataHeaderInitial(ctx,fp,&ver,&fin,&hdr_off,&stat_buf)){
		return 0;
	}

	/*
	 * this function is currently only supported for version 2 files.
	 */
	if(ver != 2){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"IPFReadDataHeaderSlots: Invalid file version (%d)",
			ver);
		errno = ENOSYS;
		return IPFErrFATAL;
	}

	/*
	 * validate nslots passed in with what is in the file.
	 * hdr_off should point to the offset in the file where the slots
	 * are finished and the 1 block of zero padding is finished.
	 */
	fileslots = hdr_off - slot_off; /* bytes for slots */

	/*
	 * bytes for slots/zero padding must be of block size 16
	 */
	if(fileslots%16){
		IPFError(ctx,IPFErrFATAL,EINVAL,
			"IPFReadDataHeaderSlots: Invalid hdr_offset (%llu)",
			hdr_off);
		/*
		 * TODO: Check validity of this errno... May need to
		 * use ENOSYS...
		 */
		errno = EFTYPE;
		return IPFErrFATAL;
	}

	/*
	 * Convert bytes to number of slots. Divide by block size, then
	 * subtract 1 for zero integrity block.
	 */
	fileslots/=16;
	fileslots--;

	if(fileslots != nslots){
		IPFError(ctx,IPFErrFATAL,EINVAL,
"IPFReadDataHeaderSlots: nslots mismatch with file: fileslots(%d), nslots(%d)",
			fileslots,nslots);
		/*
		 * TODO: Check validity of this errno... May need to
		 * use ENOSYS...
		 */
		errno = EINVAL;
		return IPFErrFATAL;
	}

	/*
	 * Position fp to beginning of slot records.
	 */
	if(fseeko(fp,slot_off,SEEK_SET)){
		err = errno;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fseeko(): %M");
		errno = err;
		return IPFErrFATAL;
	}

	for(i=0;i<nslots;i++){
		
		/*
		 * Read slot into buffer.
		 */
		if(fread(msg,1,16,fp) != 16){
			err = errno;
			IPFError(ctx,IPFErrFATAL,errno,"fread(): %M");
			errno = err;
			return IPFErrFATAL;
		}

		/*
		 * Decode slot buffer into slot record.
		 */
		if(_IPFDecodeSlot(&slots[i],msg) != IPFErrOK){
			IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"IPFReadDataHeaderSlots: Invalid Slot record");
			errno = EFTYPE;
			return IPFErrFATAL;
		}
	}

	/*
	 * Read block of Zero Integrity bytes into buffer.
	 */
	if(fread(msg,1,16,fp) != 16){
		err = errno;
		IPFError(ctx,IPFErrFATAL,errno,"fread(): %M");
		errno = err;
		return IPFErrFATAL;
	}

	/*
	 * check to make sure Zero bytes are zero.
	 */
	memset(zero,0,16);
	if(memcmp(zero,msg,16) != 0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"IPFReadDataHeaderSlots: Invalid zero padding");
		errno = EFTYPE;
		return IPFErrFATAL;
	}

	return IPFErrOK;
}

/*
 * Function:	IPFParseRecords
 *
 * Description:	
 * 	Fetch num_rec records from disk calling the record proc function
 * 	on each record.
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
IPFParseRecords(
	IPFContext		ctx,
	FILE			*fp,
	u_int32_t		num_rec,
	u_int32_t		file_version,
	IPFDoDataRecord		proc_rec,
	void			*app_data
	)
{
	u_int8_t	rbuf[_IPF_TESTREC_SIZE];
	u_int32_t	i;
	IPFDataRec	rec;
	int		rc;

	/*
	 * Someday this function may need to deal with multiple datafile
	 * versions. Currently it only supports 0 and 2. (both of which
	 * require the same 24 octet data records.)
	 */
	if((file_version != 0) && (file_version != 2)){
		IPFError(ctx,IPFErrFATAL,EINVAL,
				"IPFParseRecords: Invalid file version (%d)",
				file_version);
		return IPFErrFATAL;
	}

	for(i=0;i<num_rec;i++){
		if(fread(rbuf,_IPF_TESTREC_SIZE,1,fp) < 1){
			if(ferror(fp)){
				IPFError(ctx,IPFErrFATAL,errno,
				"fread(): STREAM ERROR: offset=%llu,i=%lu",
					ftello(fp),i);
			}
			else if(feof(fp)){
				IPFError(ctx,IPFErrFATAL,errno,
					"fread(): EOF: offset=%llu",ftello(fp));
			}
			return IPFErrFATAL;
		}
		if(!_IPFDecodeDataRecord(&rec,rbuf)){
			errno = EFTYPE;
			IPFError(ctx,IPFErrFATAL,errno,
				"IPFParseRecords: Invalid Data Record: %M");
			return IPFErrFATAL;
		}
		rc = proc_rec(&rec,app_data);
		if(!rc) continue;
		if(rc < 0)
			return IPFErrFATAL;
		return IPFErrOK;

	}

	return IPFErrOK;
}

/*
 * Function:	IPFIsLostRecord
 *
 * Description:	
 * 	Returns true if the given DataRec indicates a "lost" packet. This
 * 	is determined by looking at the recv timestamp. If it is a string
 * 	of zero bits, then it is lost.
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
IPFIsLostRecord(
	IPFDataRec *rec
	)
{
	return !rec->recv.ipftime;
}
