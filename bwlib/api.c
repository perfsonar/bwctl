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

#include "./bwlibP.h"

#ifndef EFTYPE
#define	EFTYPE	ENOSYS
#endif

BWLAddr
_BWLAddrAlloc(
	BWLContext	ctx
)
{
	BWLAddr	addr = calloc(1,sizeof(struct BWLAddrRec));

	if(!addr){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
			":calloc(1,%d):%M",sizeof(struct BWLAddrRec));
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

BWLErrSeverity
BWLAddrFree(
	BWLAddr	addr
)
{
	BWLErrSeverity	err = BWLErrOK;

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
			BWLError(addr->ctx,BWLErrWARNING,
					errno,":close(%d)",addr->fd);
			err = BWLErrWARNING;
		}
	}

	free(addr);

	return err;
}

BWLAddr
BWLAddrByNode(
	BWLContext	ctx,
	const char	*node
)
{
	BWLAddr		addr;
	char		buff[MAXHOSTNAMELEN+1];
	const char	*nptr=node;
	char		*pptr=NULL;
	char		*s1,*s2;

	if(!node)
		return NULL;

	if(!(addr=_BWLAddrAlloc(ctx)))
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
_BWLCopyAddrRec(
	BWLContext		ctx,
	const struct addrinfo	*src
)
{
	struct addrinfo	*dst = calloc(1,sizeof(struct addrinfo));

	if(!dst){
		BWLError(ctx,BWLErrFATAL,errno,
				":calloc(1,sizeof(struct addrinfo))");
		return NULL;
	}

	*dst = *src;

	if(src->ai_addr){
		dst->ai_addr = malloc(src->ai_addrlen);
		if(!dst->ai_addr){
			BWLError(ctx,BWLErrFATAL,errno,
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
			BWLError(ctx,BWLErrWARNING,
					BWLErrUNKNOWN,
					":Invalid canonname!");
			dst->ai_canonname = NULL;
		}else{
			dst->ai_canonname = malloc(sizeof(char)*(len+1));
			if(!dst->ai_canonname){
				BWLError(ctx,BWLErrWARNING,
					errno,":malloc(sizeof(%d)",len+1);
				dst->ai_canonname = NULL;
			}else
				strcpy(dst->ai_canonname,src->ai_canonname);
		}
	}

	dst->ai_next = NULL;

	return dst;
}

BWLAddr
BWLAddrByAddrInfo(
	BWLContext		ctx,
	const struct addrinfo	*ai
)
{
	BWLAddr	addr = _BWLAddrAlloc(ctx);
	struct addrinfo	**aip;

	if(!addr)
		return NULL;

	addr->ai_free = 1;
	aip = &addr->ai;

	while(ai){
		*aip = _BWLCopyAddrRec(ctx,ai);
		if(!*aip){
			BWLAddrFree(addr);
			return NULL;
		}
		aip = &(*aip)->ai_next;
		ai = ai->ai_next;
	}

	return addr;
}

BWLAddr
BWLAddrBySockFD(
	BWLContext	ctx,
	int		fd
)
{
	BWLAddr	addr = _BWLAddrAlloc(ctx);

	if(!addr)
		return NULL;

	addr->fd_user = 1;
	addr->fd = fd;

	return addr;
}

BWLAddr
_BWLAddrCopy(
	BWLAddr		from
	)
{
	BWLAddr		to;
	struct addrinfo	**aip;
	struct addrinfo	*ai;
	
	if(!from)
		return NULL;
	
	if( !(to = _BWLAddrAlloc(from->ctx)))
		return NULL;

	if(from->node_set){
		strncpy(to->node,from->node,sizeof(to->node));
		to->node_set = True;
	}

	if(from->port_set){
		strncpy(to->port,from->port,sizeof(to->port));
		to->port_set = True;
	}

	aip = &to->ai;
	ai = from->ai;

	while(ai){
		to->ai_free = 1;
		*aip = _BWLCopyAddrRec(from->ctx,ai);
		if(!*aip){
			BWLAddrFree(to);
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
BWLAddrFD(
	BWLAddr	addr
	)
{
	if(!addr || (addr->fd < 0))
		return -1;

	return addr->fd;
}

socklen_t
BWLAddrSockLen(
	BWLAddr	addr
	)
{
	if(!addr || !addr->saddr)
		return 0;

	return addr->saddrlen;
}

/*
 * Function:	BWLGetContext
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
BWLContext
BWLGetContext(
	BWLControl	cntrl
	)
{
	return cntrl->ctx;
}

/*
 * Function:	BWLGetMode
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
BWLSessionMode
BWLGetMode(
	BWLControl	cntrl
	)
{
	return cntrl->mode;
}

/*
 * Function:	BWLControlFD
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
BWLControlFD(
	BWLControl	cntrl
	)
{
	return cntrl->sockfd;
}

/*
 * Function:	BWLGetRTTBound
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
BWLNum64
BWLGetRTTBound(
	BWLControl	cntrl
	)
{
	return cntrl->rtt_bound;
}

/*
 * Function:	_BWLFailControlSession
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
BWLErrSeverity
_BWLFailControlSession(
	BWLControl	cntrl,
	int		level
	)
{
	cntrl->state = _BWLStateInvalid;
	return (BWLErrSeverity)level;
}

/*
 * Function:	_BWLTestSessionAlloc
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
BWLTestSession
_BWLTestSessionAlloc(
	BWLControl	cntrl,
	BWLBoolean	send,
	BWLAddr		sender,
	BWLAddr		receiver,
	u_int16_t	recv_port,
	BWLTestSpec	*test_spec
)
{
	BWLTestSession	test;

	/*
	 * Address records must exist.
	 */
	if(!sender || ! receiver){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"_BWLTestSessionAlloc:Invalid Addr arg");
		return NULL;
	}

	if(!(test = calloc(1,sizeof(BWLTestSessionRec)))){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"calloc(1,BWLTestSessionRec): %M");
		return NULL;
	}

	/*
	 * Initialize address records and test description record fields.
	 */
	test->cntrl = cntrl;
	memcpy(&test->test_spec,test_spec,sizeof(BWLTestSpec));

	/*
	 * Overwrite sender/receiver with passed-in values
	 */
	test->test_spec.sender = sender;
	test->test_spec.receiver = receiver;

	test->conf_receiver = !send;
	test->conf_sender = !test->conf_receiver;

	if(send){
		test->conf_sender = True;
		test->recv_port = recv_port;
	}
	else{
		test->conf_receiver = True;
		test->recv_port = 0;
	}

	return test;
}

/*
 * Function:	_BWLTestSessionFree
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
BWLErrSeverity
_BWLTestSessionFree(
	BWLTestSession	tsession,
	BWLAcceptType	aval
)
{
	BWLErrSeverity	err=BWLErrOK;

	if(!tsession){
		return BWLErrOK;
	}

	/*
	 * remove this tsession from the cntrl->tests list.
	 */
	if(tsession->cntrl->tests == tsession){
		tsession->cntrl->tests = NULL;
	}

	(void)_BWLEndpointStop(tsession,aval,&err);

	if(tsession->closure){
		_BWLCallTestComplete(tsession,aval);
	}

	BWLAddrFree(tsession->test_spec.sender);
	BWLAddrFree(tsession->test_spec.receiver);

	while(tsession->localfp &&
			(fclose(tsession->localfp) < 0) &&
			(errno == EINTR));
	while(tsession->remotefp &&
			(fclose(tsession->remotefp) < 0) &&
			(errno == EINTR));

	free(tsession);

	return err;
}


/*
 * Function:	_BWLCreateSID
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
_BWLCreateSID(
	BWLTestSession	tsession
	)
{
	u_int8_t	*aptr;

#ifdef	AF_INET6
	if(tsession->test_spec.receiver->saddr->sa_family == AF_INET6){
		struct sockaddr_in6	*s6;

		s6 = (struct sockaddr_in6*)tsession->test_spec.receiver->saddr;
		/* point at last 4 bytes of addr */
		aptr = &s6->sin6_addr.s6_addr[12];
	}else
#endif
	if(tsession->test_spec.receiver->saddr->sa_family == AF_INET){
		struct sockaddr_in	*s4;

		s4 = (struct sockaddr_in*)tsession->test_spec.receiver->saddr;
		aptr = (u_int8_t*)&s4->sin_addr;
	}
	else{
		BWLError(tsession->cntrl->ctx,BWLErrFATAL,BWLErrUNSUPPORTED,
				"_BWLCreateSID:Unknown address family");
		return 1;
	}

	memcpy(&tsession->sid[0],aptr,4);

	_BWLEncodeTimeStamp(&tsession->sid[4],&tsession->localtime);

	if(I2RandomBytes(tsession->cntrl->ctx->rand_src,&tsession->sid[12],4)
									!= 0){
		return 1;
	}

	return 0;
}

BWLPacketSizeT
BWLTestPayloadSize(
		BWLSessionMode	mode, 
		u_int32_t	padding
		)
{
	BWLPacketSizeT msg_size;

	switch (mode) {
	case BWL_MODE_OPEN:
		msg_size = 14;
		break;
	case BWL_MODE_AUTHENTICATED:
	case BWL_MODE_ENCRYPTED:
		msg_size = 32;
		break;
	default:
		return 0;
		/* UNREACHED */
	}

	return msg_size + padding;
}

/* These lengths assume no IP options. */
#define BWL_IP4_HDR_SIZE	20	/* rfc 791 */
#define BWL_IP6_HDR_SIZE	40	/* rfc 2460 */
#define BWL_UDP_HDR_SIZE	8	/* rfc 768 */

/*
** Given the protocol family, OWAMP mode and packet padding,
** compute the size of resulting full IP packet.
*/
BWLPacketSizeT
BWLTestPacketSize(
		int		af,    /* AF_INET, AF_INET6 */
		BWLSessionMode	mode, 
		u_int32_t	padding
		)
{
	BWLPacketSizeT payload_size, header_size;

	switch (af) {
	case AF_INET:
		header_size = BWL_IP4_HDR_SIZE + BWL_UDP_HDR_SIZE;
		break;
	case AF_INET6:
		header_size = BWL_IP6_HDR_SIZE + BWL_UDP_HDR_SIZE;
		break;
	default:
		return 0;
		/* UNREACHED */
	}

	if(!(payload_size = BWLTestPayloadSize(mode,padding)))
			return 0;

	return payload_size + header_size;
}

/*
 * Function:	BWLAddrNodeName
 *
 * Description:	
 * 	This function gets a char* node name for a given BWLAddr.
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
BWLAddrNodeName(
	BWLAddr	addr,
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
 * Function:	BWLAddrNodeService
 *
 * Description:	
 * 	This function gets a char* service name for a given BWLAddr.
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
BWLAddrNodeService(
	BWLAddr	addr,
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
