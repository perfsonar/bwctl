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
 *	File:		sapi.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:27:01 MDT 2003
 *
 *	Description:	
 *
 *	This file contains the api functions typically called from an
 *	ipcntrl server application.
 */
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ipcntrl/ipcntrlP.h>

static IPFAddr
AddrByWildcard(
	IPFContext	ctx
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	IPFAddr		addr;
	int		ai_err;


	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if( (ai_err = getaddrinfo(NULL,IPF_CONTROL_SERVICE_NAME,&hints,&ai)!=0)
								|| !ai){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"getaddrinfo(): %s",gai_strerror(ai_err));
		return NULL;
	}

	if( !(addr = _IPFAddrAlloc(ctx))){
		freeaddrinfo(ai);
		return NULL;
	}

	addr->ai = ai;

	return addr;
}

static IPFBoolean
SetServerAddrInfo(
	IPFContext	ctx,
	IPFAddr		addr,
	IPFErrSeverity	*err_ret
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	int		ai_err;
	char		*port=NULL;

	if(!addr || (addr->fd > -1)){
		*err_ret = IPFErrFATAL;
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,"Invalid address");
		return False;
	}

	if(addr->ai)
		return True;

	if(!addr->node_set){
		*err_ret = IPFErrFATAL;
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,"Invalid address");
		return False;
	}

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if(addr->port_set)
		port = addr->port;
	else
		port = IPF_CONTROL_SERVICE_NAME;

	if( (ai_err = getaddrinfo(addr->node,port,&hints,&ai)!=0) || !ai){
		*err_ret = IPFErrFATAL;
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"getaddrinfo(): %s",
							gai_strerror(ai_err));
		return False;
	}
	addr->ai = ai;

	return True;
}

/*
 * This function should only be called on an IPFAddr that already has
 * a fd associated with it.
 */
static IPFBoolean
AddrSetSAddr(
	IPFAddr		addr,
	struct sockaddr	*fromaddr,
	socklen_t	fromaddrlen,
	IPFErrSeverity	*err_ret
	)
{
	int			so_type;
	socklen_t		so_typesize = sizeof(so_type);
	struct sockaddr		*saddr=NULL;
	struct addrinfo		*ai=NULL;
	struct sockaddr_in	v4addr;
	int			gai;

	*err_ret = IPFErrOK;

	if(!addr || (addr->fd < 0)){
		IPFError(addr->ctx,IPFErrFATAL,IPFErrINVALID,"Invalid address");
		goto error;
	}

	if(addr->saddr && addr->saddrlen)
		return True;

	if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
				(void*)&so_type,&so_typesize) != 0){
		IPFError(addr->ctx,IPFErrFATAL,errno,
				"getsockopt():%s",strerror(errno));
		goto error;
	}

	if( !(saddr = malloc(sizeof(struct sockaddr_storage))) ||
				!(ai = malloc(sizeof(struct addrinfo)))){
		IPFError(addr->ctx,IPFErrFATAL,errno,"malloc():%s",
				strerror(errno));
		goto error;
	}

	switch(fromaddr->sa_family){
#ifdef	AF_INET6
		struct sockaddr_in6	*v6addr;

		case AF_INET6:
			/*
			 * If this is a mapped addr - create a sockaddr_in
			 * for it instead. (This is so addr matching will
			 * work later - and make sense for users attempting
			 * to use v4.) Use this to reset fromaddr - then
			 * fall through to INET case to memcpy.
			 */
			v6addr = (struct sockaddr_in6*)fromaddr;
			if(IN6_IS_ADDR_V4MAPPED(&v6addr->sin6_addr)){
				memset(&v4addr,0,sizeof(v4addr));
#ifdef	HAVE_STRUCT_SOCKADDR_SA_LEN
				v4addr.sin_len = sizeof(v4addr);
#endif
				v4addr.sin_family = AF_INET;
				v4addr.sin_port = v6addr->sin6_port;
				memcpy(&v4addr.sin_addr.s_addr,
					&v6addr->sin6_addr.s6_addr[12],4);
				fromaddr = (struct sockaddr*)&v4addr;
				fromaddrlen = sizeof(v4addr);

			}
#endif
			/* fall through */
		case AF_INET:
			memcpy((void*)saddr,(void*)fromaddr,fromaddrlen);
			break;
		default:
			IPFError(addr->ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid addr family");
			goto error;
			break;
	}

	ai->ai_flags = 0;
	ai->ai_family = saddr->sa_family;
	ai->ai_socktype = so_type;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default.	*/
	ai->ai_addrlen = fromaddrlen;
	ai->ai_canonname = NULL;
	ai->ai_addr = saddr;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->saddr = saddr;
	addr->saddrlen = fromaddrlen;
	addr->so_type = so_type;

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

	return True;

error:
	if(saddr) free(saddr);
	if(ai) free(ai);
	*err_ret = IPFErrFATAL;
	return False;
}

/*
 * This function should only be called on an IPFAddr that already has
 * a fd associated with it.
 */
static IPFBoolean
AddrSetSockName(
	IPFAddr		addr,
	IPFErrSeverity	*err_ret
	)
{
	struct sockaddr_storage	sbuff;
	socklen_t		so_size = sizeof(sbuff);

	if(!addr || (addr->fd < 0)){
		IPFError(addr->ctx,IPFErrFATAL,IPFErrINVALID,"Invalid address");
		goto error;
	}

	if(getsockname(addr->fd,(void*)&sbuff,&so_size) != 0){
		IPFError(addr->ctx,IPFErrFATAL,errno,
				"getsockname():%s",strerror(errno));
		goto error;
	}

	return AddrSetSAddr(addr,(struct sockaddr *)&sbuff,so_size,err_ret);

error:
	*err_ret = IPFErrFATAL;
	return False;
}

static int
OpenSocket(
	IPFContext	ctx	__attribute__((unused)),
	int		family,
	IPFAddr		addr
	)
{
	struct addrinfo	*ai;
	int		on;

	for(ai = addr->ai;ai;ai = ai->ai_next){
		if(ai->ai_family != family)
			continue;

		addr->fd =socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);

		if(addr->fd < 0)
			continue;

		on=1;
		if(setsockopt(addr->fd,SOL_SOCKET,SO_REUSEADDR,&on,
							sizeof(on)) != 0){
			goto failsock;
		}

		/*
		 * TODO Check for the superseded IPV6_BINDV6ONLY sockopt too?
		 * (No - not unless someone complains.)
		 */
#if	defined(AF_INET6) && defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
		on=0;
		if((ai->ai_family == AF_INET6) &&
			setsockopt(addr->fd,IPPROTO_IPV6,IPV6_V6ONLY,&on,
							sizeof(on)) != 0){
			goto failsock;
		}
#endif

		if(bind(addr->fd,ai->ai_addr,ai->ai_addrlen) == 0){

			addr->saddr = ai->ai_addr;
			addr->saddrlen = ai->ai_addrlen;
			addr->so_type = ai->ai_socktype;

			break;
		}

		if(errno == EADDRINUSE)
			return -2;

failsock:
		while((close(addr->fd) < 0) && (errno == EINTR));
		addr->fd = -1;
	}

	return addr->fd;
}

/*
 * Function:	IPFServerSockCreate
 *
 * Description:	
 * 		Used by server to create the initial listening socket.
 * 		(It is not required that the server use this interface,
 * 		but it will be kept up-to-date and in sync with the
 * 		client IPFControlOpen function. For example, both of
 * 		these functions currently give priority to IPV6 addresses
 * 		over IPV4.)
 *
 * 		The addr should be NULL for a wildcard socket, or bound to
 * 		a specific interface using IPFAddrByNode or IPFAddrByAddrInfo.
 *
 * 		This function will create the socket, bind it, and set the
 * 		"listen" backlog length.
 *
 * 		If addr is set using IPFAddrByFD, it will cause an error.
 * 		(It doesn't really make much sense to call this function at
 * 		all if you are going to	create and bind your own socket -
 * 		the only thing left is to call "listen"...)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
IPFAddr
IPFServerSockCreate(
	IPFContext	ctx,
	IPFAddr		addr,
	IPFErrSeverity	*err_ret
	)
{
	int		fd = -1;

	*err_ret = IPFErrOK;

	/*
	 * AddrByFD is invalid.
	 */
	if(addr && (addr->fd > -1)){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
			"Invalid IPFAddr record - fd already specified.");
		goto error;
	}

	/*
	 * If no addr specified, then use wildcard address.
	 */
	if((!addr) && !(addr = AddrByWildcard(ctx)))
		goto error;


	if(!SetServerAddrInfo(ctx,addr,err_ret))
		goto error;

#ifdef	AF_INET6
	/*
	 * First try IPv6 addrs only
	 */
	fd = OpenSocket(ctx,AF_INET6,addr);

	/*
	 * Fall back to IPv4 addrs if necessary.
	 */
	if(fd == -1)
#endif
		fd = OpenSocket(ctx,AF_INET,addr);

	/*
	 * if we failed to find any IPv6 or IPv4 addresses... punt.
	 */
	if(fd < 0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"IPFServerSockCreate:%M");
		goto error;
	}

	/*
	 * We have a bound socket - set the listen backlog.
	 */
	if(listen(addr->fd,IPF_LISTEN_BACKLOG) < 0){
		IPFError(ctx,IPFErrFATAL,errno,"listen(%d,%d):%s",
				addr->fd,IPF_LISTEN_BACKLOG,strerror(errno));
		goto error;
	}

	return addr;

error:
	IPFAddrFree(addr);
	*err_ret = IPFErrFATAL;
	return NULL;

}

/*
 * Function:	IPFControlAccept
 *
 * Description:	
 * 		This function is used to initialiize the communication
 * 		to the peer.
 *           
 * In Args:	
 * 		connfd,connsaddr, and connsaddrlen are all returned
 * 		from "accept".
 *
 * Returns:	Valid IPFControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
IPFControl
IPFControlAccept(
	IPFContext	ctx,		/* library context		*/
	int		connfd,		/* connected socket		*/
	struct sockaddr	*connsaddr,	/* connected socket addr	*/
	socklen_t	connsaddrlen,	/* connected socket addr len	*/
	u_int32_t	mode_offered,	/* advertised server mode	*/
	IPFNum64	uptime,		/* uptime for server		*/
	int		*retn_on_intr,	/* if *retn_on_intr return	*/
	IPFErrSeverity	*err_ret	/* err - return			*/
)
{
	IPFControl	cntrl;
	u_int8_t	challenge[16];
	u_int8_t	rawtoken[32];
	u_int8_t	token[32];
	int		rc;
	struct timeval	tvalstart,tvalend;
	int		ival=0;
	int		*intr = &ival;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	*err_ret = IPFErrOK;

	if ( !(cntrl = _IPFControlAlloc(ctx,err_ret)))
		goto error;

	cntrl->sockfd = connfd;
	cntrl->server = True;

	/*
	 * set up remote_addr for policy decisions, and log reporting.
	 *
	 * set fd_user false to make IPFAddrFree of remote_addr close the
	 * socket. (This will happen from IPFControlClose.)
	 */
	if(!(cntrl->remote_addr = IPFAddrBySockFD(ctx,connfd)))
		goto error;
	cntrl->remote_addr->fd_user = False;
	if(!AddrSetSAddr(cntrl->remote_addr,connsaddr,connsaddrlen,err_ret))
		goto error;
	/*
	 * set up local_addr for policy decisions, and log reporting.
	 */
	if( !(cntrl->local_addr = IPFAddrBySockFD(ctx,connfd))){
		*err_ret = IPFErrFATAL;
		goto error;
	}
	if(!AddrSetSockName(cntrl->local_addr,err_ret))
		goto error;

	IPFError(ctx,IPFErrINFO,IPFErrPOLICY,
		 "Connection to (%s:%s) from (%s:%s)",
		 cntrl->local_addr->node,cntrl->local_addr->port,
		 cntrl->remote_addr->node, cntrl->remote_addr->port);

	/* generate 16 random bytes of challenge and save them away. */
	if(I2RandomBytes(ctx->rand_src,challenge, 16) != 0){
		*err_ret = IPFErrFATAL;
		goto error;
	}

	if(gettimeofday(&tvalstart,NULL)!=0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"gettimeofday():%M");
		*err_ret = IPFErrFATAL;
		goto error;
	}
	if( (rc = _IPFWriteServerGreeting(cntrl,mode_offered,
					challenge,intr)) < IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
		goto error;
	}

	/*
	 * If no mode offered, immediately close socket after sending
	 * server greeting.
	 */
	if(!mode_offered){
		IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,
	"Control request to (%s:%s) denied from (%s:%s): mode == 0",
			 cntrl->local_addr->node,cntrl->local_addr->port,
			 cntrl->remote_addr->node,cntrl->remote_addr->port);
		goto error;
	}

	if((rc = _IPFReadClientGreeting(cntrl,&cntrl->mode,rawtoken,
				       cntrl->readIV,intr)) < IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
		goto error;
	}
	if(gettimeofday(&tvalend,NULL)!=0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"gettimeofday():%M");
		*err_ret = IPFErrFATAL;
		goto error;
	}
	tvalsub(&tvalend,&tvalstart);
	IPFTimevalToNum64(&cntrl->rtt_bound,&tvalend);

	/* insure that exactly one mode is chosen */
	if(	(cntrl->mode != IPF_MODE_OPEN) &&
			(cntrl->mode != IPF_MODE_AUTHENTICATED) &&
			(cntrl->mode != IPF_MODE_ENCRYPTED)){
		*err_ret = IPFErrFATAL;
		goto error;
	}

	if(!(cntrl->mode | mode_offered)){ /* can't provide requested mode */
		IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,
	"Control request to (%s:%s) denied from (%s:%s):mode not offered (%u)",
			 cntrl->local_addr->node,cntrl->local_addr->port,
			 cntrl->remote_addr->node,
			 cntrl->remote_addr->port,cntrl->mode);
		if( (rc = _IPFWriteServerOK(cntrl,IPF_CNTRL_REJECT,0,intr)) <
								IPFErrOK){
			*err_ret = (IPFErrSeverity)rc;
		}
		goto error;
	}
	
	if(cntrl->mode & (IPF_MODE_AUTHENTICATED|IPF_MODE_ENCRYPTED)){
		u_int8_t	binKey[16];
		IPFBoolean	getkey_success;
		
		/* Fetch the encryption key into binKey */
		/*
		 * go through the motions of decrypting token even if
		 * getkey fails to find username to minimize vulnerability
		 * to timing attacks.
		 */
		getkey_success = _IPFCallGetAESKey(cntrl->ctx,
				cntrl->userid_buffer,binKey,err_ret);
		if(!getkey_success && (*err_ret != IPFErrOK)){
			(void)_IPFWriteServerOK(cntrl,IPF_CNTRL_FAILURE,0,intr);
			goto error;
		}
		
		if (IPFDecryptToken(binKey,rawtoken,token) < 0){
			IPFError(cntrl->ctx,IPFErrFATAL,
					IPFErrUNKNOWN,
					"Encryption state problem?!?!");
			(void)_IPFWriteServerOK(cntrl,
						IPF_CNTRL_FAILURE,0,intr);
			*err_ret = IPFErrFATAL;
			goto error;
		}
		
		/* Decrypted challenge is in the first 16 bytes */
		if((memcmp(challenge,token,16) != 0) || !getkey_success){
			if(!getkey_success){
				IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,
					"Unknown userid (%s)",
					cntrl->userid_buffer);
			}
			else{
				IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,
 "Control request to (%s:%s) denied from (%s:%s):Invalid challenge encryption",
					cntrl->local_addr->node,
					cntrl->local_addr->port,
					cntrl->remote_addr->node,
					cntrl->remote_addr->port);
			}
			(void)_IPFWriteServerOK(cntrl,IPF_CNTRL_REJECT,0,intr);
			goto error;
		}

		/* Authentication ok - set encryption fields */
		cntrl->userid = cntrl->userid_buffer;
		if(I2RandomBytes(cntrl->ctx->rand_src,cntrl->writeIV,16) != 0){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"Unable to fetch randomness...");
			(void)_IPFWriteServerOK(cntrl,IPF_CNTRL_FAILURE,0,intr);
			goto error;
		}
		memcpy(cntrl->session_key,&token[16],16);
		_IPFMakeKey(cntrl,cntrl->session_key); 
	}

	if(!_IPFCallCheckControlPolicy(cntrl,cntrl->mode,cntrl->userid, 
		  cntrl->local_addr->saddr,cntrl->remote_addr->saddr,err_ret)){
		if(*err_ret > IPFErrWARNING){
			IPFError(ctx,IPFErrINFO,IPFErrPOLICY,
       "ControlSession request to (%s:%s) denied from userid(%s):(%s:%s)",
				cntrl->local_addr->node,cntrl->local_addr->port,
				(cntrl->userid)?cntrl->userid:(u_int8_t*)"nil",
				cntrl->remote_addr->node,
				cntrl->remote_addr->port);
			/*
			 * send mode of 0 to client, and then close.
			 */
			(void)_IPFWriteServerOK(cntrl,IPF_CNTRL_REJECT,0,intr);
		}
		else{
			IPFError(ctx,*err_ret,IPFErrUNKNOWN,
						"Policy function failed.");
			(void)_IPFWriteServerOK(cntrl,IPF_CNTRL_FAILURE,0,intr);
		}
		goto error;
	}

	/*
	 * Made it through the gauntlet - accept the control session!
	 */
	if( (rc = _IPFWriteServerOK(cntrl,IPF_CNTRL_ACCEPT,uptime,intr)) <
								IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
		goto error;
	}
	IPFError(ctx,IPFErrINFO,IPFErrPOLICY,
		"ControlSession([%s]:%s) accepted from userid(%s):([%s]:%s)",
		cntrl->local_addr->node,cntrl->local_addr->port,
		(cntrl->userid)?cntrl->userid:(u_int8_t*)"nil",
		cntrl->remote_addr->node,
		cntrl->remote_addr->port);
	
	return cntrl;

error:
	IPFControlClose(cntrl);
	return NULL;
}

IPFErrSeverity
IPFProcessTestRequest(
	IPFControl	cntrl,
	int		*retn_on_intr
		)
{
	IPFTestSession	tsession = NULL;
	IPFErrSeverity	err_ret=IPFErrOK;
	u_int32_t	offset;
	u_int16_t	port;
	int		rc;
	IPFAcceptType	acceptval = IPF_CNTRL_FAILURE;
	int		ival=0;
	int		*intr = &ival;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * Read the TestRequest and alloate tsession to hold the information.
	 */
	if((rc = _IPFReadTestRequest(cntrl,intr,&tsession,&acceptval)) !=
								IPFErrOK){
		switch(acceptval){
			case IPF_CNTRL_INVALID:
				 return IPFErrFATAL;
			case IPF_CNTRL_FAILURE:
			case IPF_CNTRL_UNSUPPORTED:
				return IPFErrWARNING;
			default:
				/* NOTREACHED */
				abort();
		}
	}

	assert(tsession);

	/*
	 * Determine how to decode the socket addresses.
	 */
	switch (tsession->sender->saddr->sa_family){
#ifdef	AF_INET6
		case AF_INET6:
			/* compute offset of port field */
			offset =
			(((char*)&(((struct sockaddr_in6*)NULL)->sin6_port)) -
				((char*)NULL));

			break;
#endif
		case AF_INET:
			/* compute offset of port field */
			offset =
			(((char*)&(((struct sockaddr_in*)NULL)->sin_port)) -
				((char*)NULL));
			break;
		default:
			/* shouldn't really happen... */
			acceptval = IPF_CNTRL_UNSUPPORTED;
			goto error;
			break;
	}

	if(tsession->conf_receiver && (_IPFCreateSID(tsession) != 0)){
		err_ret = IPFErrWARNING;
		acceptval = IPF_CNTRL_FAILURE;
		goto error;
	}

	/*
	 * Now that we know the SID we can create the schedule
	 * context.
	 */
	if(!(tsession->sctx = IPFScheduleContextCreate(cntrl->ctx,
					tsession->sid,&tsession->test_spec))){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"Unable to init schedule generator");
		err_ret = IPFErrWARNING;
		acceptval = IPF_CNTRL_FAILURE;
		goto error;
	}

	/*
	 * if conf_receiver - open port and get SID.
	 */
	if(tsession->conf_receiver){
		if(tsession->conf_sender){
			/*
			 * NOTE:
			 * This implementation only configures "local" test
			 * endpoints. For a more distributed implementation
			 * where a single control server could manage multiple
			 * endpoints - this check would be removed, and
			 * conf_sender and conf_receiver could make
			 * sense together.
			 */
			acceptval = IPF_CNTRL_UNSUPPORTED;
			err_ret = IPFErrWARNING;
			goto error;
		}

		if(!_IPFCallCheckTestPolicy(cntrl,False,
				tsession->receiver->saddr,
				tsession->sender->saddr,
				tsession->sender->saddrlen,
				&tsession->test_spec,&tsession->closure,
				&err_ret)){
			if(err_ret < IPFErrOK)
				goto error;
			IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,
							"Test not allowed");
			acceptval = IPF_CNTRL_REJECT;
			err_ret = IPFErrINFO;
			goto error;
		}

		/* receiver first (sid comes from there) */
		if(!_IPFEndpointInit(cntrl,tsession,tsession->receiver,NULL,
								&err_ret)){
			err_ret = IPFErrWARNING;
			acceptval = IPF_CNTRL_FAILURE;
			goto error;
		}
	}

	if(tsession->conf_sender){
		/*
		 * Check for possible DoS as advised in Section 7 of owdp
		 * spec.
		 * (control-client MUST be receiver if openmode.)
		 */
		if(!(cntrl->mode & IPF_MODE_DOCIPHER) &&
				(I2SockAddrEqual(cntrl->remote_addr->saddr,
					 cntrl->remote_addr->saddrlen,
					 tsession->receiver->saddr,
					 tsession->receiver->saddrlen,
					 I2SADDR_ADDR) <= 0)){
			IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,
		"Test Denied: OpenMode recieve_addr(%s) != control_client(%s)",
					tsession->receiver->node,
					cntrl->remote_addr->node);
			acceptval = IPF_CNTRL_REJECT;
			err_ret = IPFErrINFO;
			goto error;
		}

		if(!_IPFCallCheckTestPolicy(cntrl,True,
					tsession->sender->saddr,
					tsession->receiver->saddr,
					tsession->receiver->saddrlen,
					&tsession->test_spec,
					&tsession->closure,&err_ret)){
			if(err_ret < IPFErrOK)
				goto error;
			IPFError(cntrl->ctx, IPFErrINFO, IPFErrPOLICY,
				 "Test not allowed");
			acceptval = IPF_CNTRL_REJECT;
			err_ret = IPFErrINFO;
			goto error;
		}
		if(!_IPFEndpointInit(cntrl,tsession,tsession->sender,NULL,
								&err_ret)){
			err_ret = IPFErrWARNING;
			acceptval = IPF_CNTRL_FAILURE;
			goto error;
		}
		if(!_IPFEndpointInitHook(cntrl,tsession,&err_ret)){
			err_ret = IPFErrWARNING;
			acceptval = IPF_CNTRL_FAILURE;
			goto error;
		}
		/*
		 * set port to the port number fetched from the saddr.
		 * (This ugly code decodes the network ordered port number
		 * from the saddr using the port "offset" computed earlier.
		 */
		port = ntohs(*(u_int16_t*)
				((u_int8_t*)tsession->sender->saddr+offset)
				);
	}

	if(tsession->conf_receiver){
		if(!_IPFEndpointInitHook(cntrl,tsession,&err_ret)){
			err_ret = IPFErrWARNING;
			acceptval = IPF_CNTRL_FAILURE;
			goto error;
		}
		/*
		 * set port to the port number fetched from the saddr.
		 * (This ugly code decodes the network ordered port number
		 * from the saddr using the port "offset" computed earlier.
		 */
		port = ntohs(*(u_int16_t*)
				((u_int8_t*)tsession->receiver->saddr+offset)
				);
	}

	if( (rc = _IPFWriteTestAccept(cntrl,intr,IPF_CNTRL_ACCEPT,
				      port,tsession->sid)) < IPFErrOK){
		err_ret = (IPFErrSeverity)rc;
		goto err2;
	}

	/*
	 * Add tsession to list of tests managed by this control connection.
	 */
	tsession->next = cntrl->tests;
	cntrl->tests = tsession;

	return IPFErrOK;

error:
	/*
	 * If it is a non-fatal error, communication should continue, so
	 * send negative accept.
	 */
	if(err_ret >= IPFErrWARNING)
		(void)_IPFWriteTestAccept(cntrl,intr,acceptval,0,NULL);

err2:
	if(tsession)
		_IPFTestSessionFree(tsession,IPF_CNTRL_FAILURE);

	return err_ret;
}

IPFErrSeverity
IPFProcessStartSessions(
	IPFControl	cntrl,
	int		*retn_on_intr
	)
{
	int		rc;
	IPFTestSession	tsession;
	IPFErrSeverity	err,err2=IPFErrOK;
	int		ival=0;
	int		*intr = &ival;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if( (rc = _IPFReadStartSessions(cntrl,intr)) < IPFErrOK)
		return _IPFFailControlSession(cntrl,rc);

	if( (rc = _IPFWriteControlAck(cntrl,intr,IPF_CNTRL_ACCEPT)) < IPFErrOK)
		return _IPFFailControlSession(cntrl,rc);

	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->endpoint){
			if(!_IPFEndpointStart(tsession->endpoint,&err)){
				(void)_IPFWriteStopSessions(cntrl,intr,
							    IPF_CNTRL_FAILURE);
				return _IPFFailControlSession(cntrl,err);
			}
			err2 = MIN(err,err2);
		}
	}

	return err2;
}

struct DoDataState{
	IPFControl	cntrl;
	IPFErrSeverity	err;
	IPFBoolean	send;
	u_int32_t	begin;
	u_int32_t	end;
	u_int32_t	inbuf;
	u_int64_t	count;
	u_int32_t	maxiseen;
	int		*intr;
};

static int
DoDataRecords(
	IPFDataRec	*rec,
	void		*udata
	)
{
	struct DoDataState	*dstate = (struct DoDataState *)udata;
	IPFControl		cntrl = dstate->cntrl;
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;

	/*
	 * If this record is not in range - return 0 to continue on.
	 */
	if((rec->seq_no < dstate->begin) || (rec->seq_no > dstate->end)){
		return 0;
	}

	dstate->count++;

	/*
	 * Save largest index seen that is not lost.
	 * (This allows this data to be parsed again to count only those
	 * records before this index for the purposes of fetching a
	 * partial valid session even if it was unable to terminate
	 * properly.)
	 */
	if((rec->seq_no > dstate->maxiseen) && !IPFIsLostRecord(rec)){
		dstate->maxiseen = rec->seq_no;
	}

	if(dstate->send){
		/*
		 * Encode this record into cntrl->msg buffer.
		 */
		if(!_IPFEncodeDataRecord(&buf[dstate->inbuf*_IPF_TESTREC_SIZE],
									rec)){
			return -1;
		}
		dstate->inbuf++;

		/*
		 * If the buffer is full enough to send, do so.
		 */
		if(dstate->inbuf == _IPF_FETCH_TESTREC_BLOCKS){
			if(_IPFSendBlocksIntr(cntrl,buf,_IPF_FETCH_AES_BLOCKS,
					dstate->intr) != _IPF_FETCH_AES_BLOCKS){
				dstate->err = IPFErrFATAL;
				_IPFFailControlSession(cntrl,IPFErrFATAL);
				return -1;
			}
			dstate->inbuf = 0;
		}
	}

	return 0;
}

IPFErrSeverity
IPFProcessFetchSession(
	IPFControl	cntrl,
	int		*retn_on_intr
	)
{
	u_int8_t		*buf = (u_int8_t*)cntrl->msg;
	IPFErrSeverity  	err;
	IPFAcceptType		acceptval = IPF_CNTRL_REJECT;
	u_int32_t		begin;
	u_int32_t		end;
	IPFSID			sid;

	FILE			*fp;
	char			fname[PATH_MAX];

	u_int32_t		ver;
	u_int32_t		fin;
	off_t			hdr_off,tr_off,tr_size;
	struct stat		stat_buf;

	u_int64_t		filerecs;
	u_int64_t		sendrecs;
	struct DoDataState	dodata;

	int			ival=0;
	int			*intr = &ival;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * Read the complete FetchSession request.
	 */
	if((err = _IPFReadFetchSession(cntrl,intr,&begin,&end,sid)) < IPFErrOK){
		return _IPFFailControlSession(cntrl, err);
	}

	/*
	 * Try and open the file containing sid information.
	 */
	if( !(fp = _IPFCallOpenFile(cntrl,NULL,sid,fname))){
		goto reject;
	}

	/*
	 * Read the file header - fp will end up at beginning of
	 * TestRequest record.
	 */
	if(_IPFReadDataHeaderInitial(cntrl->ctx,fp,&ver,&fin,&hdr_off,
								&stat_buf)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"_IPFReadDataHeaderInitial(\"%s\"): %M",fname);
		goto failed;
	}

	/*
	 * Only version 2 files can be used to produce valid v5 Fetch
	 * response messages.
	 */
	if(ver < 2){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
		"IPFProcessFetchSession(\"%s\"): Invalid file version: %d",
			fname,ver);
		goto failed;
	}

	if(fin == _IPF_SESSION_FIN_ERROR){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"IPFProcessFetchSession(\"%s\"): Invalid file!",
			fname);
		goto failed;
	}

	/*
	 * If a "complete" session was requested, and the test did not
	 * terminate normally - we MUST deny here.
	 */
	if((begin == 0) && (end == 0xFFFFFFFF) &&
					(fin != _IPF_SESSION_FIN_NORMAL)){
		goto reject;
	}

	/*
	 * Determine size of TestReq - then check that the TestReq is
	 * non-zero and a multiple of AES blocksize.
	 */
	if( (tr_off = ftello(fp)) < 0){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,"ftello(): %M");
		goto failed;
	}
	tr_size = hdr_off - tr_off;
	if((tr_off >= hdr_off) || (tr_size % _IPF_RIJNDAEL_BLOCK_SIZE)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
		"IPFProcessFetchSession(\"%s\"): Invalid record offsets");
		goto failed;
	}

	/*
	 * Determine number of records in the file.
	 */
	filerecs = (stat_buf.st_size-hdr_off)/_IPF_TESTREC_SIZE;

	/*
	 * setup the state record for parsing the records.
	 */
	dodata.cntrl = cntrl;
	dodata.intr = intr;
	dodata.err = IPFErrOK;
	dodata.send = False;
	dodata.begin = begin;
	dodata.end = end;
	dodata.inbuf = 0;
	dodata.count = 0;
	dodata.maxiseen = 0;

	/*
	 * Now - count the number of records that will be sent.
	 * short-cut the count if full session is requested.
	 */
	if((fin == _IPF_SESSION_FIN_NORMAL) &&
					(begin == 0) && (end == 0xFFFFFFFF)){
		sendrecs = filerecs;
	}
	else{
		/* forward pointer to data records for counting */
		if(fseeko(fp,hdr_off,SEEK_SET)){
			IPFError(cntrl->ctx,IPFErrFATAL,errno,"fseeko(): %M");
			goto failed;
		}
		/*
		 * Now, count the records in range.
		 */
		if(IPFParseRecords(cntrl->ctx,fp,filerecs,ver,
					DoDataRecords,&dodata) != IPFErrOK){
			goto failed;
		}
		sendrecs = dodata.count;
		dodata.count = 0;

		/* set pointer back to beginning of TestReq */
		if(fseeko(fp,tr_off,SEEK_SET)){
			IPFError(cntrl->ctx,IPFErrFATAL,errno,"fseeko(): %M");
			goto failed;
		}

		/*
		 * If the session did not complete normally, redo the
		 * count ignoring all "missing" packets after the
		 * last seen one.
		 */
		if((fin != 1) && (dodata.maxiseen != end)){
			dodata.end = dodata.maxiseen;
			dodata.maxiseen = 0;

			if(IPFParseRecords(cntrl->ctx,fp,filerecs,ver,
					DoDataRecords,&dodata) != IPFErrOK){
				goto failed;
			}
			sendrecs = dodata.count;
			dodata.count = 0;

			/* set pointer back to beginning of TestReq */
			if(fseeko(fp,tr_off,SEEK_SET)){
				IPFError(cntrl->ctx,IPFErrFATAL,errno,
							"fseeko(): %M");
				goto failed;
			}
		}
	}

	/*
	 * Now accept the FetchRequest.
	 */
	acceptval = IPF_CNTRL_ACCEPT;
	if((err = _IPFWriteControlAck(cntrl,intr,acceptval)) < IPFErrOK){
		_IPFCallCloseFile(cntrl,NULL,fp,IPF_CNTRL_FAILURE);
		return _IPFFailControlSession(cntrl,err);
	}

	/*
	 * Read the TestReq from the file and write it to the socket.
	 * (after this loop - fp is positioned at hdr_off.
	 */
	while((tr_size > 0) &&
			(fread(buf,1,_IPF_RIJNDAEL_BLOCK_SIZE,fp) ==
			 			_IPF_RIJNDAEL_BLOCK_SIZE)){
		if(_IPFSendBlocksIntr(cntrl,buf,1,intr) != 1){
			_IPFCallCloseFile(cntrl,NULL,fp,IPF_CNTRL_FAILURE);
			return _IPFFailControlSession(cntrl,IPFErrFATAL);
		}
		tr_size -= _IPF_RIJNDAEL_BLOCK_SIZE;
	}

	/*
	 * Send the number of records.
	 */
	if((err = _IPFWriteFetchRecordsHeader(cntrl,intr,sendrecs)) < IPFErrOK){
		_IPFCallCloseFile(cntrl,NULL,fp,IPF_CNTRL_FAILURE);
		return _IPFFailControlSession(cntrl,err);
	}

	/*
	 * Now, send the data!
	 */
	dodata.send = True;
	if( (IPFParseRecords(cntrl->ctx,fp,filerecs,ver,
			DoDataRecords,&dodata) != IPFErrOK) ||
						(dodata.count != sendrecs)){
		_IPFCallCloseFile(cntrl,NULL,fp,IPF_CNTRL_FAILURE);
		return _IPFFailControlSession(cntrl,err);
	}

	/*
	 * We are done reading from the file - close it.
	 */
	_IPFCallCloseFile(cntrl,NULL,fp,IPF_CNTRL_ACCEPT);

	/*
	 * zero pad any "incomplete" records...
	 */
	assert(dodata.inbuf < _IPF_FETCH_TESTREC_BLOCKS);
	/* zero out any partial data blocks */
	while(dodata.inbuf && (dodata.inbuf < _IPF_FETCH_TESTREC_BLOCKS)){
		memset(&buf[dodata.inbuf*_IPF_TESTREC_SIZE],0,
							_IPF_TESTREC_SIZE);
		dodata.inbuf++;
	}

	/* send final data blocks */
	if(dodata.inbuf &&
		(_IPFSendBlocksIntr(cntrl,buf,_IPF_FETCH_AES_BLOCKS,intr) !=
							_IPF_FETCH_AES_BLOCKS)){
		return _IPFFailControlSession(cntrl,err);
	}

	/* now send final Zero Integrity Block */
	if(_IPFSendBlocksIntr(cntrl,cntrl->zero,1,intr) != 1){
		return _IPFFailControlSession(cntrl,err);
	}

	/*
	 * reset state to request.
	 */
	cntrl->state &= ~_IPFStateFetching;
	cntrl->state |= _IPFStateRequest;

	return IPFErrOK;

failed:
	acceptval = IPF_CNTRL_FAILURE;
reject:
	if(fp){
		_IPFCallCloseFile(cntrl,NULL,fp,acceptval);
	}

	if( (err = _IPFWriteControlAck(cntrl,intr,acceptval)) < IPFErrOK){
		return _IPFFailControlSession(cntrl,err);
	}

	return IPFErrINFO;

}
