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
				(cntrl->userid)?cntrl->userid:"nil",
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
		(cntrl->userid)?cntrl->userid:"nil",
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
	IPFTestSession	tsession = cntrl->tests;
	IPFErrSeverity	err_ret=IPFErrOK;
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

	/*
	 * If this is a "new" receiver session, create a SID for it.
	 */
	if((tsession != cntrl->tests) && tsession->conf_receiver &&
						(_IPFCreateSID(tsession) != 0)){
		err_ret = IPFErrWARNING;
		acceptval = IPF_CNTRL_FAILURE;
		goto error;
	}

	/*
	 * Initialize reservation time.
	 */
	tsession->reserve_time = IPFULongToNum64(0);

	/*
	 * Is this request allowed? Is there time (a reservation slot) for it?
	 */
#if	NOT
		/*
		 * Check for possible DoS as advised in Section 7 of owdp
		 * spec.
		 * (control-client MUST be receiver if openmode.)
		 * TODO: Move this into _IPFCallCheckTestPolicy.
		 */
	if(tsession->conf_sender){
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
	}
#endif
	if(!_IPFCallCheckTestPolicy(cntrl,tsession,&err_ret)){
		if(err_ret < IPFErrOK)
			goto error;
		IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,
							"Test not allowed");
		acceptval = IPF_CNTRL_REJECT;
		err_ret = IPFErrINFO;
		goto error;
	}

	if( (rc = _IPFWriteTestAccept(cntrl,intr,IPF_CNTRL_ACCEPT,tsession))
								< IPFErrOK){
		err_ret = (IPFErrSeverity)rc;
		goto err2;
	}

	/*
	 * Add tsession to list of tests managed by this control connection.
	 */
	cntrl->tests = tsession;

	return IPFErrOK;

error:
	/*
	 * If it is a non-fatal error, communication should continue, so
	 * send negative accept.
	 */
	if(err_ret >= IPFErrWARNING)
		(void)_IPFWriteTestAccept(cntrl,intr,acceptval,tsession);

err2:
	if(tsession)
		_IPFTestSessionFree(tsession,IPF_CNTRL_FAILURE);

	return err_ret;
}

IPFErrSeverity
IPFProcessTimeRequest(
	IPFControl	cntrl,
	int		*retn_on_intr
	)
{
	int		rc;
	int		ival=0;
	int		*intr = &ival;
	IPFTimeStamp	tstamp;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if( (rc = _IPFReadTimeRequest(cntrl,intr)) < IPFErrOK)
		return _IPFFailControlSession(cntrl,rc);

	if(!IPFGetTimestamp(cntrl->ctx,&tstamp))
		return _IPFFailControlSession(cntrl,IPFErrFATAL);

	if( (rc = _IPFWriteTimeResponse(cntrl,&tstamp,intr)) < IPFErrOK)
		return _IPFFailControlSession(cntrl,rc);

	return IPFErrOK;
}

IPFErrSeverity
IPFProcessStartSession(
	IPFControl	cntrl,
	int		*retn_on_intr
	)
{
	int		rc;
	IPFErrSeverity	err=IPFErrOK;
	int		ival=0;
	int		*intr = &ival;
	u_int16_t	dataport = 0;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if( (rc = _IPFReadStartSession(cntrl,&dataport,intr)) < IPFErrOK)
		return _IPFFailControlSession(cntrl,rc);

	if(!_IPFEndpointStart(cntrl->tests,&dataport,&err)){
		(void)_IPFWriteStartAck(cntrl,intr,0,IPF_CNTRL_FAILURE);
		return _IPFFailControlSession(cntrl,err);
	}

	if( (rc = _IPFWriteStartAck(cntrl,intr,dataport,IPF_CNTRL_ACCEPT))
								< IPFErrOK)
		return _IPFFailControlSession(cntrl,rc);


	return IPFErrOK;
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
	tsession = cntrl->tests;
	if(!tsession || (memcmp(sid,tsession->sid,sizeof(IPFSID)) != 0))
		return False;

	return _IPFEndpointStatus(tsession,aval,&err);

	return False;
}

int
IPFSessionsActive(
		IPFControl	cntrl,
		IPFAcceptType	*aval
		)
{
	IPFTestSession	tsession;
	IPFAcceptType	laval_mem = 0;
	IPFAcceptType	*laval = &laval_mem;
	IPFErrSeverity	err;

	if(aval)
		laval = aval;

	tsession = cntrl->tests;
	if(tsession && _IPFEndpointStatus(tsession,laval,&err) && (*laval < 0))
		return 1;
	return 0;
}

IPFErrSeverity
IPFStopSession(
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
	FILE		*fp;

	if(!cntrl->tests){
		return IPFErrOK;
	}

	if(acceptval_ret){
		acceptval = acceptval_ret;
	}

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * Stop the local endpoint. This should not return until
	 * the datafile is "flushed" into "localfp".
	 */
	(void)_IPFEndpointStop(cntrl->tests,*acceptval,&err);

	/*
	 * If acceptval would have been "success", but stopping of local
	 * endpoints failed, send failure acceptval instead and return error.
	 * (The endpoint_stop_func should have reported the error.)
	 */
	if(!*acceptval && (err2 < IPFErrWARNING)){
		*acceptval = IPF_CNTRL_FAILURE;
		fp = NULL;
	}
	else{
		fp = cntrl->tests->localfp;
	}

	err = (IPFErrSeverity)_IPFWriteStopSession(cntrl,intr,*acceptval,fp);
	if(err < IPFErrWARNING)
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	err2 = MIN(err,err2);

	msgtype = IPFReadRequestType(cntrl,intr);
	if(msgtype == IPFReqSockClose){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
				"IPFStopSession:Control socket closed: %M");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}
	if(msgtype != IPFReqStopSession){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid protocol message received...");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	if( (err = _IPFReadStopSession(cntrl,acceptval,intr,
					cntrl->tests->remotefp)) != IPFErrOK){
		return _IPFFailControlSession(cntrl,err);
	}
	err2 = MIN(err,err2);

	err = _IPFCallProcessResults(cntrl->tests);
	err2 = MIN(err,err2);

	err = _IPFTestSessionFree(cntrl->tests,*acceptval);

	cntrl->state &= ~_IPFStateTest;

	return MIN(err,err2);
}

int
IPFStopSessionWait(
	IPFControl		cntrl,
	IPFNum64		*wake,
	int			*retn_on_intr,
	IPFAcceptType		*acceptval_ret,
	IPFErrSeverity		*err_ret
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
	FILE		*fp;

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
		 * Sessions are complete - send StopSession message.
		 */
		*err_ret = IPFStopSession(cntrl,intr,acceptval);
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
		 * Sessions are complete - send StopSession message.
		 */
		*err_ret = IPFStopSession(cntrl,intr,acceptval);

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
			"IPFStopSessionWait: Control socket closed: %M");
		*err_ret = _IPFFailControlSession(cntrl,IPFErrFATAL);
		return -1;
	}
	if(msgtype != 3){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid protocol message received...");
		*err_ret = _IPFFailControlSession(cntrl,IPFErrFATAL);
		return -1;
	}

	*err_ret = _IPFReadStopSession(cntrl,intr,acceptval,
						cntrl->tests->remotefp);
	if(*err_ret != IPFErrOK){
		*err_ret = _IPFFailControlSession(cntrl,*err_ret);
		return -1;
	}

	/*
	 * Stop the local endpoint. This should not return until
	 * the datafile is "flushed" into "localfp".
	 */
	(void)_IPFEndpointStop(cntrl->tests,*acceptval,&err2);
	if(err2 < IPFErrWARNING){
		*acceptval = IPF_CNTRL_FAILURE;
		fp = NULL;
	}
	else{
		fp = cntrl->tests->localfp;
	}
	*err_ret = MIN(*err_ret,err2);

	if( (err2 = _IPFWriteStopSession(cntrl,intr,*acceptval,fp)) !=
								IPFErrOK){
		(void)_IPFFailControlSession(cntrl,err2);
	}
	*err_ret = MIN(*err_ret,err2);

	err2 = _IPFCallProcessResults(cntrl->tests);
	*err_ret = MIN(*err_ret,err2);

	while(cntrl->tests){
		err2 = _IPFTestSessionFree(cntrl->tests,*acceptval);
		*err_ret = MIN(*err_ret,err2);
	}

	cntrl->state &= ~_IPFStateTest;

	*err_ret = MIN(*err_ret, err2);
	return 0;
}
