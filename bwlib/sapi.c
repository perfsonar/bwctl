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
 *	bwlib server application.
 */
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bwlib/bwlibP.h>

static BWLAddr
AddrByWildcard(
	BWLContext	ctx
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	BWLAddr		addr;
	int		ai_err;


	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if( (ai_err = getaddrinfo(NULL,BWL_CONTROL_SERVICE_NAME,&hints,&ai)!=0)
								|| !ai){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"getaddrinfo(): %s",gai_strerror(ai_err));
		return NULL;
	}

	if( !(addr = _BWLAddrAlloc(ctx))){
		freeaddrinfo(ai);
		return NULL;
	}

	addr->ai = ai;

	return addr;
}

static BWLBoolean
SetServerAddrInfo(
	BWLContext	ctx,
	BWLAddr		addr,
	BWLErrSeverity	*err_ret
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	int		ai_err;
	char		*port=NULL;

	if(!addr || (addr->fd > -1)){
		*err_ret = BWLErrFATAL;
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,"Invalid address");
		return False;
	}

	if(addr->ai)
		return True;

	if(!addr->node_set){
		*err_ret = BWLErrFATAL;
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,"Invalid address");
		return False;
	}

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if(addr->port_set)
		port = addr->port;
	else
		port = BWL_CONTROL_SERVICE_NAME;

	if( (ai_err = getaddrinfo(addr->node,port,&hints,&ai)!=0) || !ai){
		*err_ret = BWLErrFATAL;
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"getaddrinfo(): %s",
							gai_strerror(ai_err));
		return False;
	}
	addr->ai = ai;

	return True;
}

/*
 * This function should only be called on an BWLAddr that already has
 * a fd associated with it.
 */
static BWLBoolean
AddrSetSAddr(
	BWLAddr		addr,
	struct sockaddr	*fromaddr,
	socklen_t	fromaddrlen,
	BWLErrSeverity	*err_ret
	)
{
	int			so_type;
	socklen_t		so_typesize = sizeof(so_type);
	struct sockaddr		*saddr=NULL;
	struct addrinfo		*ai=NULL;
	struct sockaddr_in	v4addr;
	int			gai;

	*err_ret = BWLErrOK;

	if(!addr || (addr->fd < 0)){
		BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,"Invalid address");
		goto error;
	}

	if(addr->saddr && addr->saddrlen)
		return True;

	if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
				(void*)&so_type,&so_typesize) != 0){
		BWLError(addr->ctx,BWLErrFATAL,errno,
				"getsockopt():%s",strerror(errno));
		goto error;
	}

	if( !(saddr = malloc(sizeof(struct sockaddr_storage))) ||
				!(ai = malloc(sizeof(struct addrinfo)))){
		BWLError(addr->ctx,BWLErrFATAL,errno,"malloc():%s",
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
			BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,
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
		BWLError(addr->ctx,BWLErrWARNING,BWLErrUNKNOWN,
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
	*err_ret = BWLErrFATAL;
	return False;
}

/*
 * This function should only be called on an BWLAddr that already has
 * a fd associated with it.
 */
static BWLBoolean
AddrSetSockName(
	BWLAddr		addr,
	BWLErrSeverity	*err_ret
	)
{
	struct sockaddr_storage	sbuff;
	socklen_t		so_size = sizeof(sbuff);

	if(!addr || (addr->fd < 0)){
		BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,"Invalid address");
		goto error;
	}

	if(getsockname(addr->fd,(void*)&sbuff,&so_size) != 0){
		BWLError(addr->ctx,BWLErrFATAL,errno,
				"getsockname():%s",strerror(errno));
		goto error;
	}

	return AddrSetSAddr(addr,(struct sockaddr *)&sbuff,so_size,err_ret);

error:
	*err_ret = BWLErrFATAL;
	return False;
}

static int
OpenSocket(
	BWLContext	ctx	__attribute__((unused)),
	int		family,
	BWLAddr		addr
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
 * Function:	BWLServerSockCreate
 *
 * Description:	
 * 		Used by server to create the initial listening socket.
 * 		(It is not required that the server use this interface,
 * 		but it will be kept up-to-date and in sync with the
 * 		client BWLControlOpen function. For example, both of
 * 		these functions currently give priority to IPV6 addresses
 * 		over IPV4.)
 *
 * 		The addr should be NULL for a wildcard socket, or bound to
 * 		a specific interface using BWLAddrByNode or BWLAddrByAddrInfo.
 *
 * 		This function will create the socket, bind it, and set the
 * 		"listen" backlog length.
 *
 * 		If addr is set using BWLAddrByFD, it will cause an error.
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
BWLAddr
BWLServerSockCreate(
	BWLContext	ctx,
	BWLAddr		addr,
	BWLErrSeverity	*err_ret
	)
{
	int		fd = -1;

	*err_ret = BWLErrOK;

	/*
	 * AddrByFD is invalid.
	 */
	if(addr && (addr->fd > -1)){
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
			"Invalid BWLAddr record - fd already specified.");
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
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
			"BWLServerSockCreate:%M");
		goto error;
	}

	/*
	 * We have a bound socket - set the listen backlog.
	 */
	if(listen(addr->fd,BWL_LISTEN_BACKLOG) < 0){
		BWLError(ctx,BWLErrFATAL,errno,"listen(%d,%d):%s",
				addr->fd,BWL_LISTEN_BACKLOG,strerror(errno));
		goto error;
	}

	return addr;

error:
	BWLAddrFree(addr);
	*err_ret = BWLErrFATAL;
	return NULL;

}

/*
 * Function:	BWLControlAccept
 *
 * Description:	
 * 		This function is used to initialiize the communication
 * 		to the peer.
 *           
 * In Args:	
 * 		connfd,connsaddr, and connsaddrlen are all returned
 * 		from "accept".
 *
 * Returns:	Valid BWLControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
BWLControl
BWLControlAccept(
	BWLContext	ctx,		/* library context		*/
	int		connfd,		/* connected socket		*/
	struct sockaddr	*connsaddr,	/* connected socket addr	*/
	socklen_t	connsaddrlen,	/* connected socket addr len	*/
	u_int32_t	mode_offered,	/* advertised server mode	*/
	BWLNum64	uptime,		/* uptime for server		*/
	int		*retn_on_intr,	/* if *retn_on_intr return	*/
	BWLErrSeverity	*err_ret	/* err - return			*/
)
{
	BWLControl	cntrl;
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

	*err_ret = BWLErrOK;

	if ( !(cntrl = _BWLControlAlloc(ctx,err_ret)))
		goto error;

	cntrl->sockfd = connfd;
	cntrl->server = True;

	/*
	 * set up remote_addr for policy decisions, and log reporting.
	 *
	 * set fd_user false to make BWLAddrFree of remote_addr close the
	 * socket. (This will happen from BWLControlClose.)
	 */
	if(!(cntrl->remote_addr = BWLAddrBySockFD(ctx,connfd)))
		goto error;
	cntrl->remote_addr->fd_user = False;
	if(!AddrSetSAddr(cntrl->remote_addr,connsaddr,connsaddrlen,err_ret))
		goto error;
	/*
	 * set up local_addr for policy decisions, and log reporting.
	 */
	if( !(cntrl->local_addr = BWLAddrBySockFD(ctx,connfd))){
		*err_ret = BWLErrFATAL;
		goto error;
	}
	if(!AddrSetSockName(cntrl->local_addr,err_ret))
		goto error;

	BWLError(ctx,BWLErrINFO,BWLErrPOLICY,
		 "Connection to (%s:%s) from (%s:%s)",
		 cntrl->local_addr->node,cntrl->local_addr->port,
		 cntrl->remote_addr->node, cntrl->remote_addr->port);

	/* generate 16 random bytes of challenge and save them away. */
	if(I2RandomBytes(ctx->rand_src,challenge, 16) != 0){
		*err_ret = BWLErrFATAL;
		goto error;
	}

	if(gettimeofday(&tvalstart,NULL)!=0){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"gettimeofday():%M");
		*err_ret = BWLErrFATAL;
		goto error;
	}
	if( (rc = _BWLWriteServerGreeting(cntrl,mode_offered,
					challenge,intr)) < BWLErrOK){
		*err_ret = (BWLErrSeverity)rc;
		goto error;
	}

	/*
	 * If no mode offered, immediately close socket after sending
	 * server greeting.
	 */
	if(!mode_offered){
		BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
	"Control request to (%s:%s) denied from (%s:%s): mode == 0",
			 cntrl->local_addr->node,cntrl->local_addr->port,
			 cntrl->remote_addr->node,cntrl->remote_addr->port);
		goto error;
	}

	if((rc = _BWLReadClientGreeting(cntrl,&cntrl->mode,rawtoken,
				       cntrl->readIV,intr)) < BWLErrOK){
		*err_ret = (BWLErrSeverity)rc;
		goto error;
	}
	if(gettimeofday(&tvalend,NULL)!=0){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"gettimeofday():%M");
		*err_ret = BWLErrFATAL;
		goto error;
	}
	tvalsub(&tvalend,&tvalstart);
	BWLTimevalToNum64(&cntrl->rtt_bound,&tvalend);

	/* insure that exactly one mode is chosen */
	if(	(cntrl->mode != BWL_MODE_OPEN) &&
			(cntrl->mode != BWL_MODE_AUTHENTICATED) &&
			(cntrl->mode != BWL_MODE_ENCRYPTED)){
		*err_ret = BWLErrFATAL;
		goto error;
	}

	if(!(cntrl->mode | mode_offered)){ /* can't provide requested mode */
		BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
	"Control request to (%s:%s) denied from (%s:%s):mode not offered (%u)",
			 cntrl->local_addr->node,cntrl->local_addr->port,
			 cntrl->remote_addr->node,
			 cntrl->remote_addr->port,cntrl->mode);
		if( (rc = _BWLWriteServerOK(cntrl,BWL_CNTRL_REJECT,0,intr)) <
								BWLErrOK){
			*err_ret = (BWLErrSeverity)rc;
		}
		goto error;
	}
	
	if(cntrl->mode & (BWL_MODE_AUTHENTICATED|BWL_MODE_ENCRYPTED)){
		u_int8_t	binKey[16];
		BWLBoolean	getkey_success;
		
		/* Fetch the encryption key into binKey */
		/*
		 * go through the motions of decrypting token even if
		 * getkey fails to find username to minimize vulnerability
		 * to timing attacks.
		 */
		getkey_success = _BWLCallGetAESKey(cntrl->ctx,
				cntrl->userid_buffer,binKey,err_ret);
		if(!getkey_success && (*err_ret != BWLErrOK)){
			(void)_BWLWriteServerOK(cntrl,BWL_CNTRL_FAILURE,0,intr);
			goto error;
		}
		
		if (BWLDecryptToken(binKey,rawtoken,token) < 0){
			BWLError(cntrl->ctx,BWLErrFATAL,
					BWLErrUNKNOWN,
					"Encryption state problem?!?!");
			(void)_BWLWriteServerOK(cntrl,
						BWL_CNTRL_FAILURE,0,intr);
			*err_ret = BWLErrFATAL;
			goto error;
		}
		
		/* Decrypted challenge is in the first 16 bytes */
		if((memcmp(challenge,token,16) != 0) || !getkey_success){
			if(!getkey_success){
				BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
					"Unknown userid (%s)",
					cntrl->userid_buffer);
			}
			else{
				BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
 "Control request to (%s:%s) denied from (%s:%s):Invalid challenge encryption",
					cntrl->local_addr->node,
					cntrl->local_addr->port,
					cntrl->remote_addr->node,
					cntrl->remote_addr->port);
			}
			(void)_BWLWriteServerOK(cntrl,BWL_CNTRL_REJECT,0,intr);
			goto error;
		}

		/* Authentication ok - set encryption fields */
		cntrl->userid = cntrl->userid_buffer;
		if(I2RandomBytes(cntrl->ctx->rand_src,cntrl->writeIV,16) != 0){
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"Unable to fetch randomness...");
			(void)_BWLWriteServerOK(cntrl,BWL_CNTRL_FAILURE,0,intr);
			goto error;
		}
		memcpy(cntrl->session_key,&token[16],16);
		_BWLMakeKey(cntrl,cntrl->session_key); 
	}

	if(!_BWLCallCheckControlPolicy(cntrl,cntrl->mode,cntrl->userid, 
		  cntrl->local_addr->saddr,cntrl->remote_addr->saddr,err_ret)){
		if(*err_ret > BWLErrWARNING){
			BWLError(ctx,BWLErrINFO,BWLErrPOLICY,
       "ControlSession request to (%s:%s) denied from userid(%s):(%s:%s)",
				cntrl->local_addr->node,cntrl->local_addr->port,
				(cntrl->userid)?cntrl->userid:"nil",
				cntrl->remote_addr->node,
				cntrl->remote_addr->port);
			/*
			 * send mode of 0 to client, and then close.
			 */
			(void)_BWLWriteServerOK(cntrl,BWL_CNTRL_REJECT,0,intr);
		}
		else{
			BWLError(ctx,*err_ret,BWLErrUNKNOWN,
						"Policy function failed.");
			(void)_BWLWriteServerOK(cntrl,BWL_CNTRL_FAILURE,0,intr);
		}
		goto error;
	}

	/*
	 * Made it through the gauntlet - accept the control session!
	 */
	if( (rc = _BWLWriteServerOK(cntrl,BWL_CNTRL_ACCEPT,uptime,intr)) <
								BWLErrOK){
		*err_ret = (BWLErrSeverity)rc;
		goto error;
	}
	BWLError(ctx,BWLErrINFO,BWLErrPOLICY,
		"ControlSession([%s]:%s) accepted from userid(%s):([%s]:%s)",
		cntrl->local_addr->node,cntrl->local_addr->port,
		(cntrl->userid)?cntrl->userid:"nil",
		cntrl->remote_addr->node,
		cntrl->remote_addr->port);
	
	return cntrl;

error:
	BWLControlClose(cntrl);
	return NULL;
}

BWLErrSeverity
BWLProcessTestRequest(
	BWLControl	cntrl,
	int		*retn_on_intr
		)
{
	BWLTestSession	tsession = cntrl->tests;
	BWLErrSeverity	err_ret=BWLErrOK;
	int		rc;
	BWLAcceptType	acceptval = BWL_CNTRL_FAILURE;
	int		ival=0;
	int		*intr = &ival;
	BWLNum64	one64 = BWLULongToNum64(1);
	BWLAddr		raddr;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	/*
	 * Read the TestRequest and alloate tsession to hold the information.
	 */
	if((rc = _BWLReadTestRequest(cntrl,intr,&tsession,&acceptval)) !=
								BWLErrOK){
		switch(acceptval){
			case BWL_CNTRL_INVALID:
				 return BWLErrFATAL;
			case BWL_CNTRL_FAILURE:
			case BWL_CNTRL_UNSUPPORTED:
				return BWLErrWARNING;
			default:
				/* NOTREACHED */
				abort();
		}
	}

	if(!BWLGetTimeStamp(cntrl->ctx,&tsession->localtime)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"BWLGetTimeStamp(): %M");
		err_ret = BWLErrWARNING;
		acceptval = BWL_CNTRL_FAILURE;
		goto error;
	}

	/*
	 * Initialize reservation time.
	 */
	tsession->reserve_time = BWLULongToNum64(0);

	/*
	 * Update of current reservation.
	 */
	if(tsession == cntrl->tests){
		/*
		 * If req_time is 0, client is cancelling.
		 */
		if(tsession->test_spec.req_time.tstamp == 0){
			err_ret = BWLErrINFO;
			acceptval = BWL_CNTRL_REJECT;
			goto error;
		}
	}
	/*
	 * If this "new" session is a receiver session, create a SID for it.
	 */
	else if(tsession->conf_receiver && (_BWLCreateSID(tsession) != 0)){
		err_ret = BWLErrWARNING;
		acceptval = BWL_CNTRL_FAILURE;
		goto error;
	}

	/*
	 * compute "fuzz" time.
	 * Round the NTP error on both side up to one second and add.
	 * In most cases this will give us a "fuzz" of 2 seconds.
	 */
	tsession->fuzz = BWLNum64Max(one64,
			BWLGetTimeStampError(&tsession->test_spec.req_time));
	tsession->fuzz = BWLNum64Add(tsession->fuzz,
				BWLNum64Max(one64,
				BWLGetTimeStampError(&tsession->localtime)));
	/*
	 * Add a constant to make up for the fact that iperf -u usually
	 * run for some fraction of a second longer than the -t option
	 * specifies.
	 *
	 * TODO: Make this constant configurable somehow?
	 */
	tsession->fuzz = BWLNum64Add(tsession->fuzz,BWLULongToNum64(1));

	/*
	 * TODO:
	 * Determine if this check is really needed... The StartSession
	 * command causes the two servers to handshake before running a
	 * test, so perhaps this is not needed. I'm not sure the check
	 * the (local_addr == remote_addr) is good enough to determine
	 * a connection is coming from the local host. (hosts with multiple
	 * addrs may have their addrs talking to each other...)
	 *
	 * Check for possible DoS.
	 * (control-client MUST be same address as remote test if openmode
	 * unless the request is coming from the local host.)
	 */
	raddr = (tsession->conf_sender)?
			tsession->test_spec.receiver:
					tsession->test_spec.sender;

	if(!(cntrl->mode & BWL_MODE_DOCIPHER) &&
			(I2SockAddrEqual(cntrl->remote_addr->saddr,
					 cntrl->remote_addr->saddrlen,
					 raddr->saddr,
					 raddr->saddrlen,
					 I2SADDR_ADDR) <= 0) &&
			!I2SockAddrIsLoopback(cntrl->remote_addr->saddr,
					cntrl->remote_addr->saddrlen) &&
			(I2SockAddrEqual(cntrl->remote_addr->saddr,
					 cntrl->remote_addr->saddrlen,
					 cntrl->local_addr->saddr,
					 cntrl->local_addr->saddrlen,
					 I2SADDR_ADDR) <= 0)){
		BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
		"Test Denied: OpenMode remote_addr(%s) != control_client(%s)",
					raddr->node,cntrl->remote_addr->node);
		BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
		"Test Denied: OpenMode local_addr(%s) != control_client(%s)",
					cntrl->local_addr->node,
					cntrl->remote_addr->node);
		acceptval = BWL_CNTRL_REJECT;
		err_ret = BWLErrINFO;
		goto error;
	}

	if(!_BWLCallCheckTestPolicy(cntrl,tsession,&err_ret)){
		if(err_ret < BWLErrOK)
			goto error;
		BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
							"Test not allowed");
		acceptval = BWL_CNTRL_REJECT;
		err_ret = BWLErrINFO;
		goto error;
	}

	if( (rc = _BWLWriteTestAccept(cntrl,intr,BWL_CNTRL_ACCEPT,tsession))
								< BWLErrOK){
		err_ret = (BWLErrSeverity)rc;
		goto err2;
	}

	/*
	 * Add tsession to list of tests managed by this control connection.
	 */
	cntrl->tests = tsession;

	return BWLErrOK;

error:
	/*
	 * If it is a non-fatal error, communication should continue, so
	 * send negative accept.
	 */
	if(err_ret >= BWLErrWARNING)
		(void)_BWLWriteTestAccept(cntrl,intr,acceptval,tsession);

err2:
	if(tsession)
		_BWLTestSessionFree(tsession,BWL_CNTRL_FAILURE);

	return err_ret;
}

BWLErrSeverity
BWLProcessTimeRequest(
	BWLControl	cntrl,
	int		*retn_on_intr
	)
{
	int		rc;
	int		ival=0;
	int		*intr = &ival;
	BWLTimeStamp	tstamp;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if( (rc = _BWLReadTimeRequest(cntrl,intr)) < BWLErrOK)
		return _BWLFailControlSession(cntrl,rc);

	if(!BWLGetTimeStamp(cntrl->ctx,&tstamp))
		return _BWLFailControlSession(cntrl,BWLErrFATAL);

	if( (rc = _BWLWriteTimeResponse(cntrl,&tstamp,intr)) < BWLErrOK)
		return _BWLFailControlSession(cntrl,rc);

	return BWLErrOK;
}

BWLErrSeverity
BWLProcessStartSession(
	BWLControl	cntrl,
	int		*retn_on_intr
	)
{
	int		rc;
	BWLErrSeverity	err=BWLErrOK;
	int		ival=0;
	int		*intr = &ival;
	u_int16_t	dataport = 0;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if( (rc = _BWLReadStartSession(cntrl,&dataport,intr)) < BWLErrOK)
		return _BWLFailControlSession(cntrl,rc);

	if(!_BWLEndpointStart(cntrl->tests,&dataport,&err)){
		(void)_BWLWriteStartAck(cntrl,intr,0,BWL_CNTRL_FAILURE);
		return _BWLFailControlSession(cntrl,err);
	}

	if( (rc = _BWLWriteStartAck(cntrl,intr,dataport,BWL_CNTRL_ACCEPT))
								< BWLErrOK)
		return _BWLFailControlSession(cntrl,rc);


	return BWLErrOK;
}

/*
 * Function:	BWLSessionStatus
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
 * 			>=0	Valid BWLAcceptType - see enum for meaning.
 * Side Effect:	
 */
BWLBoolean
BWLSessionStatus(
		BWLControl	cntrl,
		BWLSID		sid,
		BWLAcceptType	*aval
		)
{
	BWLTestSession	tsession;
	BWLErrSeverity	err;

	/*
	 * First find the tsession record for this test.
	 */
	tsession = cntrl->tests;
	if(!tsession || (memcmp(sid,tsession->sid,sizeof(BWLSID)) != 0))
		return False;

	return _BWLEndpointStatus(tsession,aval,&err);
}

int
BWLSessionsActive(
		BWLControl	cntrl,
		BWLAcceptType	*aval
		)
{
	BWLTestSession	tsession;
	BWLAcceptType	laval = 0;
	BWLErrSeverity	err;

	tsession = cntrl->tests;
	if(tsession && _BWLEndpointStatus(tsession,&laval,&err) && (laval < 0))
		return 1;

	if(aval)
		*aval = laval;

	return 0;
}

BWLErrSeverity
BWLStopSession(
	BWLControl	cntrl,
	int		*retn_on_intr,
	BWLAcceptType	*acceptval_ret	/* in/out	*/
		)
{
	BWLErrSeverity	err,err2=BWLErrOK;
	BWLRequestType	msgtype;
	BWLAcceptType	aval=BWL_CNTRL_ACCEPT;
	BWLAcceptType	*acceptval=&aval;
	int		ival=0;
	int		*intr=&ival;
	FILE		*fp;

	if(!cntrl->tests){
		return BWLErrOK;
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
	(void)_BWLEndpointStop(cntrl->tests,*acceptval,&err2);

	/*
	 * If acceptval would have been "success", but stopping of local
	 * endpoints failed, send failure acceptval instead and return error.
	 * (The endpoint_stop_func should have reported the error.)
	 */
	if(!*acceptval && (err2 < BWLErrWARNING)){
		*acceptval = BWL_CNTRL_FAILURE;
		fp = NULL;
	}
	else{
		fp = cntrl->tests->localfp;
	}

	err = (BWLErrSeverity)_BWLWriteStopSession(cntrl,intr,*acceptval,fp);
	if(err < BWLErrWARNING)
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	err2 = MIN(err,err2);

	msgtype = BWLReadRequestType(cntrl,intr);
	if(msgtype == BWLReqSockClose){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
				"BWLStopSession:Control socket closed: %M");
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}
	if(msgtype != BWLReqStopSession){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"Invalid protocol message received...");
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}

	if( (err = _BWLReadStopSession(cntrl,acceptval,intr,
					cntrl->tests->remotefp)) != BWLErrOK){
		return _BWLFailControlSession(cntrl,err);
	}
	err2 = MIN(err,err2);

	err = _BWLCallProcessResults(cntrl->tests);
	err2 = MIN(err,err2);

	err = _BWLTestSessionFree(cntrl->tests,*acceptval);

	cntrl->state &= ~_BWLStateTest;

	return MIN(err,err2);
}

int
BWLStopSessionWait(
	BWLControl		cntrl,
	BWLNum64		*wake,
	int			*retn_on_intr,
	BWLAcceptType		*acceptval_ret,
	BWLErrSeverity		*err_ret
	)
{
	struct timeval	currtime;
	struct timeval	reltime;
	struct timeval	*waittime = NULL;
	fd_set		readfds;
	fd_set		exceptfds;
	int		rc;
	int		msgtype;
	BWLErrSeverity	err2=BWLErrOK;
	BWLAcceptType	aval;
	BWLAcceptType	*acceptval=&aval;
	int		ival=0;
	int		*intr=&ival;
	FILE		*fp;

	*err_ret = BWLErrOK;
	if(acceptval_ret){
		acceptval = acceptval_ret;
	}
	*acceptval = BWL_CNTRL_ACCEPT;

	if(retn_on_intr){
		intr = retn_on_intr;
	}

	if(!cntrl || cntrl->sockfd < 0){
		*err_ret = BWLErrFATAL;
		return -1;
	}

	/*
	 * If there are no active sessions, get the status and return.
	 */
	if(!BWLSessionsActive(cntrl,acceptval) || (*acceptval)){
		/*
		 * Sessions are complete - send StopSession message.
		 */
		*err_ret = BWLStopSession(cntrl,intr,acceptval);
		return 0;
	}

	if(wake){
		BWLTimeStamp	wakestamp;

		/*
		 * convert abs wake time to timeval
		 */
		wakestamp.tstamp = *wake;
		BWLTimeStampToTimeval(&reltime,&wakestamp);

		/*
		 * get current time.
		 */
		if(gettimeofday(&currtime,NULL) != 0){
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
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
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"select():%M");
			*err_ret = BWLErrFATAL;
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
		if(BWLSessionsActive(cntrl,acceptval) && !*acceptval){
			goto AGAIN;
		}

		/*
		 * Sessions are complete - send StopSession message.
		 */
		*err_ret = BWLStopSession(cntrl,intr,acceptval);

		return 0;
	}
	if(rc == 0)
		return 1;

	if(!FD_ISSET(cntrl->sockfd,&readfds) &&
					!FD_ISSET(cntrl->sockfd,&exceptfds)){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"select():cntrl fd not ready?:%M");
		*err_ret = _BWLFailControlSession(cntrl,BWLErrFATAL);
		return -1;
	}

	msgtype = BWLReadRequestType(cntrl,intr);
	if(msgtype == 0){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
			"BWLStopSessionWait: Control socket closed: %M");
		*err_ret = _BWLFailControlSession(cntrl,BWLErrFATAL);
		return -1;
	}
	if(msgtype != 3){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"Invalid protocol message received...");
		*err_ret = _BWLFailControlSession(cntrl,BWLErrFATAL);
		return -1;
	}

	*err_ret = _BWLReadStopSession(cntrl,intr,acceptval,
						cntrl->tests->remotefp);
	if(*err_ret != BWLErrOK){
		*err_ret = _BWLFailControlSession(cntrl,*err_ret);
		return -1;
	}

	/*
	 * If StopSessions was sent with accept==0, then make EndpointStop
	 * wait for the local endpoint to exit before continuing.
	 */
	if(*acceptval == 0){
		cntrl->tests->endpoint->dont_kill = 1;
	}

	/*
	 * Stop the local endpoint. This should not return until
	 * the datafile is "flushed" into "localfp".
	 */
	(void)_BWLEndpointStop(cntrl->tests,*acceptval,&err2);
	if(err2 < BWLErrWARNING){
		*acceptval = BWL_CNTRL_FAILURE;
		fp = NULL;
	}
	else{
		fp = cntrl->tests->localfp;
	}
	*err_ret = MIN(*err_ret,err2);

	if( (err2 = _BWLWriteStopSession(cntrl,intr,*acceptval,fp)) !=
								BWLErrOK){
		(void)_BWLFailControlSession(cntrl,err2);
	}
	*err_ret = MIN(*err_ret,err2);

	err2 = _BWLCallProcessResults(cntrl->tests);
	*err_ret = MIN(*err_ret,err2);

	while(cntrl->tests){
		err2 = _BWLTestSessionFree(cntrl->tests,*acceptval);
		*err_ret = MIN(*err_ret,err2);
	}

	cntrl->state &= ~_BWLStateTest;

	*err_ret = MIN(*err_ret, err2);
	return 0;
}
