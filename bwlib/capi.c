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
 *	File:		capi.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:25:27 MDT 2003
 *
 *	Description:	
 *
 *	This file contains the api functions that are typically called from
 *	an bwlib client application.
 */
#include <I2util/util.h>
#include <bwlib/bwlibP.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>

/*
 * Function:	_BWLClientBind
 *
 * Description:	
 * 	This function attempts to bind the fd to a local address allowing
 * 	the client socket to have the source addr bound.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * 	True if successful, False if unsuccessful.
 * 	Additionally err_ret will be set to BWLErrFATAL if there was a
 * 	problem with the local_addr.
 * Side Effect:	
 */
static BWLBoolean
_BWLClientBind(
	BWLControl	cntrl,
	int		fd,
	BWLAddr		local_addr,
	struct addrinfo	*remote_addrinfo,
	BWLErrSeverity	*err_ret
)
{
	struct addrinfo	*ai;

	*err_ret = BWLErrOK;

	/*
	 * Ensure local_addr is not from a fd.
	 */
	if(local_addr->fd > -1){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
						"Invalid local_addr - ByFD");
		*err_ret = BWLErrFATAL;
		return False;
	}

	/*
	 * if getaddrinfo has not been called for this BWLAddr, then call
	 * it.
	 */
	if(!local_addr->ai){
		/*
		 * Call getaddrinfo to find useful addresses
		 */
		struct addrinfo	hints, *airet;
		const char	*port=NULL;
		int		gai;

		if(!local_addr->node_set){
			BWLError(cntrl->ctx,BWLErrFATAL,
				BWLErrUNKNOWN,"Invalid localaddr specified");
			*err_ret = BWLErrFATAL;
			return False;
		}

		if(local_addr->port_set)
			port = local_addr->port;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if(((gai = getaddrinfo(local_addr->node,port,&hints,&airet))!=0)
							|| !airet){
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"getaddrinfo(): %s",gai_strerror(gai));
			*err_ret = BWLErrFATAL;
			return False;
		}

		local_addr->ai = airet;
	}

	/*
	 * Now that we have a valid addrinfo list for this address, go
	 * through each of those addresses and try to bind the first
	 * one that matches addr family and socktype.
	 */
	for(ai=local_addr->ai;ai;ai = ai->ai_next){
		if(ai->ai_family != remote_addrinfo->ai_family)
			continue;
		if(ai->ai_socktype != remote_addrinfo->ai_socktype)
			continue;

		if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){
			local_addr->saddr = ai->ai_addr;
			local_addr->saddrlen = ai->ai_addrlen;
			return True;
		}else{
			switch(errno){
				/* report these errors */
				case EAGAIN:
				case EBADF:
				case ENOTSOCK:
				case EADDRNOTAVAIL:
				case EADDRINUSE:
				case EACCES:
				case EFAULT:
					BWLError(cntrl->ctx,BWLErrFATAL,errno,
							"bind(): %M");
					break;
				/* ignore all others */
				default:
					break;
			}
			return False;
		}

	}

	/*
	 * None found.
	 */
	return False;
}

/*
 * Function:	SetClientAddrInfo
 *
 * Description:	
 * 	PRIVATE function for initializing the addrinfo portion of
 * 	the given BWLAddr.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static BWLBoolean
SetClientAddrInfo(
	BWLControl	cntrl,
	BWLAddr		addr,
	BWLErrSeverity	*err_ret
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	const char	*node=NULL;
	const char	*port=NULL;
	int		gai;

	if(!addr){
		*err_ret = BWLErrFATAL;
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
							"Invalid address");
		return False;
	}

	if(addr->ai)
		return True;

	/*
	 * Call getaddrinfo to find useful addresses
	 */

	if(addr->node_set)
		node = addr->node;
	if(addr->port_set)
		port = addr->port;
	else
		port = BWL_CONTROL_SERVICE_NAME;

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if(((gai = getaddrinfo(node,port,&hints,&ai))!=0) || !ai){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"getaddrinfo(): %s",gai_strerror(gai));
		return False;
	}

	addr->ai = ai;
	return True;
}

/*
 * Function:	TryAddr
 *
 * Description:	
 * 	This function attempts to connect to the given ai description of
 * 	the "server" addr possibly binding to "local" addr.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 *	-1: error - future trys are unlikely to succeed - terminate upward.
 *	 0: success - wahoo!
 *	 1: keep trying - this one didn't work, probably addr mismatch.
 * Side Effect:	
 */
/*
 */
static int
TryAddr(
	BWLControl	cntrl,
	struct addrinfo	*ai,
	BWLAddr		local_addr,
	BWLAddr		server_addr
	)
{
	BWLErrSeverity	addr_ok=BWLErrOK;
	int		fd;

	fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
	if(fd < 0)
		return 1;

	if(local_addr){
		if(!_BWLClientBind(cntrl,fd,local_addr,ai,&addr_ok)){
			if(addr_ok != BWLErrOK){
				return -1;
			}
			goto cleanup;
		}
	}

	/*
	 * Call connect - if it succeeds, return else try again.
	 */
	if(connect(fd,ai->ai_addr,ai->ai_addrlen) == 0){
		server_addr->fd = fd;
		server_addr->saddr = ai->ai_addr;
		server_addr->saddrlen = ai->ai_addrlen;
		server_addr->so_type = ai->ai_socktype;
		server_addr->so_protocol = ai->ai_protocol;
		cntrl->remote_addr = server_addr;
		cntrl->local_addr = local_addr;
		cntrl->sockfd = fd;

		return 0;
	}

cleanup:
	while((close(fd) < 0) && (errno == EINTR));
	return 1;
}

/*
 * Function:	_BWLClientConnect
 *
 * Description:	
 * 	This function attempts to create a socket connection between
 * 	the local client and the server. Each specified with BWLAddr
 * 	records. If the local_addr is not specified, then the source
 * 	addr is not bound. The server_addr is used to get a valid list
 * 	of addrinfo records and each addrinfo description record is
 * 	tried until one succeeds. (IPV6 is prefered over IPV4)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static int
_BWLClientConnect(
	BWLControl	cntrl,
	BWLAddr		local_addr,
	BWLAddr		server_addr,
	BWLErrSeverity	*err_ret
)
{
	int		rc;
	struct addrinfo	*ai=NULL;
	char		*tstr;

	if(!server_addr)
		goto error;

	/*
	 * Easy case - application provided socket directly.
	 */
	if(server_addr->fd > -1){
		cntrl->remote_addr = server_addr;
		cntrl->sockfd = server_addr->fd;
		return 0;
	}

	/*
	 * Initialize addrinfo portion of server_addr record.
	 */
	if(!SetClientAddrInfo(cntrl,server_addr,err_ret))
		goto error;

	/*
	 * Now that we have addresses - see if it is valid by attempting
	 * to create a socket of that type, and binding(if wanted).
	 * Also check policy for allowed connection before calling
	 * connect.
	 * (Binding will call the policy function internally.)
	 */
#ifdef	AF_INET6
	for(ai=server_addr->ai;ai;ai=ai->ai_next){

		if(ai->ai_family != AF_INET6) continue;

		if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0)
			return 0;
		if(rc < 0)
			goto error;
	}
#endif
	/*
	 * Now try IPv4 addresses.
	 */
	for(ai=server_addr->ai;ai;ai=ai->ai_next){

		if(ai->ai_family != AF_INET) continue;

		if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0)
			return 0;
		if(rc < 0)
			goto error;
	}

	/*
	 * Unable to connect! If we have a server name report it in
	 * the error message.
	 */
	if(server_addr->node_set)
		tstr = server_addr->node;
	else
		tstr = "Server";

	BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
			"Unable to connect to %s",tstr);

error:
	*err_ret = BWLErrFATAL;

	return -1;
}

/*
 * Function:	BWLControlOpen
 *
 * Description:	
 * 		Opens a connection to an bwlib server. Returns after complete
 * 		control connection setup is complete. This means that encrytion
 * 		has been intialized, and the client is authenticated to the
 * 		server if that is necessary. However, the client has not
 * 		verified the server at this point.
 *
 * Returns:	
 * 		A valid BWLControl pointer or NULL.
 * Side Effect:	
 */
BWLControl
BWLControlOpen(
	BWLContext	ctx,		/* control context	*/
	BWLAddr		local_addr,	/* local addr or null	*/
	BWLAddr		server_addr,	/* server addr		*/
	u_int32_t	mode_req_mask,	/* requested modes	*/
	BWLUserID	userid,		/* userid or NULL	*/
	BWLNum64	*uptime_ret,	/* server uptime - ret	*/
	BWLErrSeverity	*err_ret	/* err - return		*/
)
{
	int		rc;
	BWLControl	cntrl;
	u_int32_t	mode_avail;
	u_int8_t	key_value[16];
	u_int8_t	challenge[16];
	u_int8_t	token[32];
	u_int8_t	*key=NULL;
	BWLAcceptType	acceptval;
	struct timeval	tvalstart,tvalend;
	BWLNum64	uptime;

	*err_ret = BWLErrOK;

	/*
	 * First allocate memory for the control state.
	 */
	if( !(cntrl = _BWLControlAlloc(ctx,err_ret)))
		goto error;

	/*
	 * Initialize server record for address we are connecting to.
	 */
	if((!server_addr) &&
		!(server_addr = BWLAddrByNode(cntrl->ctx,"localhost"))){
		goto error;
	}

	/*
	 * Connect to the server.
	 * Address policy check happens in here.
	 */
	if(_BWLClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
		goto error;

	/*
	 * Read the server greating.
	 */
	if((rc=_BWLReadServerGreeting(cntrl,&mode_avail,challenge)) < BWLErrOK){
		*err_ret = (BWLErrSeverity)rc;
		goto error;
	}

	/*
	 * Select mode wanted...
	 */
	mode_avail &= mode_req_mask;	/* mask out unwanted modes */

	/*
	 * retrieve key if needed
	 */
	if(userid &&
		(mode_avail & BWL_MODE_DOCIPHER)){
		strncpy(cntrl->userid_buffer,userid,
					sizeof(cntrl->userid_buffer)-1);
		if(_BWLCallGetAESKey(cntrl->ctx,cntrl->userid_buffer,key_value,
								err_ret)){
			key = key_value;
			cntrl->userid = cntrl->userid_buffer;
		}
		else{
			if(*err_ret != BWLErrOK)
				goto error;
		}
	}
	/*
	 * If no key, then remove auth/crypt modes
	 */
	if(!key)
		mode_avail &= ~BWL_MODE_DOCIPHER;

	/*
	 * Pick "highest" level mode still available to this server.
	 */
	if((mode_avail & BWL_MODE_ENCRYPTED) &&
			_BWLCallCheckControlPolicy(cntrl,BWL_MODE_ENCRYPTED,
				cntrl->userid,
				(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = BWL_MODE_ENCRYPTED;
	}
	else if((*err_ret == BWLErrOK) &&
			(mode_avail & BWL_MODE_AUTHENTICATED) &&
			_BWLCallCheckControlPolicy(cntrl,BWL_MODE_AUTHENTICATED,
				cntrl->userid,
				(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = BWL_MODE_AUTHENTICATED;
	}
	else if((*err_ret == BWLErrOK) &&
			(mode_avail & BWL_MODE_OPEN) &&
			_BWLCallCheckControlPolicy(cntrl,BWL_MODE_OPEN,
				NULL,(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = BWL_MODE_OPEN;
	}
	else if(*err_ret != BWLErrOK){
		goto error;
	}
	else{
		BWLError(ctx,BWLErrINFO,BWLErrPOLICY,
				"BWLControlOpen:No Common Modes");
		goto denied;
	}

	/*
	 * Initialize all the encryption values as necessary.
	 */
	if(cntrl->mode & BWL_MODE_DOCIPHER){
		/*
		 * Create "token" for ClientGreeting message.
		 * Section 4.1 of bwlib spec:
		 * 	AES(concat(challenge(16),sessionkey(16)))
		 */
		unsigned char	buf[32];

		/*
		 * copy challenge
		 */
		memcpy(buf,challenge,16);

		/*
		 * Create random session key
		 */
		if(I2RandomBytes(ctx->rand_src,cntrl->session_key,16) != 0)
			goto error;
		/*
		 * concat session key to buffer
		 */
		memcpy(&buf[16],cntrl->session_key,16);

		/*
		 * Initialize AES structures for use with this
		 * key. (ReadBlock/WriteBlock functions will automatically
		 * use this key for this cntrl connection.
		 */
		_BWLMakeKey(cntrl,cntrl->session_key);

		/*
		 * Encrypt the token as specified by Section 4.1
		 */
		if(BWLEncryptToken(key,buf,token) != 0)
			goto error;

		/*
		 * Create random writeIV
		 */
		if(I2RandomBytes(ctx->rand_src,cntrl->writeIV,16) != 0)
			goto error;
	}

	/*
	 * Get current time before sending client greeting - used
	 * for very rough estimate of RTT. (upper bound)
	 */
	if(gettimeofday(&tvalstart,NULL)!=0)
		goto error;

	/*
	 * Write the client greeting, and see if the Server agree's to it.
	 */
	if( ((rc=_BWLWriteClientGreeting(cntrl,token)) < BWLErrOK) ||
			((rc=_BWLReadServerOK(cntrl,&acceptval)) < BWLErrOK)){
		*err_ret = (BWLErrSeverity)rc;
		goto error;
	}

	if(acceptval != BWL_CNTRL_ACCEPT){
		BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
							"Server denied access");
		goto denied;
	}

	/*
	 * Get current time after response from server and set the RTT
	 * in the "rtt_bound" field of cntrl.
	 */
	if(gettimeofday(&tvalend,NULL)!=0)
		goto error;
	tvalsub(&tvalend,&tvalstart);
	BWLTimevalToNum64(&cntrl->rtt_bound,&tvalend);

	if((rc=_BWLReadServerUptime(cntrl,&uptime)) < BWLErrOK){
		*err_ret = (BWLErrSeverity)rc;
		goto error;
	}

	if(uptime_ret){
		*uptime_ret = uptime;
	}

	/*
	 * Done - return!
	 */
	return cntrl;

	/*
	 * If there was an error - set err_ret, then cleanup memory and return.
	 */
error:
	*err_ret = BWLErrFATAL;

	/*
	 * If access was denied - cleanup memory and return.
	 */
denied:
	if(cntrl->local_addr != local_addr)
		BWLAddrFree(local_addr);
	if(cntrl->remote_addr != server_addr)
		BWLAddrFree(server_addr);
	BWLControlClose(cntrl);
	return NULL;
}

/*
 * Function:	BWLControlTimeCheck
 *
 * Description:	
 * 	Public function used to request the current time from the server.
 * 	(Including the servers "estimate" of it's timestamp.)
 * 	Also updates the clients idea of the rtt_bound to this server.
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
BWLControlTimeCheck(
	BWLControl	cntrl,
	BWLTimeStamp	*time_ret
)
{
	BWLErrSeverity		err;
	BWLTimeStamp		tstamp;

	if((err = _BWLWriteTimeRequest(cntrl)) != BWLErrOK){
		goto error;
	}

	if((err = _BWLReadTimeResponse(cntrl,&tstamp)) != BWLErrOK){
		goto error;
	}

	if(time_ret){
		*time_ret = tstamp;
	}

	return BWLErrOK;

error:
	return _BWLFailControlSession(cntrl,BWLErrFATAL);
}

/*
 * Function:	SetEndpointAddrInfo
 *
 * Description:	
 * 	Initialize the BWLAddr record's addrinfo section for an Endpoint
 * 	of a test. (UDP test with no fixed port number.)
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static BWLBoolean
SetEndpointAddrInfo(
	BWLControl	cntrl,
	BWLAddr		addr,
	int		socktype,
	BWLErrSeverity	*err_ret
)
{
	int			so_type;
	socklen_t		so_typesize = sizeof(so_type);
	struct sockaddr_storage	sbuff;
	socklen_t		so_size = sizeof(sbuff);
	struct sockaddr		*saddr=NULL;
	struct addrinfo		*ai=NULL;
	struct addrinfo		hints;
	char			*port=NULL;
	int			rc;

	/*
	 * Must specify an addr record to this function.
	 */
	if(!addr){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
						"Invalid test address");
		return False;
	}

	/*
	 * Already done!
	 */
	if(addr->ai){
		/*
		 * If this is a faked ai record, then set the socktype
		 */
		if(addr->ai->ai_addr == addr->saddr){
			addr->ai->ai_socktype = socktype;
			addr->so_type = socktype;
		}
		return True;
	}

	/*
	 * Addr was passed in as a fd so application created the
	 * socket itself - determine as much information about the
	 * socket as we can.
	 */
	if(addr->fd > -1){

		/*
		 * Get an saddr to describe the fd...
		 */
		if(getsockname(addr->fd,(void*)&sbuff,&so_size) != 0){
			BWLError(cntrl->ctx,BWLErrFATAL,
				errno,"getsockname():%s",
				strerror(errno));
			goto error;
		}

		/*
		 * Determine "type" of socket.
		 */
		if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
				(void*)&so_type,&so_typesize) != 0){
			BWLError(cntrl->ctx,BWLErrFATAL,
				errno,"getsockopt():%s",
				strerror(errno));
			goto error;
		}

		if(! (saddr = malloc(so_size))){
			BWLError(cntrl->ctx,BWLErrFATAL,
				errno,"malloc():%s",strerror(errno));
			goto error;
		}
		memcpy((void*)saddr,(void*)&sbuff,so_size);
		
		/*
		 * create an addrinfo to describe this sockaddr
		 */
		if(! (ai = malloc(sizeof(struct addrinfo)))){
			BWLError(cntrl->ctx,BWLErrFATAL,
				errno,"malloc():%s",strerror(errno));
			goto error;
		}

		ai->ai_flags = 0;
		ai->ai_family = saddr->sa_family;
		ai->ai_socktype = so_type;
		/*
		 * all necessary info encapsalated by family/socktype,
		 * so default proto to IPPROTO_IP(0).
		 * (Could probably set this to IPPROTO_UDP/IPPROTO_TCP
		 * based upon the socktype, but the 0 default fits
		 * the model for most "socket" calls.)
		 */
		ai->ai_protocol = IPPROTO_IP;
		ai->ai_addrlen = so_size;
		ai->ai_canonname = NULL;
		ai->ai_addr = saddr;
		ai->ai_next = NULL;

		/*
		 * Set BWLAddr ai
		 */
		addr->ai = ai;
		addr->ai_free = True;
	}
	else if(addr->node_set){
		/*
		 * Hey - do the normal thing, call getaddrinfo
		 * to get an addrinfo, how novel!
		 */
		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = socktype;

		if(addr->port_set)
			port = addr->port;
		if(((rc = getaddrinfo(addr->node,port,&hints,&ai))!=0) || !ai){
			BWLError(cntrl->ctx,BWLErrFATAL,
				errno,"getaddrinfo(): %s", gai_strerror(rc));
			goto error;
		}
		addr->ai = ai;

	}else{
		/*
		 * Empty BWLAddr record - report error.
		 */
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
						"Invalid test address");
		goto error;
	}

	/*
	 * success!
	 */
	return True;

error:
	/*
	 * Failed - free memory and return negative.
	 */
	if(saddr) free(saddr);
	if(ai) free(ai);
	*err_ret = BWLErrFATAL;
	return FALSE;
}

/*
 * Function:	_BWLClientRequestTestReadResponse
 *
 * Description:	
 * 	This function is used to request a test from the server and
 * 	return the response.
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
static int
_BWLClientRequestTestReadResponse(
	BWLControl	cntrl,
	BWLTestSession	tsession,
	BWLErrSeverity	*err_ret
	)
{
	int		rc;
	BWLAcceptType	acceptval;

	if((rc = _BWLWriteTestRequest(cntrl,tsession)) < BWLErrOK){
		*err_ret = (BWLErrSeverity)rc;
		return 1;
	}

	if((rc = _BWLReadTestAccept(cntrl,&acceptval,tsession)) < BWLErrOK){
		*err_ret = (BWLErrSeverity)rc;
		return 1;
	}

	if(acceptval == BWL_CNTRL_ACCEPT)
		return 0;

	BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,"Server denied test");

	*err_ret = BWLErrOK;
	return 1;
}

/*
 * Function:	BWLAddrByControl
 *
 * Description:	
 * 	Create an BWLAddr record for the remote address based upon the
 * 	control socket connection. (wrapper for getpeername)
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
BWLAddrByControl(
		   BWLControl	cntrl
		   )
{
	struct addrinfo		*ai=NULL;
	BWLAddr			addr;
	struct sockaddr_storage	saddr_rec;
	struct sockaddr		*oaddr=(struct sockaddr*)&saddr_rec;
	socklen_t		len;

	/*
	 * copy current socketaddr into saddr_rec
	 */
	if(cntrl->remote_addr && cntrl->remote_addr->saddr){
		len = cntrl->remote_addr->saddrlen;
		memcpy(&saddr_rec,cntrl->remote_addr->saddr,len);
	}else{
		memset(&saddr_rec,0,sizeof(saddr_rec));
		len = sizeof(saddr_rec);
		if(getpeername(cntrl->sockfd,oaddr,&len) != 0){
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"getpeername():%M");
			return NULL;
		}
	}

	/*
	 * If copy was unsuccessful return error.
	 */
	if(!len)
		return NULL;

	/*
	 * Allocate an BWLAddr record to assign the data into.
	 */
	if( !(addr = _BWLAddrAlloc(cntrl->ctx)))
		return NULL;

	if( !(ai = calloc(1,sizeof(struct addrinfo))) ||
					!(addr->saddr = calloc(1,len))){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,"malloc():%M");
		goto error;
	}

	/*
	 * Assign all the fields.
	 */
	memcpy(addr->saddr,oaddr,len);
	ai->ai_addr = addr->saddr;
	addr->saddrlen = len;
	ai->ai_addrlen = len;

	ai->ai_flags = 0;
	ai->ai_family = oaddr->sa_family;
	ai->ai_socktype = SOCK_STREAM;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default */
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->so_type = SOCK_STREAM;
	addr->so_protocol = IPPROTO_IP;

	return addr;

error:
	if(addr)
		BWLAddrFree(addr);
	if(ai)
		free(ai);

	return NULL;
}

/*
 * Function:	BWLAddrByLocalControl
 *
 * Description:	
 * 	Create an BWLAddr record for the local address based upon the
 * 	control socket connection. (This is used to make a test request
 * 	to to the same address that the control connection is coming from -
 * 	it is very useful when you allow the local connection to wildcard
 * 	since the test connection cannot wildcard.
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
BWLAddrByLocalControl(
		   BWLControl	cntrl
		   )
{
	struct addrinfo		*ai=NULL;
	BWLAddr			addr;
	struct sockaddr_storage	saddr_rec;
	struct sockaddr		*oaddr=(struct sockaddr*)&saddr_rec;
	socklen_t		len;
	u_int16_t		*port=NULL;

	/*
	 * copy current socketaddr into saddr_rec
	 */
	if(cntrl->local_addr && cntrl->local_addr->saddr){
		len = cntrl->local_addr->saddrlen;
		memcpy(&saddr_rec,cntrl->local_addr->saddr,len);
	}else{
		memset(&saddr_rec,0,sizeof(saddr_rec));
		len = sizeof(saddr_rec);
		if(getsockname(cntrl->sockfd,oaddr,&len) != 0){
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"getsockname():%M");
			return NULL;
		}
	}

	/*
	 * If copy was unsuccessful return error.
	 */
	if(!len)
		return NULL;

	/*
	 * decode v4 and v6 sockaddrs.
	 */
	switch(oaddr->sa_family){
		struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
		struct sockaddr_in6	*saddr6;

		case AF_INET6:
			saddr6 = (struct sockaddr_in6*)oaddr;
			port = &saddr6->sin6_port;
			break;
#endif
		case AF_INET:
			saddr4 = (struct sockaddr_in*)oaddr;
			port = &saddr4->sin_port;
			break;
		default:
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
						"Invalid address family");
			return NULL;
	}

	*port = htons(BWL_CONTROL_SERVICE_NUMBER);

	/*
	 * Allocate an BWLAddr record to assign the data into.
	 */
	if( !(addr = _BWLAddrAlloc(cntrl->ctx)))
		return NULL;

	if( !(ai = calloc(1,sizeof(struct addrinfo))) ||
					!(addr->saddr = calloc(1,len))){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,"malloc():%M");
		goto error;
	}

	/*
	 * Assign all the fields.
	 */
	memcpy(addr->saddr,oaddr,len);
	ai->ai_addr = addr->saddr;
	addr->saddrlen = len;
	ai->ai_addrlen = len;

	ai->ai_flags = 0;
	ai->ai_family = oaddr->sa_family;
	ai->ai_socktype = SOCK_STREAM;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default */
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->so_type = SOCK_STREAM;
	addr->so_protocol = IPPROTO_IP;

	return addr;

error:
	if(addr)
		BWLAddrFree(addr);
	if(ai)
		free(ai);

	return NULL;
}

/*
 * Function:	BWLSessionRequest
 *
 * Description:	
 * 	Public function used to request a test from the server.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * 	True/False based upon acceptance from server. If False is returned
 * 	check err_ret to see if an error condition exists. (If err_ret is
 * 	not BWLErrOK, the control connection is probably no longer valid.)
 * Side Effect:	
 */
BWLBoolean
BWLSessionRequest(
	BWLControl	cntrl,
	BWLBoolean	send,
	BWLTestSpec	*test_spec,
	BWLTimeStamp	*avail_time_ret,
	u_int16_t	*recv_port,
	BWLSID		sid,
	BWLErrSeverity	*err_ret
)
{
	struct addrinfo		*rai=NULL;
	struct addrinfo		*sai=NULL;
	BWLTestSession		tsession = NULL;
	int			rc=0;
	BWLAddr			receiver=NULL;
	BWLAddr			sender=NULL;
	int			socktype;
	BWLNum64		zero64=BWLULongToNum64(0);

	*err_ret = BWLErrOK;

	/* will be set to non-zero if request params ok */
	avail_time_ret->tstamp = zero64;

	/*
	 * Check cntrl state is appropriate for this call.
	 * (this would happen as soon as we tried to call the protocol
	 * function - but it saves a lot of misplaced work to check now.)
	 */
	if(!cntrl || !_BWLStateIsRequest(cntrl)){
		*err_ret = BWLErrFATAL;
		BWLError(cntrl->ctx,*err_ret,BWLErrINVALID,
		"BWLSessionRequest called with invalid cntrl record");
		goto error;
	}

	/*
	 * Look for existing TestSession with this SID!
	 */
	if(cntrl->tests){
		if(memcmp(sid,cntrl->tests->sid,sizeof(BWLSID))){
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLSessionRequest: sid mis-match");
			goto error;
		}
		tsession = cntrl->tests;
		tsession->test_spec.req_time = test_spec->req_time;
		tsession->test_spec.latest_time = test_spec->latest_time;
		/*
		 * If req_time == 0, this is a reservation cancellation.
		 */
		if(test_spec->req_time.tstamp == zero64)
			goto cancel;
	}else{

		/*
		 * If NULL passed in for recv address - fill it in with local
		 */
		if(test_spec->receiver){
			receiver = _BWLAddrCopy(test_spec->receiver);
		}else{
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLSessionRequest:Invalid receive address");
		}

		if(!receiver)
			goto error;
	
		/*
		 * If NULL passed in for send address - fill it in with local
		 */
		if(test_spec->sender){
			sender = _BWLAddrCopy(test_spec->sender);
		}else{
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLSessionRequest:Invalid receive address");
		}

		if(!sender)
			goto error;
	
		/*
		 * Get addrinfo for address spec's so we can choose between
		 * the different address possiblities in the next step.
		 */
		socktype = (test_spec->udp)? SOCK_DGRAM: SOCK_STREAM;
		if(!SetEndpointAddrInfo(cntrl,receiver,socktype,err_ret) ||
				!SetEndpointAddrInfo(cntrl,sender,socktype,
								err_ret))
			goto error;
	
		/*
		 * Determine proper address specifications for send/recv.
		 * Loop on ai values to find a match and use that.
		 * (We prefer IPV6 over others, so loop over IPv6 addrs
		 * first...) Only supports AF_INET and AF_INET6.
		 */
	#ifdef	AF_INET6
		for(rai = receiver->ai;rai;rai = rai->ai_next){
			if(rai->ai_family != AF_INET6) continue;
			for(sai = sender->ai;sai;sai = sai->ai_next){
				if(rai->ai_family != sai->ai_family) continue;
				if(rai->ai_socktype != sai->ai_socktype)
					continue;
				goto foundaddr;
			}
		}
	#endif
		for(rai = receiver->ai;rai;rai = rai->ai_next){
			if(rai->ai_family != AF_INET) continue;
			for(sai = sender->ai;sai;sai = sai->ai_next){
				if(rai->ai_family != sai->ai_family) continue;
				if(rai->ai_socktype != sai->ai_socktype)
					continue;
				goto foundaddr;
			}
		}
	
		/*
		 * Didn't find compatible addrs - return error.
		 */
		*err_ret = BWLErrWARNING;
		BWLError(cntrl->ctx,*err_ret,BWLErrINVALID,
			"BWLSessionRequest called with incompatible addresses");
		goto error;
	
	foundaddr:
		/*
		 * Fill BWLAddr records with "selected" addresses for test.
		 */
		receiver->saddr = rai->ai_addr;
		receiver->saddrlen = rai->ai_addrlen;
		receiver->so_type = rai->ai_socktype;
		receiver->so_protocol = rai->ai_protocol;
		sender->saddr = sai->ai_addr;
		sender->saddrlen = sai->ai_addrlen;
		sender->so_type = sai->ai_socktype;
		sender->so_protocol = sai->ai_protocol;
	
		/*
		 * Create a structure to store the stuff we need to keep for
		 * later calls.
		 */
		if( !(tsession = _BWLTestSessionAlloc(cntrl,send,sender,
						receiver,*recv_port,test_spec)))
			goto error;
	}

	if(tsession->conf_receiver){
		*recv_port = 0;
	}
	else{
		memcpy(tsession->sid,sid,sizeof(BWLSID));
	}

	/*
	 * Request the server create the receiver & possibly the
	 * sender.
	 */
	if((rc = _BWLClientRequestTestReadResponse(cntrl,tsession,err_ret))
									!= 0){
		goto error;
	}

	avail_time_ret->tstamp = tsession->reserve_time;
	if(recv_port){
		*recv_port = tsession->recv_port;
	}

	/*
	 * Server accepted our request, and we were able to initialize this
	 * side of the test. Add this "session" to the tests list for this
	 * control connection if it isn't there already.
	 */
	if(cntrl->tests != tsession){
		cntrl->tests = tsession;
	}

	/*
	 * return the SID for this session to the caller.
	 */
	if(tsession->conf_receiver){
		memcpy(sid,tsession->sid,sizeof(BWLSID));
	}

	return True;

	{
		BWLAcceptType	acceptval = BWL_CNTRL_FAILURE;
		BWLBoolean	retval = False;
cancel:
		retval = True;

		if(_BWLWriteTestRequest(cntrl,tsession) < BWLErrOK){
			goto error;
		}
		if(_BWLReadTestAccept(cntrl,&acceptval,tsession) < BWLErrOK){
			goto error;
		}

		if(acceptval != BWL_CNTRL_REJECT){
			BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"Reservation Cancellation Error");
			_BWLFailControlSession(cntrl,BWLErrFATAL);
		}

error:
		if(tsession){
			_BWLTestSessionFree(tsession,acceptval);
			if(cntrl->tests == tsession){
				cntrl->tests = NULL;
			}
		}
		else{
			/*
			 * If tsession exists - the addr's will be free'd as
			 * part of it - otherwise, do it here.
			 */
			BWLAddrFree(receiver);
			BWLAddrFree(sender);
		}

		return retval;
	}
}

/*
 * Function:	BWLStartSession
 *
 * Description:	
 * 	This function is used by applications to send the StartSession
 * 	message to the server and to kick of it's side of all sessions.
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
BWLStartSession(
	BWLControl	cntrl,
	u_int16_t	*dataport /* retn for recv - set for send */
)
{
	int		rc;
	BWLAcceptType	acceptval;
	u_int16_t	lport_val = 0;
	u_int16_t	*lport = &lport_val;

	/*
	 * Must pass valid cntrl record.
	 */
	if(!cntrl){
		BWLError(NULL,BWLErrFATAL,BWLErrINVALID,
		"BWLStartSession called with invalid cntrl record");
		return BWLErrFATAL;
	}

	/*
	 * if dataport is non-null, pass the value pointed at by it instead
	 * of the stack value 0.
	 */
	if(dataport){
		lport = dataport;
	}

	/*
	 * Send the StartSession message to the server
	 */
	if((rc = _BWLWriteStartSession(cntrl,*lport)) < BWLErrOK){
		return _BWLFailControlSession(cntrl,rc);
	}

	/*
	 * Read the server response.
	 */
	if(((rc = _BWLReadStartAck(cntrl,lport,&acceptval)) < BWLErrOK) ||
					(acceptval != BWL_CNTRL_ACCEPT)){
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}

	return BWLErrOK;
}

BWLErrSeverity
BWLEndSession(
	BWLControl	cntrl,
	BWLAcceptType	*acceptval,
	FILE		*fp
	)
{
	int		ival = 0;
	int		*intr=&ival;
	BWLRequestType	msgtype;
	BWLAcceptType	aval = BWL_CNTRL_ACCEPT;
	BWLAcceptType	*aptr = &aval;
	BWLErrSeverity	rc;

	if(acceptval)
		aptr = acceptval;

	if( (rc = _BWLWriteStopSession(cntrl,intr,*aptr,NULL)) < BWLErrOK){
		*aptr = BWL_CNTRL_FAILURE;
		return _BWLFailControlSession(cntrl,rc);
	}

	msgtype = BWLReadRequestType(cntrl,intr);
	if(msgtype == BWLReqSockClose){
		BWLError(cntrl->ctx,BWLErrFATAL,errno,
				"BWLEndSession: Control socket closed: %M");
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}
	if(msgtype != BWLReqStopSession){
		BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
			"BWLEndSession: Invalid protocol message received...");
		return _BWLFailControlSession(cntrl,BWLErrFATAL);
	}
	if( (rc = _BWLReadStopSession(cntrl,intr,aptr,fp)) < BWLErrOK){
		return _BWLFailControlSession(cntrl,rc);
	}

	return _BWLTestSessionFree(cntrl->tests,*aptr);
}

/*
 * Function:	BWLDelay
 *
 * Description:	
 * 	Compute delay between two timestamps.
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
BWLDelay(
	BWLTimeStamp	*send_time,
	BWLTimeStamp	*recv_time
	)
{
	return BWLNum64ToDouble(recv_time->tstamp) -
			BWLNum64ToDouble(send_time->tstamp);
}
