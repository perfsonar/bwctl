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
 *	an ipcntrl client application.
 */
#include <I2util/util.h>
#include <ipcntrl/ipcntrlP.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>

/*
 * Function:	_IPFClientBind
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
 * 	Additionally err_ret will be set to IPFErrFATAL if there was a
 * 	problem with the local_addr.
 * Side Effect:	
 */
static IPFBoolean
_IPFClientBind(
	IPFControl	cntrl,
	int		fd,
	IPFAddr		local_addr,
	struct addrinfo	*remote_addrinfo,
	IPFErrSeverity	*err_ret
)
{
	struct addrinfo	*ai;

	*err_ret = IPFErrOK;

	/*
	 * Ensure local_addr is not from a fd.
	 */
	if(local_addr->fd > -1){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
						"Invalid local_addr - ByFD");
		*err_ret = IPFErrFATAL;
		return False;
	}

	/*
	 * if getaddrinfo has not been called for this IPFAddr, then call
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
			IPFError(cntrl->ctx,IPFErrFATAL,
				IPFErrUNKNOWN,"Invalid localaddr specified");
			*err_ret = IPFErrFATAL;
			return False;
		}

		if(local_addr->port_set)
			port = local_addr->port;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		if(((gai = getaddrinfo(local_addr->node,port,&hints,&airet))!=0)
							|| !airet){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"getaddrinfo(): %s",gai_strerror(gai));
			*err_ret = IPFErrFATAL;
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
					IPFError(cntrl->ctx,IPFErrFATAL,errno,
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
 * 	the given IPFAddr.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static IPFBoolean
SetClientAddrInfo(
	IPFControl	cntrl,
	IPFAddr		addr,
	IPFErrSeverity	*err_ret
	)
{
	struct addrinfo	*ai=NULL;
	struct addrinfo	hints;
	const char	*node=NULL;
	const char	*port=NULL;
	int		gai;

	if(!addr){
		*err_ret = IPFErrFATAL;
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
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
		port = IPF_CONTROL_SERVICE_NAME;

	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if(((gai = getaddrinfo(node,port,&hints,&ai))!=0) || !ai){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
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
	IPFControl	cntrl,
	struct addrinfo	*ai,
	IPFAddr		local_addr,
	IPFAddr		server_addr
	)
{
	IPFErrSeverity	addr_ok=IPFErrOK;
	int		fd;

	fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
	if(fd < 0)
		return 1;

	if(local_addr){
		if(!_IPFClientBind(cntrl,fd,local_addr,ai,&addr_ok)){
			if(addr_ok != IPFErrOK){
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
 * Function:	_IPFClientConnect
 *
 * Description:	
 * 	This function attempts to create a socket connection between
 * 	the local client and the server. Each specified with IPFAddr
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
_IPFClientConnect(
	IPFControl	cntrl,
	IPFAddr		local_addr,
	IPFAddr		server_addr,
	IPFErrSeverity	*err_ret
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

	IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"Unable to connect to %s",tstr);

error:
	*err_ret = IPFErrFATAL;

	return -1;
}

/*
 * Function:	IPFControlOpen
 *
 * Description:	
 * 		Opens a connection to an ipcntrl server. Returns after complete
 * 		control connection setup is complete. This means that encrytion
 * 		has been intialized, and the client is authenticated to the
 * 		server if that is necessary. However, the client has not
 * 		verified the server at this point.
 *
 * Returns:	
 * 		A valid IPFControl pointer or NULL.
 * Side Effect:	
 */
IPFControl
IPFControlOpen(
	IPFContext	ctx,		/* control context	*/
	IPFAddr		local_addr,	/* local addr or null	*/
	IPFAddr		server_addr,	/* server addr		*/
	u_int32_t	mode_req_mask,	/* requested modes	*/
	IPFUserID	userid,		/* userid or NULL	*/
	IPFNum64	*uptime_ret,	/* server uptime - ret	*/
	IPFErrSeverity	*err_ret	/* err - return		*/
)
{
	int		rc;
	IPFControl	cntrl;
	u_int32_t	mode_avail;
	u_int8_t	key_value[16];
	u_int8_t	challenge[16];
	u_int8_t	token[32];
	u_int8_t	*key=NULL;
	IPFAcceptType	acceptval;
	struct timeval	tvalstart,tvalend;
	IPFNum64	uptime;

	*err_ret = IPFErrOK;

	/*
	 * First allocate memory for the control state.
	 */
	if( !(cntrl = _IPFControlAlloc(ctx,err_ret)))
		goto error;

	/*
	 * Initialize server record for address we are connecting to.
	 */
	if((!server_addr) &&
		!(server_addr = IPFAddrByNode(cntrl->ctx,"localhost"))){
		goto error;
	}

	/*
	 * Connect to the server.
	 * Address policy check happens in here.
	 */
	if(_IPFClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
		goto error;

	/*
	 * Read the server greating.
	 */
	if((rc=_IPFReadServerGreeting(cntrl,&mode_avail,challenge)) < IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
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
		(mode_avail & IPF_MODE_DOCIPHER)){
		strncpy(cntrl->userid_buffer,userid,
					sizeof(cntrl->userid_buffer)-1);
		if(_IPFCallGetAESKey(cntrl->ctx,cntrl->userid_buffer,key_value,
								err_ret)){
			key = key_value;
			cntrl->userid = cntrl->userid_buffer;
		}
		else{
			if(*err_ret != IPFErrOK)
				goto error;
		}
	}
	/*
	 * If no key, then remove auth/crypt modes
	 */
	if(!key)
		mode_avail &= ~IPF_MODE_DOCIPHER;

	/*
	 * Pick "highest" level mode still available to this server.
	 */
	if((mode_avail & IPF_MODE_ENCRYPTED) &&
			_IPFCallCheckControlPolicy(cntrl,IPF_MODE_ENCRYPTED,
				cntrl->userid,
				(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = IPF_MODE_ENCRYPTED;
	}
	else if((*err_ret == IPFErrOK) &&
			(mode_avail & IPF_MODE_AUTHENTICATED) &&
			_IPFCallCheckControlPolicy(cntrl,IPF_MODE_AUTHENTICATED,
				cntrl->userid,
				(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = IPF_MODE_AUTHENTICATED;
	}
	else if((*err_ret == IPFErrOK) &&
			(mode_avail & IPF_MODE_OPEN) &&
			_IPFCallCheckControlPolicy(cntrl,IPF_MODE_OPEN,
				NULL,(local_addr)?local_addr->saddr:NULL,
				server_addr->saddr,err_ret)){
		cntrl->mode = IPF_MODE_OPEN;
	}
	else if(*err_ret != IPFErrOK){
		goto error;
	}
	else{
		IPFError(ctx,IPFErrINFO,IPFErrPOLICY,
				"IPFControlOpen:No Common Modes");
		goto denied;
	}

	/*
	 * Initialize all the encryption values as necessary.
	 */
	if(cntrl->mode & IPF_MODE_DOCIPHER){
		/*
		 * Create "token" for ClientGreeting message.
		 * Section 4.1 of ipcntrl spec:
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
		_IPFMakeKey(cntrl,cntrl->session_key);

		/*
		 * Encrypt the token as specified by Section 4.1
		 */
		if(IPFEncryptToken(key,buf,token) != 0)
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
	if( ((rc=_IPFWriteClientGreeting(cntrl,token)) < IPFErrOK) ||
			((rc=_IPFReadServerOK(cntrl,&acceptval)) < IPFErrOK)){
		*err_ret = (IPFErrSeverity)rc;
		goto error;
	}

	if(acceptval != IPF_CNTRL_ACCEPT){
		IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,
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
	IPFTimevalToNum64(&cntrl->rtt_bound,&tvalend);

	if((rc=_IPFReadServerUptime(cntrl,&uptime)) < IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
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
	*err_ret = IPFErrFATAL;

	/*
	 * If access was denied - cleanup memory and return.
	 */
denied:
	if(cntrl->local_addr != local_addr)
		IPFAddrFree(local_addr);
	if(cntrl->remote_addr != server_addr)
		IPFAddrFree(server_addr);
	IPFControlClose(cntrl);
	return NULL;
}

/*
 * Function:	SetEndpointAddrInfo
 *
 * Description:	
 * 	Initialize the IPFAddr record's addrinfo section for an Endpoint
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
static IPFBoolean
SetEndpointAddrInfo(
	IPFControl	cntrl,
	IPFAddr		addr,
	IPFErrSeverity	*err_ret
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
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
						"Invalid test address");
		return False;
	}

	/*
	 * Already done!
	 */
	if(addr->ai)
		return True;

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
			IPFError(cntrl->ctx,IPFErrFATAL,
				errno,"getsockname():%s",
				strerror(errno));
			goto error;
		}

		/*
		 * Determine "type" of socket.
		 */
		if(getsockopt(addr->fd,SOL_SOCKET,SO_TYPE,
				(void*)&so_type,&so_typesize) != 0){
			IPFError(cntrl->ctx,IPFErrFATAL,
				errno,"getsockopt():%s",
				strerror(errno));
			goto error;
		}

		if(! (saddr = malloc(so_size))){
			IPFError(cntrl->ctx,IPFErrFATAL,
				errno,"malloc():%s",strerror(errno));
			goto error;
		}
		memcpy((void*)saddr,(void*)&sbuff,so_size);
		
		/*
		 * create an addrinfo to describe this sockaddr
		 */
		if(! (ai = malloc(sizeof(struct addrinfo)))){
			IPFError(cntrl->ctx,IPFErrFATAL,
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
		 * Set IPFAddr ai
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
		hints.ai_socktype = SOCK_DGRAM;

		if(addr->port_set)
			port = addr->port;
		if(((rc = getaddrinfo(addr->node,port,&hints,&ai))!=0) || !ai){
			IPFError(cntrl->ctx,IPFErrFATAL,
				errno,"getaddrinfo(): %s", gai_strerror(rc));
			goto error;
		}
		addr->ai = ai;

	}else{
		/*
		 * Empty IPFAddr record - report error.
		 */
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
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
	*err_ret = IPFErrFATAL;
	return FALSE;
}

/*
 * Function:	_IPFClientRequestTestReadResponse
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
_IPFClientRequestTestReadResponse(
	IPFControl	cntrl,
	IPFAddr		sender,
	IPFBoolean	server_conf_sender,
	IPFAddr		receiver,
	IPFBoolean	server_conf_receiver,
	IPFTestSpec	*test_spec,
	IPFSID		sid,		/* ret iff conf_receiver else set */
	IPFErrSeverity	*err_ret
	)
{
	int		rc;
	IPFAcceptType	acceptval;
	struct sockaddr	*set_addr=NULL;
	u_int16_t	port_ret=NULL;
	u_int8_t	*sid_ret=NULL;

	if((rc = _IPFWriteTestRequest(cntrl, sender->saddr, receiver->saddr,
				      server_conf_sender, server_conf_receiver,
				      sid, test_spec)) < IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
		return 1;
	}

	/*
	 * Figure out if the server will be returning Port field.
	 * If so - set set_addr to the sockaddr that needs to be set.
	 */
	if(server_conf_sender && !server_conf_receiver)
		set_addr = sender->saddr;
	else if(!server_conf_sender && server_conf_receiver)
		set_addr = receiver->saddr;

	if(server_conf_receiver)
		sid_ret = sid;

	if((rc = _IPFReadTestAccept(cntrl,&acceptval,&port_ret,sid_ret)) <
								IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
		return 1;
	}

	/*
	 * If it was determined that the server returned a port,
	 * figure out the correct offset into set_addr for the type
	 * of sockaddr, and set  the port in the saddr to the
	 * port_ret value.
	 * (Don't you just love the joy's of supporting multiple AF's?)
	 */
	if(set_addr){
		switch(set_addr->sa_family){
			struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
			struct sockaddr_in6	*saddr6;

			case AF_INET6:
				saddr6 = (struct sockaddr_in6*)set_addr;
				saddr6->sin6_port = htons(port_ret);
				break;
#endif
			case AF_INET:
				saddr4 = (struct sockaddr_in*)set_addr;
				saddr4->sin_port = htons(port_ret);
				break;
			default:
				IPFError(cntrl->ctx,
						IPFErrFATAL,IPFErrINVALID,
						"Invalid address family");
				return 1;
		}
	}


	if(acceptval == IPF_CNTRL_ACCEPT)
		return 0;

	IPFError(cntrl->ctx,IPFErrINFO,IPFErrPOLICY,"Server denied test");

	*err_ret = IPFErrOK;
	return 1;
}

/*
 * Function:	IPFAddrByLocalControl
 *
 * Description:	
 * 	Create an IPFAddr record for the local address based upon the
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
IPFAddr
IPFAddrByLocalControl(
		   IPFControl	cntrl
		   )
{
	struct addrinfo		*ai=NULL;
	IPFAddr			addr;
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
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
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
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
						"Invalid address family");
			return NULL;
	}
	*port = 0;

	/*
	 * Allocate an IPFAddr record to assign the data into.
	 */
	if( !(addr = _IPFAddrAlloc(cntrl->ctx)))
		return NULL;

	if( !(ai = calloc(1,sizeof(struct addrinfo))) ||
					!(addr->saddr = calloc(1,len))){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,"malloc():%M");
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
	ai->ai_socktype = SOCK_DGRAM;
	ai->ai_protocol = IPPROTO_IP;	/* reasonable default */
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;

	addr->ai = ai;
	addr->ai_free = True;
	addr->so_type = SOCK_DGRAM;
	addr->so_protocol = IPPROTO_IP;

	return addr;

error:
	if(addr)
		IPFAddrFree(addr);
	if(ai)
		free(ai);

	return NULL;
}

/*
 * Function:	IPFSessionRequest
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
 * 	not IPFErrOK, the control connection is probably no longer valid.)
 * Side Effect:	
 */
IPFBoolean
IPFSessionRequest(
	IPFControl	cntrl,
	IPFAddr		sender,
	IPFBoolean	server_conf_sender,
	IPFAddr		receiver,
	IPFBoolean	server_conf_receiver,
	IPFTestSpec	*test_spec,
	FILE		*fp,
	IPFSID		sid_ret,
	IPFErrSeverity	*err_ret
)
{
	struct addrinfo		*rai=NULL;
	struct addrinfo		*sai=NULL;
	IPFTestSession		tsession = NULL;
	int			rc=0;

	*err_ret = IPFErrOK;

	/*
	 * Check cntrl state is appropriate for this call.
	 * (this would happen as soon as we tried to call the protocol
	 * function - but it saves a lot of misplaced work to check now.)
	 */
	if(!cntrl || !_IPFStateIsRequest(cntrl)){
		*err_ret = IPFErrFATAL;
		IPFError(cntrl->ctx,*err_ret,IPFErrINVALID,
		"IPFSessionRequest called with invalid cntrl record");
		goto error;
	}

	/*
	 * If NULL passed in for recv address - fill it in with local
	 */
	if(!receiver){
		if(server_conf_receiver)
			receiver = IPFAddrByNode(cntrl->ctx,"localhost");
		else
			receiver = IPFAddrByLocalControl(cntrl);
		if(!receiver)
			goto error;
	}

	/*
	 * If NULL passed in for send address - fill it in with local
	 */
	if(!sender){
		if(server_conf_sender)
			sender = IPFAddrByNode(cntrl->ctx,"localhost");
		else
			sender = IPFAddrByLocalControl(cntrl);
		if(!sender)
			goto error;
	}

	/*
	 * Get addrinfo for address spec's so we can choose between
	 * the different address possiblities in the next step. (These
	 * ai will be SOCK_DGRAM unless an fd was passed in directly, in
	 * which case we trust the application knows what it is doing...)
	 */
	if(!SetEndpointAddrInfo(cntrl,receiver,err_ret) ||
				!SetEndpointAddrInfo(cntrl,sender,err_ret))
		goto error;
	/*
	 * Determine proper address specifications for send/recv.
	 * Loop on ai values to find a match and use that.
	 * (We prefer IPV6 over others, so loop over IPv6 addrs first...)
	 * We only support AF_INET and AF_INET6.
	 */
#ifdef	AF_INET6
	for(rai = receiver->ai;rai;rai = rai->ai_next){
		if(rai->ai_family != AF_INET6) continue;
		for(sai = sender->ai;sai;sai = sai->ai_next){
			if(rai->ai_family != sai->ai_family) continue;
			if(rai->ai_socktype != sai->ai_socktype) continue;
			goto foundaddr;
		}
	}
#endif
	for(rai = receiver->ai;rai;rai = rai->ai_next){
		if(rai->ai_family != AF_INET) continue;
		for(sai = sender->ai;sai;sai = sai->ai_next){
			if(rai->ai_family != sai->ai_family) continue;
			if(rai->ai_socktype != sai->ai_socktype) continue;
			goto foundaddr;
		}
	}

	/*
	 * Didn't find compatible addrs - return error.
	 */
	*err_ret = IPFErrWARNING;
	IPFError(cntrl->ctx,*err_ret,IPFErrINVALID,
		"IPFSessionRequest called with incompatible addresses");
	goto error;

foundaddr:
	/*
	 * Fill IPFAddr records with "selected" addresses for test.
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
	if( !(tsession = _IPFTestSessionAlloc(cntrl,sender,server_conf_sender,
				receiver,server_conf_receiver,test_spec)))
		goto error;

	/*
	 * This section initializes the two endpoints for the test.
	 * EndpointInit is used to create a local socket and allocate
	 * a port for the local side of the test.
	 *
	 * EndpointInitHook is used to set the information for the
	 * remote side of the test and then the Endpoint process
	 * is forked off.
	 *
	 * The request to the server is interwoven in based upon which
	 * side needs to happen first. (The receiver needs to be initialized
	 * first because the SID comes from there - so, if conf_receiver
	 * then the request is sent to the server, and then other work
	 * happens. If the client is the receiver, then the local
	 * initialization needs to happen before sending the request.)
	 */

	/*
	 * Configure receiver first since the sid comes from there.
	 */
	if(server_conf_receiver){
		/*
		 * If send local, check local policy for sender
		 */
		if(!server_conf_sender){
			/*
			 * create the local sender
			 */
			if(!_IPFEndpointInit(cntrl,tsession,sender,NULL,
								err_ret)){
				goto error;
			}
		}
		else{
			/*
			 * This request will fail with the sample implementation
			 * ipcntrld. ipcntrld is not prepared to configure both
			 * endpoints - but let the test request go through
			 * here anyway.  It will allow a client of the
			 * sample implementation to be used with a possibly
			 * more robust server.
			 */
			;
		}

		/*
		 * Request the server create the receiver & possibly the
		 * sender.
		 */
		if((rc = _IPFClientRequestTestReadResponse(cntrl,
					sender,server_conf_sender,
					receiver,server_conf_receiver,
					test_spec,tsession->sid,err_ret)) != 0){
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
			goto error;
		}

		/*
		 * If sender is local, complete it's initialization now that
		 * we know the receiver port number.
		 */
		if(!server_conf_sender){
			/*
			 * check local policy for this sender
			 * (had to call policy check after initialize
			 * because schedule couldn't be computed until
			 * we got the SID from the server.)
			 */
			if(!_IPFCallCheckTestPolicy(cntrl,True,
					sender->saddr,receiver->saddr,
					sender->saddrlen,
					test_spec,&tsession->closure,err_ret)){
				IPFError(cntrl->ctx,*err_ret,IPFErrPOLICY,
					"Test not allowed");
				goto error;
			}

			if(!_IPFEndpointInitHook(cntrl,tsession,err_ret)){
				goto error;
			}
		}
	}
	else{
		/*
		 * local receiver - create SID and compute schedule.
		 */
		if(_IPFCreateSID(tsession) != 0){
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
			goto error;
		}

		/*
		 * Local receiver - first check policy, then create.
		 */
		if(!_IPFCallCheckTestPolicy(cntrl,False,receiver->saddr,
					sender->saddr,sender->saddrlen,
					test_spec,
					&tsession->closure,err_ret)){
			IPFError(cntrl->ctx,*err_ret,IPFErrPOLICY,
					"Test not allowed");
			goto error;
		}
		if(!_IPFEndpointInit(cntrl,tsession,receiver,fp,err_ret)){
			goto error;
		}


		/*
		 * If conf_sender - make request to server
		 */
		if(server_conf_sender){
			if((rc = _IPFClientRequestTestReadResponse(cntrl,
					sender,server_conf_sender,
					receiver,server_conf_receiver,
					test_spec,tsession->sid,err_ret)) != 0){
				goto error;
			}
		}
		else{
			/*
			 * This is a VERY strange situation - the
			 * client is setting up a test session without
			 * making a request to the server...
			 *
			 * Just return an error here...
			 */
			IPFError(cntrl->ctx,*err_ret,IPFErrPOLICY,
					"Test not allowed");
			goto error;
		}
		if(!_IPFEndpointInitHook(cntrl,tsession,err_ret)){
			goto error;
		}
	}

	/*
	 * Server accepted our request, and we were able to initialize our
	 * side of the test. Add this "session" to the tests list for this
	 * control connection.
	 */
	tsession->next = cntrl->tests;
	cntrl->tests = tsession;

	/*
	 * return the SID for this session to the caller.
	 */
	memcpy(sid_ret,tsession->sid,sizeof(IPFSID));

	return True;

error:
	if(tsession){
		_IPFTestSessionFree(tsession,IPF_CNTRL_FAILURE);
	}
	else{
		/*
		 * If tsession exists - the addr's will be free'd as part
		 * of it - otherwise, do it here.
		 */
		IPFAddrFree(receiver);
		IPFAddrFree(sender);
	}

	return False;
}

/*
 * Function:	IPFStartSessions
 *
 * Description:	
 * 	This function is used by applications to send the StartSessions
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
IPFErrSeverity
IPFStartSessions(
	IPFControl	cntrl
)
{
	int		rc;
	IPFErrSeverity	err,err2=IPFErrOK;
	IPFTestSession	tsession;
	IPFAcceptType	acceptval;

	/*
	 * Must pass valid cntrl record.
	 */
	if(!cntrl){
		IPFError(NULL,IPFErrFATAL,IPFErrINVALID,
		"IPFStartSessions called with invalid cntrl record");
		return IPFErrFATAL;
	}

	/*
	 * Send the StartSessions message to the server
	 */
	if((rc = _IPFWriteStartSessions(cntrl)) < IPFErrOK){
		return _IPFFailControlSession(cntrl,rc);
	}

	/*
	 * Small optimization... - start local receivers while waiting for
	 * the server to respond. (should not start senders - don't want
	 * to send packets unless control-ack comes back positive.)
	 */
	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->endpoint && !tsession->endpoint->send){
			if(!_IPFEndpointStart(tsession->endpoint,&err)){
				return _IPFFailControlSession(cntrl,err);
			}
			err2 = MIN(err,err2);
		}
	}

	/*
	 * Read the server response.
	 */
	if(((rc = _IPFReadControlAck(cntrl,&acceptval)) < IPFErrOK) ||
					(acceptval != IPF_CNTRL_ACCEPT)){
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	/*
	 * Now start local senders.
	 */
	for(tsession = cntrl->tests;tsession;tsession = tsession->next){
		if(tsession->endpoint && tsession->endpoint->send){
			if(!_IPFEndpointStart(tsession->endpoint,&err)){
				return _IPFFailControlSession(cntrl,err);
			}
			err2 = MIN(err,err2);
		}
	}

	return err2;
}

/*
 * Function:	IPFDelay
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
IPFDelay(
	IPFTimeStamp	*send_time,
	IPFTimeStamp	*recv_time
	)
{
	return IPFNum64ToDouble(recv_time->ipftime) -
			IPFNum64ToDouble(send_time->ipftime);
}

/*
 * Function:	IPFFetchSession
 *
 * Description:	
 *	This function is used to request that the data for the TestSession
 *	identified by sid be fetched from the server and copied to the
 *	file pointed at by fp. This function assumes fp is currently pointing
 *	at an open file, and that fp is ready to write at the begining of the
 *	file.
 *
 *	To request an entire session set begin = 0, and end = 0xFFFFFFFF.
 *	(This is only valid if the session is complete - otherwise the server
 *	should deny this request.)
 *	Otherwise, "begin" and "end" refer to sequence numbers in the test
 *	session.
 *	The number of records returned will not necessarily be end-begin due
 *	to possible loss and/or duplication.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 *	The number of data records in the file. If < 1, check err_ret to
 *	find out if it was an error condition: ErrOK just means the request
 *	was denied by the server. ErrWARNING means there was a local
 *	problem (fp not writeable etc...) and the control connection is
 *	still valid.
 * Side Effect:	
 */
u_int64_t
IPFFetchSession(
	IPFControl		cntrl,
	FILE			*fp,
	u_int32_t		begin,
	u_int32_t		end,
	IPFSID			sid,
	IPFErrSeverity		*err_ret
	)
{
	IPFAcceptType		acceptval;
	IPFTestSession		tsession = NULL;
	IPFSessionHeaderRec	hdr;
	u_int64_t		num_rec,n;
	u_int8_t		buf[_IPF_FETCH_BUFFSIZE];
	int			i;
	IPFBoolean		dowrite = True;

	*err_ret = IPFErrOK;

	if(!fp){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
						"IPFFetchSession: Invalid fp");
		*err_ret = IPFErrFATAL;
		return 0;
	}

	/*
	 * Make the request of the server.
	 */
	if((*err_ret = _IPFWriteFetchSession(cntrl,begin,end,sid)) <
								IPFErrWARNING)
		goto failure;

	/*
	 * Read the response
	 */
	if((*err_ret = _IPFReadControlAck(cntrl, &acceptval)) < IPFErrWARNING)
		goto failure;
	
	/*
	 * If the server didn't accept, we are done.
	 */
	if(acceptval != IPF_CNTRL_ACCEPT)
		return 0;

	if((*err_ret = _IPFReadTestRequest(cntrl,NULL,&tsession,NULL)) !=
								IPFErrOK){
		goto failure;
	}

	/*
	 * Write the file header now. First encode the tsession into
	 * a SessionHeader.
	 */

	assert(sizeof(hdr.addr_sender) >= tsession->sender->saddrlen);
	memcpy(&hdr.addr_sender,tsession->sender->saddr,
						tsession->sender->saddrlen);
	memcpy(&hdr.addr_receiver,tsession->receiver->saddr,
						tsession->receiver->saddrlen);

	hdr.conf_sender = tsession->conf_sender;
	hdr.conf_receiver = tsession->conf_receiver;

	memcpy(hdr.sid,tsession->sid,sizeof(hdr.sid));
		/* hdr.test_spec will now point at same slots memory. */
	hdr.test_spec = tsession->test_spec;

	if(IPFWriteDataHeader(cntrl->ctx,fp,&hdr) != 0){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"IPFFetchSession: IPFWriteDataHeader(): %M");
		*err_ret = IPFErrWARNING;
		(void)_IPFTestSessionFree(tsession,IPF_CNTRL_INVALID);
		dowrite = True;
	}

	/*
	 * Read the RecordsHeader from the server. Just the number of
	 * data records that will follow.
	 */
	if((*err_ret = _IPFReadFetchRecordsHeader(cntrl,&num_rec)) <
								IPFErrWARNING)
		goto failure;


	for(n=num_rec;
			n >= _IPF_FETCH_TESTREC_BLOCKS;
				n -= _IPF_FETCH_TESTREC_BLOCKS){
		if(_IPFReceiveBlocks(cntrl,buf,_IPF_FETCH_AES_BLOCKS) !=
							_IPF_FETCH_AES_BLOCKS){
			*err_ret = IPFErrFATAL;
			goto failure;
		}
		if(dowrite && (fwrite(buf,_IPF_TESTREC_SIZE,
					_IPF_FETCH_TESTREC_BLOCKS,fp) !=
						_IPF_FETCH_TESTREC_BLOCKS)){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"IPFFetchSession: fwrite(): %M");
			dowrite = False;
		}
	}

	if(n){
		/*
		 * Read enough AES blocks to get remaining records.
		 */
		int	blks = n*_IPF_TESTREC_SIZE/_IPF_RIJNDAEL_BLOCK_SIZE + 1;

		if(_IPFReceiveBlocks(cntrl,buf,blks) != blks){
			*err_ret = IPFErrFATAL;
			goto failure;
		}
		if(dowrite && (fwrite(buf,_IPF_TESTREC_SIZE,n,fp) != n)){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"IPFFetchSession: fwrite(): %M");
			dowrite = False;
		}
		/* check zero padding */
		for(i=(n*_IPF_TESTREC_SIZE);
				i < (blks*_IPF_RIJNDAEL_BLOCK_SIZE);i++){
			if(buf[i] != 0){
				IPFError(cntrl->ctx,IPFErrINFO,IPFErrUNKNOWN,
				"IPFFetchSession: record padding non-zero");
			}
		}
	}

	fflush(fp);

	/*
	 * Read final MBZ AES block to finalize transaction.
	 */
	if(_IPFReceiveBlocks(cntrl,buf,1) != 1){
		*err_ret = IPFErrFATAL;
		goto failure;
	}

	if(memcmp(cntrl->zero,buf,_IPF_RIJNDAEL_BLOCK_SIZE)){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"IPFFetchSession:Final MBZ block corrupt");
		*err_ret = IPFErrFATAL;
		goto failure;
	}

	/*
	 * reset state to request.
	 */
	cntrl->state &= ~_IPFStateFetching;
	cntrl->state |= _IPFStateRequest;

	if(!dowrite){
		*err_ret = IPFErrWARNING;
		num_rec = 0;
	}

	return num_rec;

failure:
	(void)_IPFFailControlSession(cntrl,*err_ret);
	return 0;
}
