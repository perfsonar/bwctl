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
 * Function:	IPFControlTimeCheck
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
IPFErrSeverity
IPFControlTimeCheck(
	IPFControl	cntrl,
	IPFTimeStamp	*time_ret
)
{
	IPFErrSeverity		err;
	IPFTimeStamp		tstamp;

	if((err = _IPFWriteTimeRequest(cntrl)) != IPFErrOK){
		goto error;
	}

	if((err = _IPFReadTimeResponse(cntrl,&tstamp)) != IPFErrOK){
		goto error;
	}

	if(time_ret){
		*time_ret = tstamp;
	}

	return IPFErrOK;

error:
	return _IPFFailControlSession(cntrl,IPFErrFATAL);
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
	int		socktype,
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
		hints.ai_socktype = socktype;

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
	IPFTestSession	tsession,
	IPFErrSeverity	*err_ret
	)
{
	int		rc;
	IPFAcceptType	acceptval;

	if((rc = _IPFWriteTestRequest(cntrl,tsession)) < IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
		return 1;
	}

	if((rc = _IPFReadTestAccept(cntrl,&acceptval,tsession)) < IPFErrOK){
		*err_ret = (IPFErrSeverity)rc;
		return 1;
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

	*port = htons(IPF_CONTROL_SERVICE_NUMBER);

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
	IPFBoolean	send,
	IPFTestSpec	*test_spec,
	IPFTimeStamp	*avail_time_ret,
	u_int16_t	*recv_port,
	IPFSID		sid,
	IPFErrSeverity	*err_ret
)
{
	struct addrinfo		*rai=NULL;
	struct addrinfo		*sai=NULL;
	IPFTestSession		tsession = NULL;
	int			rc=0;
	IPFAddr			receiver=NULL;
	IPFAddr			sender=NULL;
	int			socktype;

	*err_ret = IPFErrOK;

	/* TODO: set to non-zero if request params ok */
	avail_time_ret->ipftime = IPFULongToNum64(0);

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
	 * TODO: Look for existing TestSession with this SID!
	 */
	if(cntrl->tests){
		if(memcmp(sid,cntrl->tests->sid,sizeof(IPFSID))){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFSessionRequest: sid mis-match");
			goto error;
		}
		tsession = cntrl->tests;
		tsession->test_spec.req_time = test_spec->req_time;
		tsession->test_spec.latest_time = test_spec->latest_time;
	}else{

		/*
		 * If NULL passed in for recv address - fill it in with local
		 */
		if(test_spec->receiver){
			receiver = _IPFAddrCopy(test_spec->receiver);
		}else{
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFSessionRequest:Invalid receive address");
		}

		if(!receiver)
			goto error;
	
		/*
		 * If NULL passed in for send address - fill it in with local
		 */
		if(test_spec->sender){
			sender = _IPFAddrCopy(test_spec->sender);
		}else{
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFSessionRequest:Invalid receive address");
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
		if( !(tsession = _IPFTestSessionAlloc(cntrl,send,sender,
						receiver,*recv_port,test_spec)))
			goto error;
	}

	if(tsession->conf_receiver){
		*recv_port = 0;
	}
	else{
		memcpy(tsession->sid,sid,sizeof(IPFSID));
	}

	/*
	 * Request the server create the receiver & possibly the
	 * sender.
	 */
	if((rc = _IPFClientRequestTestReadResponse(cntrl,tsession,err_ret))
									!= 0){
		goto error;
	}

	if(avail_time_ret){
		avail_time_ret->ipftime = tsession->reserve_time;
	}
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
		memcpy(sid,tsession->sid,sizeof(IPFSID));
	}

	return True;

error:
	if(tsession){
		_IPFTestSessionFree(tsession,IPF_CNTRL_FAILURE);
		if(cntrl->tests == tsession)
			cntrl->tests = NULL;
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
 * Function:	IPFStartSession
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
IPFErrSeverity
IPFStartSession(
	IPFControl	cntrl,
	u_int16_t	*dataport /* retn for recv - set for send */
)
{
	int		rc;
	IPFAcceptType	acceptval;
	u_int16_t	lport_val = 0;
	u_int16_t	*lport = &lport_val;

	/*
	 * Must pass valid cntrl record.
	 */
	if(!cntrl){
		IPFError(NULL,IPFErrFATAL,IPFErrINVALID,
		"IPFStartSession called with invalid cntrl record");
		return IPFErrFATAL;
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
	if((rc = _IPFWriteStartSession(cntrl,*lport)) < IPFErrOK){
		return _IPFFailControlSession(cntrl,rc);
	}

	/*
	 * Read the server response.
	 */
	if(((rc = _IPFReadStartAck(cntrl,lport,&acceptval)) < IPFErrOK) ||
					(acceptval != IPF_CNTRL_ACCEPT)){
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}

	return IPFErrOK;
}

IPFErrSeverity
IPFEndSession(
	IPFControl	cntrl,
	IPFAcceptType	*acceptval,
	FILE		*fp
	)
{
	int		ival = 0;
	int		*intr=&ival;
	IPFRequestType	msgtype;
	IPFAcceptType	aval = IPF_CNTRL_ACCEPT;
	IPFAcceptType	*aptr = &aval;
	IPFErrSeverity	rc;

	if(acceptval)
		aptr = acceptval;

	if( (rc = _IPFWriteStopSession(cntrl,intr,*aptr,NULL)) < IPFErrOK){
		*aptr = IPF_CNTRL_FAILURE;
		return _IPFFailControlSession(cntrl,rc);
	}

	msgtype = IPFReadRequestType(cntrl,intr);
	if(msgtype == IPFReqSockClose){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,
				"IPFEndSession: Control socket closed: %M");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}
	if(msgtype != IPFReqStopSession){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"IPFEndSession: Invalid protocol message received...");
		return _IPFFailControlSession(cntrl,IPFErrFATAL);
	}
	if( (rc = _IPFReadStopSession(cntrl,intr,aptr,fp)) < IPFErrOK){
		return _IPFFailControlSession(cntrl,rc);
	}

	return _IPFTestSessionFree(cntrl->tests,*aptr);
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
