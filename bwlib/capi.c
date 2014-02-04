/*
 *      $Id$
 */
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
 *
 *    License:
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
#include <I2util/util.h>
#include <bwlib/bwlibP.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>

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
        const char      *local_addr,
        struct addrinfo	*remote_addrinfo,
        BWLErrSeverity	*err_ret
        )
{
    struct addrinfo *fai;
    struct addrinfo *ai;
    BWLBoolean      retval = False;

    *err_ret = BWLErrOK;

    if (BWLIsInterface(local_addr)) {
        struct ifaddrs *ifaddr, *ifa;

        if (getifaddrs(&ifaddr) == -1) {
            return False;
        }

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

            if (strcmp(ifa->ifa_name, local_addr) != 0)
                continue;

            if (ifa->ifa_addr == NULL)
                continue;

            if (remote_addrinfo->ai_family != ifa->ifa_addr->sa_family)
                continue;

	    // This is a hacky method of getting the addrlen. It should match
	    // the remote_addrinfo's addrlen.
            if (bind(fd,ifa->ifa_addr,remote_addrinfo->ai_addrlen) == 0){
                retval = True;
                break;
            }
        }

        freeifaddrs(ifaddr);
    }
    else {
        struct addrinfo hints;
        struct addrinfo *result;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = remote_addrinfo->ai_family;
        hints.ai_socktype = remote_addrinfo->ai_socktype;
        hints.ai_flags = 0;    /* For wildcard IP address */
        hints.ai_protocol = remote_addrinfo->ai_protocol;
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;

        if (getaddrinfo(local_addr, NULL, &hints, &result) != 0) {
            BWLError(cntrl->ctx,BWLErrFATAL,errno,
                    "getaddrinfo(): %M");
            return False;
        }

        for(ai=result;ai;ai = ai->ai_next){
            if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){
                retval = True;
                break;
            }
            else{
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
            }
        }

        freeaddrinfo(result);
    }

    return retval;
}

BWLBoolean __set_nonblocking(int fd, BWLBoolean non_blocking)
{
   int curr_flags = fcntl(fd, F_GETFL, 0);
   if (curr_flags < 0)
       return False;

   if (non_blocking) {
       curr_flags |= O_NONBLOCK;
   }
   else {
       curr_flags &= ~O_NONBLOCK;
   }

   if (fcntl(fd, F_SETFL, curr_flags) != 0) {
       return False;
   }

   return False;
}

/*
 * Function:	TryAddr
 *
 * Description:	
 * 	This function attempts to connect to the given ai description of
 * 	the "server" addr possibly binding to "local" addr. It has a timeout period of 
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
        const char      *local_addr,
        I2Addr		server_addr
       )
{
    BWLErrSeverity	addr_ok=BWLErrOK;
    int		fd;

    fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
    if(fd < 0){
        BWLError(cntrl->ctx,BWLErrDEBUG,errno,"socket(): %M: "
                "family=%d, socktype=%d, protocol=%d",
                ai->ai_family,ai->ai_socktype,ai->ai_protocol);
        return 1;
    }

    if(local_addr){
        if(!_BWLClientBind(cntrl,fd,local_addr,ai,&addr_ok)){
            if(addr_ok != BWLErrOK){
                return -1;
            }
            goto cleanup;
        }
    }


    // set the socket into non-blocking mode for the connect. We'll undo this
    // before returning from the function. This lets us set a sane timeout.
    __set_nonblocking(fd, True);

    /*
     * Call connect - if it succeeds, return else try again.
     */
    if (connect(fd,ai->ai_addr,ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
        goto cleanup;
    }

    if (errno == EINPROGRESS) {
        fd_set  fdset;
        struct timeval timeout;
        int err = -1;
        socklen_t err_len = sizeof(err);

        // Default: 2 second timeout
        timeout.tv_sec  = 2;
        timeout.tv_usec = 0;

        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        if (select(fd + 1, NULL, &fdset, NULL, &timeout) != 1) {
            goto cleanup;
        }
     
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
        if (err != 0)
            goto cleanup;
    }

    /*
     * connected, set the fields in the addr records
     */
    if(I2AddrSetSAddr(server_addr,ai->ai_addr,ai->ai_addrlen) == False ||
            I2AddrSetSocktype(server_addr,ai->ai_socktype) == False ||
            I2AddrSetProtocol(server_addr,ai->ai_protocol) == False ||
            I2AddrSetFD(server_addr,fd,True) == False){
            goto cleanup;
    }

    cntrl->remote_addr = server_addr;
    cntrl->sockfd = fd;

    __set_nonblocking(fd, False);

    if( !(cntrl->local_addr = I2AddrByLocalSockFD(
                    BWLContextErrHandle(cntrl->ctx),
                    cntrl->sockfd,False))){
        BWLError(cntrl->ctx,BWLErrFATAL,errno, "I2AddrByLocalSockFD() failed");
        goto cleanup;
    }

    return 0;

cleanup:
    __set_nonblocking(fd, False);

    while((close(fd) < 0) && (errno == EINTR));
    return 1;
}

/*
 * Function:	_BWLClientConnect
 *
 * Description:	
 * 	This function attempts to create a socket connection between
 * 	the local client and the server. Each specified with I2Addr
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
        const char      *local_addr,
        I2Addr		server_addr,
        BWLErrSeverity	*err_ret
        )
{
    int		rc;
    struct      addrinfo	*fai;
    struct      addrinfo	*ai;
    char        buf[NI_MAXHOST+NI_MAXSERV+3];
    size_t      buflen = sizeof(buf);

    if(!server_addr)
        goto error;

    /*
     * Easy case - application provided socket directly.
     */
    if((cntrl->sockfd = I2AddrFD(server_addr)) > -1){
        cntrl->remote_addr = server_addr;
        return 0;
    }

    /*
     * Initialize addrinfo portion of server_addr record.
     */
    if(!(fai = I2AddrAddrInfo(server_addr,"localhost",
                    BWL_CONTROL_SERVICE_NAME))){
        BWLError(cntrl->ctx,BWLErrFATAL,errno, "I2AddrAddrInfo failed");
        goto error;
    }

    /*
     * Now that we have addresses - see if it is valid by attempting
     * to create a socket of that type, and binding(if wanted).
     * Also check policy for allowed connection before calling
     * connect.
     */
    if( !BWLContextConfigGetV(cntrl->ctx,BWLIPv4Only)){
#ifdef	AF_INET6
        for(ai=fai;ai;ai=ai->ai_next){
            struct sockaddr_in6 srec;

            if(ai->ai_family != AF_INET6) continue;

            /* avoid type punning by using memcpy instead of casting ai_addr */
            memcpy(&srec,ai->ai_addr,sizeof(srec));
            if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0) {
                return 0;
            }
            if(rc < 0) {
                goto error;
            }
        }
#endif
    }

    /*
     * Now try IPv4 addresses.
     */
    if( !BWLContextConfigGetV(cntrl->ctx,BWLIPv6Only)){
        for(ai=fai;ai;ai=ai->ai_next){
            struct sockaddr_in saddr4;

            if(ai->ai_family != AF_INET) continue;

            /* avoid type punning by using memcpy instead of casting ai_addr */
            memcpy(&saddr4,ai->ai_addr,sizeof(saddr4));

            if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0) {
                return 0;
            }
            if(rc < 0) {
                goto error;
            }
        }
    }

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
        BWLContext	    ctx,	    /* control context	        */
        const char          *local_addr,    /* local addr or null	*/
        I2Addr		    server_addr,    /* server addr		*/
        uint32_t	    mode_req_mask,  /* requested modes	        */
        BWLUserID	    userid,	    /* userid or NULL	        */
        BWLNum64	    *uptime_ret,    /* server uptime - ret	*/
        BWLToolAvailability *tools_ret,     /* server supported tools   */
        BWLErrSeverity	    *err_ret	    /* err - return		*/
        )
{
    int		    rc;
    BWLControl	    cntrl;
    uint32_t	    mode_avail;
    uint32_t	    mode_avail_orig;
    uint32_t	    do_mode;
    uint8_t	    key_value[16];
    uint8_t	    challenge[16];
    uint8_t	    token[32];
    uint8_t	    *key=NULL;
    BWLAcceptType   acceptval;
    BWLTimeStamp    timestart,timeend;
    BWLNum64	    uptime;

    *err_ret = BWLErrOK;

    /*
     * Check for valid context.
     */
    if( !ctx->valid){
        BWLError(ctx,BWLErrFATAL,EINVAL,
                "BWLControlOpen(): Invalid context record");
        *err_ret = BWLErrFATAL;
        return NULL;
    }

    /*
     * First allocate memory for the control state.
     */
    if( !(cntrl = _BWLControlAlloc(ctx,err_ret))) {
        BWLError(ctx,BWLErrFATAL,errno, "Failed to allocate memory for the control state.");
        goto error;
    }

    /*
     * Initialize server record for address we are connecting to.
     */
    if(!server_addr){
        goto error;
    }
    if(!I2AddrSetSocktype(server_addr,SOCK_STREAM)){
        BWLError(ctx,BWLErrFATAL,errno, "I2AddrSetSocktype() failed");
        goto error;
    }

    /*
     * Connect to the server.
     * Address policy check happens in here.
     */
    if(_BWLClientConnect(cntrl,local_addr,server_addr,err_ret) != 0) {
        /*
         * no error printing here - smart client can recover. (Spawn local...)
         */
        BWLError(ctx,BWLErrDEBUG,errno, "_BWLClientConnect() failed");
        goto error;
    }

    /*
     * Read the server greating.
     */
    if((rc=_BWLReadServerGreeting(cntrl,&mode_avail,challenge)) < BWLErrOK){
        BWLError(ctx,BWLErrFATAL,errno, "Server Greeting Failed");
        *err_ret = (BWLErrSeverity)rc;
        goto error;
    }

    mode_avail_orig = mode_avail;

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
        }else{
            if(*err_ret != BWLErrOK) {
                BWLError(ctx,BWLErrFATAL,errno, "Get AESKey failed");
                goto error;
            }
        }
    }
    /*
     * If no key, then remove auth/crypt modes
     */
    if(!key)
        mode_avail &= ~BWL_MODE_DOCIPHER;

    /*
     * Pick "highest" level mode still available unless
     * least_restrictive is in the bitmask, then pick the
     * "lowest" level mode.
     */
    if(mode_req_mask & BWL_MODE_LEAST_RESTRICTIVE){
        do_mode = BWL_MODE_OPEN;
	*err_ret = BWLErrOK;
        while((*err_ret == BWLErrOK) &&(do_mode <= BWL_MODE_ENCRYPTED)){
            if((mode_avail & do_mode) &&
                    _BWLCallCheckControlPolicy(cntrl,
                        do_mode,cntrl->userid,
                        I2AddrSAddr(cntrl->local_addr,NULL),
                        I2AddrSAddr(cntrl->remote_addr,NULL),
                        err_ret)){
                cntrl->mode = do_mode;
                goto gotmode;
            }
            do_mode <<= 1;
        }
    }else{
        do_mode = BWL_MODE_ENCRYPTED;
	*err_ret = BWLErrOK;
        while((*err_ret == BWLErrOK) && (do_mode > BWL_MODE_UNDEFINED)){
            if((mode_avail & do_mode) &&
                    _BWLCallCheckControlPolicy(cntrl,
                        do_mode,cntrl->userid,
                        I2AddrSAddr(cntrl->local_addr,NULL),
                        I2AddrSAddr(cntrl->remote_addr,NULL),
                        err_ret)){
                cntrl->mode = do_mode;
                goto gotmode;
            }
            do_mode >>= 1;
        }
    }

    if(*err_ret != BWLErrOK){
	BWLError(ctx,BWLErrFATAL,errno, "No authentication mode available");
        goto error;
    }else{
        char buf[255];
        buf[0] = '\0';
        if (mode_avail_orig & BWL_MODE_OPEN)
		strncat(buf, " open", sizeof(buf));
        if (mode_avail_orig & BWL_MODE_AUTHENTICATED)
		strncat(buf, " authenticated", sizeof(buf));
        if (mode_avail_orig & BWL_MODE_ENCRYPTED)
		strncat(buf, " encrypted", sizeof(buf));

        BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
                "Server denied access. No authentication modes in common. Modes available: %s", buf);
        errno = EACCES;
        goto denied;
    }

gotmode:

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
        if(I2RandomBytes(ctx->rand_src,cntrl->session_key,16) != 0) {
	    BWLError(ctx,BWLErrFATAL,errno, "I2RandomBytes failed");
            goto error;
	}

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
        if(_BWLEncryptToken(key,buf,token) != 0) {
	    BWLError(ctx,BWLErrFATAL,errno, "_BWLEncryptToken failed");
            goto error;
        }

        /*
         * Create random writeIV
         */
        if(I2RandomBytes(ctx->rand_src,cntrl->writeIV,16) != 0) {
	    BWLError(ctx,BWLErrFATAL,errno, "I2RandomBytes failed");
            goto error;
	}
    }

    /*
     * Get current time before sending client greeting - used
     * for very rough estimate of RTT. (upper bound)
     */
    if(!BWLGetTimeStamp(ctx,&timestart)) {
	BWLError(ctx,BWLErrFATAL,errno, "BWLGetTimeStamp failed");
        goto error;
    }

    /*
     * Write the client greeting, and see if the Server agree's to it.
     */
    if( ((rc=_BWLWriteClientGreeting(cntrl,token)) < BWLErrOK) ||
            ((rc=_BWLReadServerOK(cntrl,&acceptval,tools_ret)) < BWLErrOK)){
        *err_ret = (BWLErrSeverity)rc;
	BWLError(ctx,BWLErrFATAL,errno, "BWLWriteClientGreeeting failed");
        goto error;
    }

    if(acceptval != BWL_CNTRL_ACCEPT){
        BWLError(cntrl->ctx,BWLErrINFO,BWLErrPOLICY,
                "Server denied access");
        errno = EACCES;
        goto denied;
    }

    /*
     * Get current time after response from server and set the RTT
     * in the "rtt_bound" field of cntrl.
     */
    if(!BWLGetTimeStamp(ctx,&timeend)) {
	BWLError(ctx,BWLErrFATAL,errno, "BWLGetTimeStamp failed");
        goto error;
    }

    cntrl->rtt_bound = BWLNum64Sub(timeend.tstamp,timestart.tstamp);

    if((rc=_BWLReadServerUptime(cntrl,&uptime)) < BWLErrOK){
        *err_ret = (BWLErrSeverity)rc;
	BWLError(ctx,BWLErrFATAL,errno, "BWLReadServerUptime failed");
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
    if(cntrl->remote_addr != server_addr)
        I2AddrFree(server_addr);
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

    *err_ret = BWLErrOK;
    return 1;
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
        BWLBoolean	is_client,
        BWLTestSpec	*test_spec,
        BWLTimeStamp	*avail_time_ret,
        uint16_t	*tool_port,
        BWLSID		sid,
        BWLErrSeverity	*err_ret
        )
{
    struct addrinfo *frai=NULL;
    struct addrinfo *fsai=NULL;
    struct addrinfo *rai=NULL;
    struct addrinfo *sai=NULL;
    BWLTestSession  tsession = NULL;
    int		    rc=0;
    I2Addr	    server=NULL;
    I2Addr	    client=NULL;
    struct sockaddr *rsaddr;
    struct sockaddr *ssaddr;
    socklen_t       saddrlen;
    BWLNum64	    zero64=BWLULongToNum64(0);
    BWLAcceptType   acceptval = BWL_CNTRL_FAILURE;
    BWLBoolean	    retval = False;

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

        if(test_spec->server){
            server = I2AddrCopy(test_spec->server);
        }else{
            BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "BWLSessionRequest:Invalid receive address");
        }

        if(!server)
            goto error;

        if(test_spec->client){
            client = I2AddrCopy(test_spec->client);
        }else{
            BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "BWLSessionRequest:Invalid receive address");
        }

        if(!client)
            goto error;

        /*
         * Set the socktypes needed for this type of test so the
         * getaddrinfo happens correctly.
         */
        if(     !I2AddrSetSocktype(client,
                    (test_spec->udp)? SOCK_DGRAM: SOCK_STREAM) ||
                !I2AddrSetSocktype(server,
                    (test_spec->udp)? SOCK_DGRAM: SOCK_STREAM)){
            goto error;
        }

        /*
         * Get addrinfo for address spec's so we can choose between
         * the different address possiblities in the next step.
         */
        if(     !(frai = I2AddrAddrInfo(server,NULL,NULL)) ||
                !(fsai = I2AddrAddrInfo(client,NULL,NULL))){
            goto error;
        }

        /*
         * Determine proper address specifications for send/recv.
         * Loop on ai values to find a match and use that.
         * (We prefer IPV6 over others, so loop over IPv6 addrs
         * first...) Only supports AF_INET and AF_INET6.
         */
        if( !BWLContextConfigGetV(cntrl->ctx,BWLIPv4Only)){
#ifdef	AF_INET6
            for(rai = frai;rai;rai = rai->ai_next){
                if(rai->ai_family != AF_INET6) continue;
                for(sai = fsai;sai;sai = sai->ai_next){
                    struct sockaddr_in6 s_srec;
                    struct sockaddr_in6 r_srec;

                    if(rai->ai_family != sai->ai_family) continue;
                    if(rai->ai_socktype != sai->ai_socktype)
                        continue;

                    memcpy(&s_srec,sai->ai_addr,sizeof(s_srec));
                    memcpy(&r_srec,rai->ai_addr,sizeof(r_srec));

                    if(IN6_IS_ADDR_LOOPBACK(&s_srec.sin6_addr) && !IN6_IS_ADDR_LOOPBACK(&r_srec.sin6_addr))
                        continue;

                    if(!IN6_IS_ADDR_LOOPBACK(&s_srec.sin6_addr) && IN6_IS_ADDR_LOOPBACK(&r_srec.sin6_addr))
                        continue;

                    goto foundaddr;
                }
            }
#endif
        }

        if( !BWLContextConfigGetV(cntrl->ctx,BWLIPv6Only)){
            for(rai = frai;rai;rai = rai->ai_next){

                if(rai->ai_family != AF_INET) continue;

                for(sai = fsai;sai;sai = sai->ai_next){
                    struct sockaddr_in s_saddr4;
                    struct sockaddr_in r_saddr4;

                    if(rai->ai_family != sai->ai_family) continue;
                    if(rai->ai_socktype != sai->ai_socktype)
                        continue;

                    memcpy(&s_saddr4,sai->ai_addr,sizeof(s_saddr4));
                    memcpy(&r_saddr4,rai->ai_addr,sizeof(r_saddr4));

                    if(s_saddr4.sin_addr.s_addr == INADDR_LOOPBACK && r_saddr4.sin_addr.s_addr != INADDR_LOOPBACK)
                        continue;

                    if(s_saddr4.sin_addr.s_addr != INADDR_LOOPBACK && r_saddr4.sin_addr.s_addr == INADDR_LOOPBACK)
                        continue;

                    goto foundaddr;
                }
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
         * Fill I2Addr records with "selected" addresses for test.
         */
        if( !I2AddrSetSAddr(server,rai->ai_addr,rai->ai_addrlen) ||
                !I2AddrSetSAddr(client,sai->ai_addr,sai->ai_addrlen)){
            BWLError(cntrl->ctx,*err_ret,BWLErrINVALID,
                    "BWLSessionRequest: Unable to set socket info");
            goto error;
        }

        /*
         * Save direct pointers to recv/send saddr's for policy funcs
         */
        rsaddr = rai->ai_addr;
        ssaddr = sai->ai_addr;
        saddrlen = sai->ai_addrlen;

        /*
         * Create a structure to store the stuff we need to keep for
         * later calls.
         */
        if( !(tsession = _BWLTestSessionAlloc(cntrl,is_client,client,
                        server,*tool_port,test_spec)))
            goto error;
    }

    if(tsession->conf_server){
        *tool_port = 0;
    }
    else{
        memcpy(tsession->sid,sid,sizeof(BWLSID));
    }

    /*
     * Request the server create the server & possibly the
     * client. (copy reservation time so a denied response can be
     * differentiated from a "busy" response.)
     */
    rc = _BWLClientRequestTestReadResponse(cntrl,tsession,err_ret);
    avail_time_ret->tstamp = tsession->reserve_time;

    if(rc != 0){
        goto error;
    }

    *tool_port = tsession->tool_port;

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
    if(tsession->conf_server){
        memcpy(sid,tsession->sid,sizeof(BWLSID));
    }

    return True;

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
        _BWLTestSessionFree(cntrl->ctx, tsession,acceptval);
        if(cntrl->tests == tsession){
            cntrl->tests = NULL;
        }
    }
    else{
        /*
         * If tsession exists - the addr's will be free'd as
         * part of it - otherwise, do it here.
         */
        I2AddrFree(server);
        I2AddrFree(client);
    }

    return retval;
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
        BWLControl  cntrl,
        uint16_t    *dataport /* retn for recv - set for send */
        )
{
    int		    rc;
    BWLAcceptType   acceptval;
    uint16_t	    lport_val = 0;
    uint16_t	    *lport = &lport_val;

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
        BWLControl      cntrl,
        int	        *retn_on_intr,
        BWLAcceptType	*acceptval,
        FILE		*fp
        )
{
    int		    ival = 0;
    int		    *intr=&ival;
    BWLRequestType  msgtype;
    BWLAcceptType   aval = BWL_CNTRL_ACCEPT;
    BWLAcceptType   *aptr = &aval;
    BWLErrSeverity  rc;

    if(acceptval)
        aptr = acceptval;

    if(retn_on_intr)
        intr = retn_on_intr;

    if( (rc = _BWLWriteStopSession(cntrl,intr,*aptr,NULL)) < BWLErrOK){
        *aptr = BWL_CNTRL_FAILURE;
        return _BWLFailControlSession(cntrl,(int)rc);
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
        return _BWLFailControlSession(cntrl,(int)rc);
    }

    return _BWLTestSessionFree(cntrl->ctx,cntrl->tests,*aptr);
}
