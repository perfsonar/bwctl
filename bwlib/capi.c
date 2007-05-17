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
        I2Addr		local_addr,
        struct addrinfo	*remote_addrinfo,
        BWLErrSeverity	*err_ret
        )
{
    struct addrinfo	*fai;
    struct addrinfo	*ai;

    *err_ret = BWLErrOK;

    if(!I2AddrSetSocktype(local_addr,SOCK_STREAM) ||
            !I2AddrSetProtocol(local_addr,IPPROTO_TCP) ||
            !(fai = I2AddrAddrInfo(local_addr,NULL,NULL))){
        *err_ret = BWLErrFATAL;
        return False;
    }

    /*
     * Now that we have a valid addrinfo list for this address, go
     * through each of those addresses and try to bind the first
     * one that matches addr family and socktype.
     */
    for(ai=fai;ai;ai = ai->ai_next){
        if(ai->ai_family != remote_addrinfo->ai_family)
            continue;
        if(ai->ai_socktype != remote_addrinfo->ai_socktype)
            continue;

        if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){
            if( I2AddrSetSAddr(local_addr,ai->ai_addr,ai->ai_addrlen)){
                return True;
            }
            BWLError(cntrl->ctx,BWLErrFATAL,errno,
                    "I2AddrSetSAddr(): failed to set saddr");
            return False;
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
        I2Addr		local_addr,
        I2Addr		server_addr
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

        /*
         * connected, set the fields in the addr records
         */
        if(I2AddrSetSAddr(server_addr,ai->ai_addr,ai->ai_addrlen) &&
                I2AddrSetSocktype(server_addr,ai->ai_socktype) &&
                I2AddrSetProtocol(server_addr,ai->ai_protocol) &&
                I2AddrSetFD(server_addr,fd,True)){

            cntrl->remote_addr = server_addr;
            cntrl->local_addr = local_addr;
            cntrl->sockfd = fd;
            return 0;
        }

        /*
         * Connected, but addr record stuff failed.
         */
        BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "I2Addr functions failed after successful connection");

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
        I2Addr		local_addr,
        I2Addr		server_addr,
        BWLErrSeverity	*err_ret
        )
{
    int		rc;
    struct addrinfo	*fai;
    struct addrinfo	*ai;

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
    if(!(fai = I2AddrAddrInfo(server_addr,NULL,BWL_CONTROL_SERVICE_NAME))){
        goto error;
    }

    /*
     * Now that we have addresses - see if it is valid by attempting
     * to create a socket of that type, and binding(if wanted).
     * Also check policy for allowed connection before calling
     * connect.
     */
#ifdef	AF_INET6
    for(ai=fai;ai;ai=ai->ai_next){
        struct sockaddr_in6 *saddr6;

        if(ai->ai_family != AF_INET6) continue;

        saddr6 = (struct sockaddr_in6*)ai->ai_addr;
        if(IN6_IS_ADDR_LOOPBACK(&saddr6->sin6_addr)){
            BWLError(cntrl->ctx,BWLErrWARNING,errno,
                    "Loopback is probably not a valid test address (can't schedule both a receiver and a sender at one time)");
        }

        if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0)
            return 0;
        if(rc < 0)
            goto error;
    }
#endif
    /*
     * Now try IPv4 addresses.
     */
    for(ai=fai;ai;ai=ai->ai_next){
        struct sockaddr_in *saddr4;

        if(ai->ai_family != AF_INET) continue;

        saddr4 = (struct sockaddr_in*)ai->ai_addr;
        if(saddr4->sin_addr.s_addr == INADDR_LOOPBACK){
            BWLError(cntrl->ctx,BWLErrWARNING,errno,
                    "Loopback is probably not a valid test address (can't schedule both a receiver and a sender at one time)");
        }

        if( (rc = TryAddr(cntrl,ai,local_addr,server_addr)) == 0)
            return 0;
        if(rc < 0)
            goto error;
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
        BWLContext	ctx,		/* control context	*/
        I2Addr		local_addr,	/* local addr or null	*/
        I2Addr		server_addr,	/* server addr		*/
        uint32_t	mode_req_mask,	/* requested modes	*/
        BWLUserID	userid,		/* userid or NULL	*/
        BWLNum64	*uptime_ret,	/* server uptime - ret	*/
        BWLTesterAvailability	*avail_testers,	/* server supported testers */
        BWLErrSeverity	*err_ret	/* err - return		*/
        )
{
    int		    rc;
    BWLControl	    cntrl;
    uint32_t	    mode_avail;
    uint32_t	    do_mode;
    uint8_t	    key_value[16];
    uint8_t	    challenge[16];
    uint8_t	    token[32];
    uint8_t	    *key=NULL;
    BWLAcceptType   acceptval;
    struct timeval  tvalstart,tvalend;
    BWLNum64	    uptime;

    *err_ret = BWLErrOK;

    /*
     * First allocate memory for the control state.
     */
    if( !(cntrl = _BWLControlAlloc(ctx,err_ret)))
        goto error;

    /*
     * Initialize server record for address we are connecting to.
     */
    if(!server_addr){
        goto error;
    }
    if(!I2AddrSetSocktype(server_addr,SOCK_STREAM)){
        goto error;
    }

    /*
     * Connect to the server.
     * Address policy check happens in here.
     */
    if(_BWLClientConnect(cntrl,local_addr,server_addr,err_ret) != 0)
        goto error;

    if(!cntrl->local_addr){
        if( !(cntrl->local_addr = I2AddrByLocalSockFD(
                        BWLContextErrHandle(cntrl->ctx),
                        cntrl->sockfd,False))){
            goto error;
        }
    }

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
     * Pick "highest" level mode still available unless
     * least_restrictive is in the bitmask, then pick the
     * "lowest" level mode.
     */
    if(mode_req_mask & BWL_MODE_LEAST_RESTRICTIVE){
        do_mode = BWL_MODE_OPEN;
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
        goto error;
    }
    else{
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
            ((rc=_BWLReadServerOK(cntrl,&acceptval,
                                  avail_testers)) < BWLErrOK)){
        *err_ret = (BWLErrSeverity)rc;
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
        I2AddrFree(local_addr);
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
        BWLBoolean	send,
        BWLTestSpec	*test_spec,
        BWLTimeStamp	*avail_time_ret,
        uint16_t	*recv_port,
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
    I2Addr	    receiver=NULL;
    I2Addr	    sender=NULL;
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

        if(test_spec->receiver){
            receiver = I2AddrCopy(test_spec->receiver);
        }else{
            BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "BWLSessionRequest:Invalid receive address");
        }

        if(!receiver)
            goto error;

        if(test_spec->sender){
            sender = I2AddrCopy(test_spec->sender);
        }else{
            BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "BWLSessionRequest:Invalid receive address");
        }

        if(!sender)
            goto error;

        /*
         * Set the socktypes needed for this type of test so the
         * getaddrinfo happens correctly.
         */
        if(     !I2AddrSetSocktype(receiver,
                    (test_spec->udp)? SOCK_DGRAM: SOCK_STREAM) ||
                !I2AddrSetSocktype(sender,
                    (test_spec->udp)? SOCK_DGRAM: SOCK_STREAM)){
            goto error;
        }

        /*
         * Get addrinfo for address spec's so we can choose between
         * the different address possiblities in the next step.
         */
        if(     !(frai = I2AddrAddrInfo(receiver,NULL,NULL)) ||
                !(fsai = I2AddrAddrInfo(sender,NULL,NULL))){
            goto error;
        }

        /*
         * Determine proper address specifications for send/recv.
         * Loop on ai values to find a match and use that.
         * (We prefer IPV6 over others, so loop over IPv6 addrs
         * first...) Only supports AF_INET and AF_INET6.
         */
#ifdef	AF_INET6
        for(rai = frai;rai;rai = rai->ai_next){
            if(rai->ai_family != AF_INET6) continue;
            for(sai = fsai;sai;sai = sai->ai_next){
                if(rai->ai_family != sai->ai_family) continue;
                if(rai->ai_socktype != sai->ai_socktype)
                    continue;
                goto foundaddr;
            }
        }
#endif
        for(rai = frai;rai;rai = rai->ai_next){
            if(rai->ai_family != AF_INET) continue;
            for(sai = fsai;sai;sai = sai->ai_next){
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
         * Fill I2Addr records with "selected" addresses for test.
         */
        if( !I2AddrSetSAddr(receiver,rai->ai_addr,rai->ai_addrlen) ||
                !I2AddrSetSAddr(sender,sai->ai_addr,sai->ai_addrlen)){
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
     * sender. (copy reservation time so a denied response can be
     * differentiated from a "busy" response.)
     */
    rc = _BWLClientRequestTestReadResponse(cntrl,tsession,err_ret);
    avail_time_ret->tstamp = tsession->reserve_time;

    if(rc != 0){
        goto error;
    }

    *recv_port = tsession->recv_port;

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
        I2AddrFree(receiver);
        I2AddrFree(sender);
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
