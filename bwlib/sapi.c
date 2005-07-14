/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 *      $Id$
 */
/************************************************************************
 *                                                                        *
 *                          Copyright (C)  2003                            *
 *                              Internet2                               *
 *                          All Rights Reserved                         *
 *                                                                        *
 ************************************************************************/
/*
 *    File:            sapi.c
 *
 *    Author:            Jeff W. Boote
 *                    Internet2
 *
 *    Date:            Tue Sep 16 14:27:01 MDT 2003
 *
 *    Description:    
 *
 *    This file contains the api functions typically called from an
 *    bwlib server application.
 */
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bwlib/bwlibP.h>

static int
OpenSocket(
        BWLContext  ctx    __attribute__((unused)),
        int         family,
        BWLAddr     addr
        )
{
    struct addrinfo *fai;
    struct addrinfo *ai;
    int             on;
    int             fd;

    if(!(fai = BWLAddrAddrInfo(addr,NULL,BWL_CONTROL_SERVICE_NAME))){
        return -2;
    }

    for(ai = fai;ai;ai = ai->ai_next){
        if(ai->ai_family != family)
            continue;

        fd =socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);

        if(fd < 0)
            continue;

        on=1;
        if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,
                    sizeof(on)) != 0){
            goto failsock;
        }

        /*
         * TODO Check for the superseded IPV6_BINDV6ONLY sockopt too?
         * (No - not unless someone complains.)
         */
#if    defined(AF_INET6) && defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
        on=0;
        if((ai->ai_family == AF_INET6) &&
                setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&on,
                    sizeof(on)) != 0){
            goto failsock;
        }
#endif

        if(bind(fd,ai->ai_addr,ai->ai_addrlen) == 0){

            BWLAddrSetFD(addr,-1,True);
            BWLAddrSetSocktype(addr,ai->ai_socktype);
            BWLAddrSetSAddr(addr,ai->ai_addr,ai->ai_addrlen);
            BWLAddrSetFD(addr,fd,True);

            break;
        }

        if(errno == EADDRINUSE)
            return -2;

failsock:
        while((close(fd) < 0) && (errno == EINTR));
        fd = -1;
    }


    return fd;
}

/*
 * Function:    BWLServerSockCreate
 *
 * Description:    
 *         Used by server to create the initial listening socket.
 *         (It is not required that the server use this interface,
 *         but it will be kept up-to-date and in sync with the
 *         client BWLControlOpen function. For example, both of
 *         these functions currently give priority to IPV6 addresses
 *         over IPV4.)
 *
 *         The addr should be NULL for a wildcard socket, or bound to
 *         a specific interface using BWLAddrByNode or BWLAddrByAddrInfo.
 *
 *         This function will create the socket, bind it, and set the
 *         "listen" backlog length.
 *
 *         If addr is set using BWLAddrByFD, it will cause an error.
 *         (It doesn't really make much sense to call this function at
 *         all if you are going to    create and bind your own socket -
 *         the only thing left is to call "listen"...)
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
        BWLContext      ctx,
        BWLAddr         addr,
        BWLErrSeverity  *err_ret
        )
{
    int        fd = -1;

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
    if((!addr) && !(addr = BWLAddrByWildcard(ctx,SOCK_STREAM)))
        goto error;

    /*
     * Tell Addr API that this should be created as a "passive"
     * socket.
     */
     if(!BWLAddrSetPassive(addr,True))
        goto error;

#ifdef    AF_INET6
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
    if(listen(fd,BWL_LISTEN_BACKLOG) < 0){
        BWLError(ctx,BWLErrFATAL,errno,"listen(%d,%d):%s",
                fd,BWL_LISTEN_BACKLOG,strerror(errno));
        goto error;
    }

    return addr;

error:
    BWLAddrFree(addr);
    *err_ret = BWLErrFATAL;
    return NULL;

}

/*
 * Function:    BWLControlAccept
 *
 * Description:    
 *         This function is used to initialiize the communication
 *         to the peer.
 *           
 * In Args:    
 *         connfd,connsaddr, and connsaddrlen are all returned
 *         from "accept".
 *
 * Returns:    Valid BWLControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
BWLControl
BWLControlAccept(
        BWLContext      ctx,            /* library context              */
        int             connfd,         /* connected socket             */
        struct sockaddr *connsaddr,     /* connected socket addr        */
        socklen_t       connsaddrlen,   /* connected socket addr len    */
        u_int32_t       mode_offered,   /* advertised server mode       */
        BWLNum64        uptime,         /* uptime for server            */
        int             *retn_on_intr,  /* if *retn_on_intr return      */
        BWLErrSeverity  *err_ret        /* err - return                 */
        )
{
    BWLControl      cntrl;
    u_int8_t        challenge[16];
    u_int8_t        rawtoken[32];
    u_int8_t        token[32];
    int             rc;
    struct timeval  tvalstart,tvalend;
    int             ival=0;
    int             *intr = &ival;

    if(connfd < 0)
        return NULL;

    if(retn_on_intr){
        intr = retn_on_intr;
    }

    *err_ret = BWLErrOK;
    mode_offered &= BWL_MODE_ALLMODES;

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
    /*
     * If connsaddr is not existant, than create the Addr using the
     * socket only.
     */
    if(!connsaddr || !connsaddrlen){
        if(!(cntrl->remote_addr = BWLAddrBySockFD(ctx,connfd))){
            goto error;
        }
    }
    else if(!(cntrl->remote_addr =
                BWLAddrBySAddr(ctx,connsaddr,connsaddrlen,SOCK_STREAM))){
        goto error;
    }
    /* set fd_user to False so a Free of the addr will close the fd. */
    if(!BWLAddrSetFD(cntrl->remote_addr,connfd,True)){
        goto error;
    }

    /*
     * set up local_addr for policy decisions, and log reporting.
     */
    if( !(cntrl->local_addr = BWLAddrByLocalSockFD(ctx,connfd))){
        *err_ret = BWLErrFATAL;
        goto error;
    }

    /*
     * TODO: decide what "level" to send access logs to.
     */
    BWLError(ctx,ctx->access_prio,BWLErrPOLICY,
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
     * server greeting. (Nice way of saying goodbye.)
     */
    if(!mode_offered){
        BWLError(cntrl->ctx,cntrl->ctx->access_prio,BWLErrPOLICY,
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
    if(    (cntrl->mode != BWL_MODE_OPEN) &&
            (cntrl->mode != BWL_MODE_AUTHENTICATED) &&
            (cntrl->mode != BWL_MODE_ENCRYPTED)){
        *err_ret = BWLErrFATAL;
        goto error;
    }

    if(!(cntrl->mode | mode_offered)){ /* can't provide requested mode */
        BWLError(cntrl->ctx,cntrl->ctx->access_prio,BWLErrPOLICY,
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
        u_int8_t    binKey[16];
        BWLBoolean  getkey_success;

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
                BWLError(cntrl->ctx,cntrl->ctx->access_prio,BWLErrPOLICY,
                        "Unknown userid (%s)",
                        cntrl->userid_buffer);
            }
            else{
                BWLError(cntrl->ctx,cntrl->ctx->access_prio,BWLErrPOLICY,
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
            BWLError(ctx,ctx->access_prio,BWLErrPOLICY,
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
    BWLError(ctx,ctx->access_prio,BWLErrPOLICY,
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
        BWLControl    cntrl,
        int        *retn_on_intr
        )
{
    BWLTestSession    tsession = cntrl->tests;
    BWLErrSeverity    err_ret=BWLErrOK;
    int        rc;
    BWLAcceptType    acceptval = BWL_CNTRL_FAILURE;
    int        ival=0;
    int        *intr = &ival;
    BWLAddr        raddr;

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
     */
    tsession->fuzz = BWLGetTimeStampError(&tsession->test_spec.req_time);
    tsession->fuzz = BWLNum64Add(tsession->fuzz,
            BWLGetTimeStampError(&tsession->localtime));
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
            (cntrl->remote_addr->saddr->sa_family != AF_UNIX) &&
            !I2SockAddrIsLoopback(cntrl->remote_addr->saddr,
                cntrl->remote_addr->saddrlen) &&
            (I2SockAddrEqual(cntrl->remote_addr->saddr,
                             cntrl->remote_addr->saddrlen,
                             cntrl->local_addr->saddr,
                             cntrl->local_addr->saddrlen,
                             I2SADDR_ADDR) <= 0) &&
            (I2SockAddrEqual(cntrl->remote_addr->saddr,
                             cntrl->remote_addr->saddrlen,
                             raddr->saddr,
                             raddr->saddrlen,
                             I2SADDR_ADDR) <= 0)){
        BWLError(cntrl->ctx,cntrl->ctx->access_prio,BWLErrPOLICY,
                "Test Denied: OpenMode remote_addr(%s) != control_client(%s)",
                raddr->node,cntrl->remote_addr->node);
        BWLError(cntrl->ctx,cntrl->ctx->access_prio,BWLErrPOLICY,
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
        BWLError(cntrl->ctx,cntrl->ctx->access_prio,BWLErrPOLICY,
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
        BWLControl    cntrl,
        int        *retn_on_intr
        )
{
    int        rc;
    int        ival=0;
    int        *intr = &ival;
    BWLTimeStamp    tstamp;

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
        BWLControl    cntrl,
        int        *retn_on_intr
        )
{
    int        rc;
    BWLErrSeverity    err=BWLErrOK;
    int        ival=0;
    int        *intr = &ival;
    u_int16_t    dataport = 0;

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
 * Function:    BWLSessionStatus
 *
 * Description:    
 *     This function returns the "status" of the test session identified
 *     by the sid. "send" indicates which "side" of the test to retrieve
 *     information about.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    True if status was available, False otherwise.
 *         aval contains the actual "status":
 *             <0    Test is not yet complete
 *             >=0    Valid BWLAcceptType - see enum for meaning.
 * Side Effect:    
 */
BWLBoolean
BWLSessionStatus(
        BWLControl    cntrl,
        BWLSID        sid,
        BWLAcceptType    *aval
        )
{
    BWLTestSession    tsession;
    BWLErrSeverity    err;

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
        BWLControl    cntrl,
        BWLAcceptType    *aval
        )
{
    BWLTestSession    tsession;
    BWLAcceptType    laval = 0;
    BWLErrSeverity    err;

    tsession = cntrl->tests;
    if(tsession && _BWLEndpointStatus(tsession,&laval,&err) && (laval < 0))
        return 1;

    if(aval)
        *aval = laval;

    return 0;
}

BWLErrSeverity
BWLStopSession(
        BWLControl    cntrl,
        int        *retn_on_intr,
        BWLAcceptType    *acceptval_ret    /* in/out    */
        )
{
    BWLErrSeverity    err,err2=BWLErrOK;
    BWLRequestType    msgtype;
    BWLAcceptType    aval=BWL_CNTRL_ACCEPT;
    BWLAcceptType    *acceptval=&aval;
    int        ival=0;
    int        *intr=&ival;
    FILE        *fp;

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
        BWLControl        cntrl,
        BWLNum64        *wake,
        int            *retn_on_intr,
        BWLAcceptType        *acceptval_ret,
        BWLErrSeverity        *err_ret
        )
{
    struct timeval    currtime;
    struct timeval    reltime;
    struct timeval    *waittime = NULL;
    fd_set        readfds;
    fd_set        exceptfds;
    int        rc;
    int        msgtype;
    BWLErrSeverity    err2=BWLErrOK;
    BWLAcceptType    aval;
    BWLAcceptType    *acceptval=&aval;
    int        ival=0;
    int        *intr=&ival;
    FILE        *fp;

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

AGAIN:
    if(wake){
        BWLTimeStamp    wakestamp;

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
