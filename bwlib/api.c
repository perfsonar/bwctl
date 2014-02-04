/*
 ** ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 **      $Id$
 */
/************************************************************************
 *                                                                       *
 *                       Copyright (C)  2003                             *
 *                           Internet2                                   *
 *                       All Rights Reserved                             *
 *                                                                       *
 ************************************************************************/
/*
 **    File:        api.c
 **
 **    Author:      Jeff W. Boote
 **
 **    Date:        Tue Sep 16 14:24:49 MDT 2003
 **
 **    Description:    
 * 
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
#define    EFTYPE    ENOSYS
#endif

/*
 * Function:    BWLGetContext
 *
 * Description:    
 *              Returns the context pointer that was referenced when the
 *              given control connection was created.
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
        BWLControl  cntrl
        )
{
    return cntrl->ctx;
}

/*
 * Function:    BWLGetMode
 *
 * Description:    
 *              Returns the "mode" of the control connection.
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
        BWLControl  cntrl
        )
{
    return cntrl->mode;
}

/*
 * Function:    BWLControlFD
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
        BWLControl  cntrl
        )
{
    return cntrl->sockfd;
}

/*
 * Function:    BWLControlLocalAddr
 *
 * Description:    
 *              Returns a pointer to the address of the local end of the
 *              control connection in an I2Addr struct. Does not make a copy of
 *              the struct.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
I2Addr
BWLControlLocalAddr(
        BWLControl  cntrl
        )
{
    return cntrl->local_addr;
}

/*
 * Function:    BWLControlRemoteAddr
 *
 * Description:    
 *              Returns a pointer to the address of the remote end of the
 *              control connection in an I2Addr struct. Does not make a copy of
 *              the struct.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
I2Addr
BWLControlRemoteAddr(
        BWLControl  cntrl
        )
{
    return cntrl->remote_addr;
}

/*
 * Function:    BWLAddrByControl
 *
 * Description:    
 *              Wrapper for some I2Addr functions on the
 *              control socket.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
I2Addr
BWLAddrByControl(
        BWLControl  cntrl
        )
{
    struct sockaddr *saddr;
    socklen_t       saddrlen;

    if(!cntrl->remote_addr ||
            !(saddr = I2AddrSAddr(cntrl->remote_addr,&saddrlen))){
        return NULL;
    }

    return I2AddrBySAddr(BWLContextErrHandle(cntrl->ctx),
            saddr,saddrlen,
            I2AddrSocktype(cntrl->remote_addr),
            I2AddrProtocol(cntrl->remote_addr));
}

/*
 * Function:    BWLAddrByLocalControl
 *
 * Description:    
 *              Wrapper for some I2Addr functions on the
 *              control socket.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
I2Addr
BWLAddrByLocalControl(
        BWLControl  cntrl
        )
{
    struct sockaddr *saddr;
    socklen_t       saddrlen;

    if(!cntrl->local_addr ||
            !(saddr = I2AddrSAddr(cntrl->local_addr,&saddrlen))){
        return NULL;
    }

    return I2AddrBySAddr(BWLContextErrHandle(cntrl->ctx),
            saddr,saddrlen,
            I2AddrSocktype(cntrl->local_addr),
            I2AddrProtocol(cntrl->local_addr));
}

/*
 * Function:    BWLGetRTTBound
 *
 * Description: Returns a very rough estimate of the upper-bound rtt to
 *              the server.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 *         bound or 0 if unavailable
 * Side Effect:    
 */
BWLNum64
BWLGetRTTBound(
        BWLControl  cntrl
        )
{
    return cntrl->rtt_bound;
}

/*
 * Function:    _BWLFailControlSession
 *
 * Description:    
 *              Simple convienience to set the state and return the failure at
 *              the same time.
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
        BWLControl  cntrl,
        int         level
        )
{
    cntrl->state = _BWLStateInvalid;
    return (BWLErrSeverity)level;
}

/*
 * Function:    _BWLTestSessionAlloc
 *
 * Description:    
 *
 * This function is used to allocate/initialize the memory record used
 * to maintain state information about a "configured" test.
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
        BWLControl  cntrl,
        BWLBoolean  is_client,
        I2Addr      client,
        I2Addr      server,
        uint16_t    tool_port,
        BWLTestSpec *test_spec
        )
{
    BWLTestSession  test;

    /*
     * Address records must exist.
     */
    if(!client || !server){
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
     * Overwrite client/server with passed-in values
     */
    test->test_spec.client = client;
    test->test_spec.server = server;

    test->conf_server = !is_client;
    test->conf_client = !test->conf_server;

    if(is_client){
        test->conf_client = True;
        test->conf_server = False;
        test->tool_port = tool_port;
    }
    else{
        test->conf_server = True;
        test->conf_client = False;
        test->tool_port = 0;
    }

    return test;
}

/*
 * Function:    _BWLTestSessionFree
 *
 * Description:    
 *     This function is used to free the memory associated with a "configured"
 *     test session.
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
        BWLContext      ctx,
        BWLTestSession  tsession,
        BWLAcceptType   aval
        )
{
    BWLErrSeverity  err=BWLErrOK;

    if(!tsession){
        return BWLErrOK;
    }

    /*
     * remove this tsession from the cntrl->tests list.
     */
    if(tsession->cntrl->tests == tsession){
        tsession->cntrl->tests = NULL;
    }

    (void)_BWLEndpointStop(ctx,tsession,aval,&err);

    if(tsession->closure){
        _BWLCallTestComplete(tsession,aval);
    }

    I2AddrFree(tsession->test_spec.client);
    I2AddrFree(tsession->test_spec.server);

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
 * Function:    _BWLCreateSID
 *
 * Description:    
 *     Generate a "unique" SID from addr(4)/time(8)/random(4) values.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 *     0 on success
 * Side Effect:    
 */
int
_BWLCreateSID(
        BWLTestSession    tsession
        )
{
    uint8_t    *aptr;
    struct sockaddr *saddr = I2AddrSAddr(tsession->test_spec.server,NULL);

    if(!saddr){
        BWLError(tsession->cntrl->ctx,BWLErrFATAL,BWLErrUNSUPPORTED,
                "_BWLCreateSID: Invalid socket address");
        return 1;
    }

    switch(saddr->sa_family){
        struct sockaddr_in    *s4;
#ifdef    AF_INET6
        struct sockaddr_in6    *s6;

        case AF_INET6:

        s6 = (struct sockaddr_in6*)saddr;
        /* point at last 4 bytes of addr */
        aptr = &s6->sin6_addr.s6_addr[12];

        break;
#endif

        case AF_INET:

        s4 = (struct sockaddr_in*)saddr;
        aptr = (uint8_t*)&s4->sin_addr;

        break;

        default:
        BWLError(tsession->cntrl->ctx,BWLErrFATAL,BWLErrUNSUPPORTED,
                "_BWLCreateSID: Unknown address family");
        return 1;
        break;
    }

    memcpy(&tsession->sid[0],aptr,4);

    _BWLEncodeTimeStamp(&tsession->sid[4],&tsession->localtime);

    if(I2RandomBytes(tsession->cntrl->ctx->rand_src,&tsession->sid[12],4)
            != 0){
        return 1;
    }

    return 0;
}

