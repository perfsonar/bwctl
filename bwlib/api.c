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
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the following copyright notice,
 *       this list of conditions and the disclaimer below.
 * 
 *        Copyright (c) 2003-2008, Internet2
 * 
 *                              All rights reserved.
 * 
 *     * Redistribution in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 *    *  Neither the name of Internet2 nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       explicit prior written permission.
 * 
 * You are under no obligation whatsoever to provide any enhancements to Internet2,
 * or its contributors.  If you choose to provide your enhancements, or if you
 * choose to otherwise publish or distribute your enhancement, in source code form
 * without contemporaneously requiring end users to enter into a separate written
 * license agreement for such enhancements, then you thereby grant Internet2, its
 * contributors, and its members a non-exclusive, royalty-free, perpetual license
 * to copy, display, install, use, modify, prepare derivative works, incorporate
 * into the software or other computer software, distribute, and sublicense your
 * enhancements or derivative works thereof, in binary and source code form.
 * 
 * DISCLAIMER - THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * “AS IS” AND WITH ALL FAULTS.  THE UNIVERSITY OF DELAWARE, INTERNET2, ITS CONTRI-
 * BUTORS, AND ITS MEMBERS DO NOT IN ANY WAY WARRANT, GUARANTEE, OR ASSUME ANY RES-
 * PONSIBILITY, LIABILITY OR OTHER UNDERTAKING WITH RESPECT TO THE SOFTWARE. ANY E-
 * XPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRAN-
 * TIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT
 * ARE HEREBY DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH THE USER THEREOF.  IN NO EVENT SHALL THE COPYRIGHT
 * OWNER, CONTRIBUTORS, OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELO-
 * PMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTIT-
 * UTE GOODS OR SERVICES; REMOVAL OR REINSTALLATION LOSS OF USE, DATA, SAVINGS OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILIT-
 * Y, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHE-
 * RWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRUBUTION OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
        BWLBoolean  send_local,
        I2Addr      sender,
        I2Addr      receiver,
        uint16_t    tool_port,
        BWLTestSpec *test_spec
        )
{
    BWLTestSession  test;

    /*
     * Address records must exist.
     */
    if(!sender || ! receiver){
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
     * Overwrite sender/receiver with passed-in values
     */
    test->test_spec.sender = sender;
    test->test_spec.receiver = receiver;

    test->conf_receiver = !send_local;
    test->conf_sender = !test->conf_receiver;

    if(send_local){
        test->conf_sender = True;
        test->conf_receiver = False;
        test->tool_port = tool_port;
    }
    else{
        test->conf_receiver = True;
        test->conf_sender = False;
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

    (void)_BWLEndpointStop(tsession,aval,&err);

    if(tsession->closure){
        _BWLCallTestComplete(tsession,aval);
    }

    I2AddrFree(tsession->test_spec.sender);
    I2AddrFree(tsession->test_spec.receiver);

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
    struct sockaddr *saddr = I2AddrSAddr(tsession->test_spec.receiver,NULL);

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

