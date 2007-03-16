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
        BWLBoolean  send,
        I2Addr      sender,
        I2Addr      receiver,
        uint16_t   recv_port,
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

    test->conf_receiver = !send;
    test->conf_sender = !test->conf_receiver;

    if(send){
        test->conf_sender = True;
        test->recv_port = recv_port;
    }
    else{
        test->conf_receiver = True;
        test->recv_port = 0;
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

BWLPacketSizeT
BWLTestPayloadSize(
        BWLSessionMode    mode, 
        uint32_t    padding
        )
{
    BWLPacketSizeT msg_size;

    switch (mode) {
        case BWL_MODE_OPEN:
            msg_size = 14;
            break;
        case BWL_MODE_AUTHENTICATED:
        case BWL_MODE_ENCRYPTED:
            msg_size = 32;
            break;
        default:
            return 0;
            /* UNREACHED */
    }

    return msg_size + padding;
}

/* These lengths assume no IP options. */
#define BWL_IP4_HDR_SIZE    20    /* rfc 791 */
#define BWL_IP6_HDR_SIZE    40    /* rfc 2460 */
#define BWL_UDP_HDR_SIZE    8    /* rfc 768 */

/*
 ** Given the protocol family, OWAMP mode and packet padding,
 ** compute the size of resulting full IP packet.
 */
BWLPacketSizeT
BWLTestPacketSize(
        int             af,    /* AF_INET, AF_INET6 */
        BWLSessionMode  mode, 
        uint32_t       padding
        )
{
    BWLPacketSizeT payload_size, header_size;

    switch (af) {
        case AF_INET:
            header_size = BWL_IP4_HDR_SIZE + BWL_UDP_HDR_SIZE;
            break;
        case AF_INET6:
            header_size = BWL_IP6_HDR_SIZE + BWL_UDP_HDR_SIZE;
            break;
        default:
            return 0;
            /* UNREACHED */
    }

    if(!(payload_size = BWLTestPayloadSize(mode,padding)))
        return 0;

    return payload_size + header_size;
}
