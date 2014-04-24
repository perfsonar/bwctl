/*
 *      $Id$
 */
/************************************************************************
 *                                                                      *
 *                          Copyright (C)  2003                         *
 *                              Internet2                               *
 *                          All Rights Reserved                         *
 *                                                                      *
 ************************************************************************/
/*
 *    File:         endpoint.c
 *
 *    Author:       Jeff W. Boote
 *                  Internet2
 *
 *    Date:         Tue Sep 16 14:25:57 MDT 2003
 *
 *    Description:
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
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "bwlibP.h"
#ifdef HAVE_THRULAY_CLIENT_H
#include <thrulay/client.h>
#endif
#ifdef HAVE_THRULAY_SERVER_H
#include <thrulay/server.h>
#endif

static int ipf_term;
static int ipf_chld;
static int ipf_intr;
static int ipf_alrm;

/*
 * Function:    EndpointAlloc
 *
 * Description:    
 *     Allocate a record to keep track of the state information for
 *     this endpoint. (Much of this state is also in the control record
 *     and the TestSession record... May simplify this in the future
 *     to just reference the other records.)
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static BWLEndpoint
EndpointAlloc(
        BWLTestSession    tsess
        )
{
    BWLEndpoint    ep = calloc(1,sizeof(BWLEndpointRec));

    if(!ep){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                "malloc(EndpointRec)");
        return NULL;
    }

    ep->cntrl = tsess->cntrl;
    ep->tsess = tsess;

    ep->ssockfd = -1;

    ep->acceptval = BWL_CNTRL_INVALID;
    ep->wopts = WNOHANG;

    return ep;
}

/*
 * Function:    EndpointClear
 *
 * Description:    
 *     Clear out any resources that are used in the Endpoint record
 *     that are not needed in the parent process after the endpoint
 *     forks off to do the actual test.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static void
EndpointClear(
        BWLEndpoint    ep
        )
{
    if(!ep)
        return;

    if(ep->ssockfd > -1){
        close(ep->ssockfd);
        ep->ssockfd = -1;
    }

    return;
}

/*
 * Function:    EndpointFree
 *
 * Description:    
 *     completely free all resoruces associated with an endpoint record.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static void
EndpointFree(
        BWLEndpoint    ep
        )
{
    if(!ep)
        return;

    EndpointClear(ep);

    free(ep);

    return;
}

static FILE *
tfile(
        BWLTestSession    tsess
     )
{
    char    fname[PATH_MAX+1];
    int    fd;
    FILE    *fp;

    strcpy(fname,tsess->cntrl->ctx->tmpdir);
    strcat(fname,_BWL_PATH_SEPARATOR);
    strcat(fname,_BWL_TMPFILEFMT);

    if((fd = mkstemp(fname)) < 0){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                "mkstemp(%s): %M",fname);
        return NULL;
    }

    if( !(fp = fdopen(fd,"w+"))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                "fdopen(%s:(%d)): %M",fname,fd);
        return NULL;
    }

    if(unlink(fname) != 0){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                "unlink(%s): %M",fname);
        while((fclose(fp) != 0) && (errno == EINTR));
        return NULL;
    }

    return fp;
}

/*
 * Function:    epssock
 *
 * Description:    
 *              Open a server socket for the endpoint process.
 *              Used for Peer communication.
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
epssock(
        BWLTestSession  tsess,
        uint16_t       *peerport
       )
{
    int                     fd;
    int                     on;
    struct sockaddr         *lsaddr;
    socklen_t               lsaddrlen;
    struct sockaddr_storage sbuff;
    socklen_t               sbuff_len = sizeof(sbuff);
    struct sockaddr         *saddr = (struct sockaddr *)&sbuff;
    char                    nodebuff[MAXHOSTNAMELEN];
    size_t                  nodebufflen = sizeof(nodebuff);
    uint16_t                port;
    uint16_t                p;
    BWLPortRange            portrange=NULL;
    int                     saveerr=0;


    if( !(lsaddr = I2AddrSAddr(tsess->test_spec.server,&lsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "epssock: Invalid server I2Addr");
        return -1;
    }

    fd = socket(lsaddr->sa_family,SOCK_STREAM,IPPROTO_IP);
    if(fd < 0){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                "Unable to open Endpoint Peer Server-Socket: %M");
        return fd;
    }

    on=1;
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) != 0){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                "setsockopt(SO_REUSEADDR): %M");
        goto failsock;
    }

#if    defined(AF_INET6) && defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
    on=0;
    if((lsaddr->sa_family == AF_INET6) &&
            setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&on,sizeof(on)) != 0){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                "setsockopt(!IPV6_V6ONLY): %M");
        goto failsock;
    }
#endif

    if((portrange = (BWLPortRange)BWLContextConfigGetV(tsess->cntrl->ctx,
                    BWLPeerPortRange))){
        /* Initialize port range with 'random' value in range */
        BWLPortsSetI(tsess->cntrl->ctx,portrange,(uint16_t)0);
        p = port = BWLPortsNext(portrange);
    }
    else{
        p = port = 0;
    }

    do{
        memset(&sbuff,0,sizeof(sbuff));
        memcpy(&sbuff,lsaddr,lsaddrlen);

        /* type-punning!! */
        /* Specify port number to use */
        switch(lsaddr->sa_family){
            struct sockaddr_in  *s4;
#ifdef  AF_INET6
            struct sockaddr_in6 *s6;

            case AF_INET6:
            s6 = (struct sockaddr_in6*)&sbuff;
            s6->sin6_port = htons(p);
            break;
#endif
            case AF_INET:
            s4 = (struct sockaddr_in*)&sbuff;
            s4->sin_port = htons(p);
            break;

            default:
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "Invalid address family for peer connection");
            goto failsock;
        }
        
        if(bind(fd,(struct sockaddr *)&sbuff,lsaddrlen) == 0)
            goto bind_success;

        /*
         * If it failed, and we are not using a "range" then break out of
         * loop and report failure. (Or if the error is not EADDRINUSE.)
         */
        if(!portrange || !BWLPortsRange(portrange) || (errno != EADDRINUSE))
            goto bind_fail;

        /*
         * compute next port to try.
         */
        p = BWLPortsNext(portrange);
    } while(p != port);

    saveerr = errno;
    BWLError(tsess->cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
            "Full PeerPortRange exhausted");
bind_fail:
    if(!saveerr) saveerr = errno;
    BWLError(tsess->cntrl->ctx,BWLErrFATAL,saveerr,"bind([%s]:%d): %M",
            I2AddrNodeName(tsess->test_spec.server,nodebuff,&nodebufflen),p);
    goto failsock;

bind_success:

    /* set listen backlog to 1 - we only expect 1 client */
    if(listen(fd,1) != 0){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"listen(): %M");
        goto failsock;
    }

    if(p!=0){
        *peerport = p;
    }
    else{
        /*
         * Retrieve the ephemeral port picked by the system.
         */
        memset(&sbuff,0,sizeof(sbuff));
        if(getsockname(fd,(void*)&sbuff,&sbuff_len) != 0){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"getsockname(): %M");
            goto failsock;
        }

        switch(saddr->sa_family){
            struct sockaddr_in  saddr4;
#ifdef    AF_INET6
            struct sockaddr_in6 saddr6;

            case AF_INET6:
            memcpy(&saddr6,saddr,sizeof(saddr6));
            *peerport = ntohs(saddr6.sin6_port);
            break;
#endif
            case AF_INET:
            memcpy(&saddr4,saddr,sizeof(saddr4));
            *peerport = ntohs(saddr4.sin_port);
            break;
            default:
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "Endpoint control socket: Invalid AF(%d)",
                    saddr->sa_family);
            goto failsock;
        }
    }

    return fd;

failsock:
    while((close(fd) < 0) && (errno == EINTR));
    return -1;
}

#define    _BWLGetSIDAESKEY    "V._BWLGetSIDAESKEY"

static BWLBoolean
getsidaeskey(
        BWLContext    ctx,
        const BWLUserID    userid    __attribute__((unused)),
        BWLKey        key_ret,
        BWLErrSeverity    *err_ret
        )
{
    uint8_t    *sidbytes;

    if(!(sidbytes = (uint8_t*)BWLContextConfigGetV(ctx,_BWLGetSIDAESKEY))){
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                "getsidaeskey: _BWLGetSIDAESKEY not set");
        *err_ret = BWLErrFATAL;
        return False;
    }

    memcpy(key_ret,sidbytes,sizeof(BWLKey));

    return True;
}

int    signo_caught;

static void
sig_catch(
        int    signo
        )
{
    signo_caught = signo;

    switch(signo){
        case SIGTERM:
        case SIGINT:
        case SIGHUP:
            ipf_term++;
            break;
        case SIGALRM:
            ipf_alrm++;
            break;
        case SIGCHLD:
            ipf_chld++;
            /*
             * return - don't want sigchld to interrupt I/O
             */
            return;
            break;
        default:
            BWLError(NULL,BWLErrFATAL,BWLErrUNKNOWN,
                    "sig_catch: Invalid signal(%d)",signo);
            abort();
    }

    ipf_intr++;

    return;
}

/*
 * This function redirects stdout to the tmpfile that was created
 * to hold the result, and then waits until it should fire off
 * the test - and then exec's.
 *
 * Child process:
 *  Redirects I/O, resets signal environment.
 *  Does tool specific preparation (command-line mapping).
 *  Waits until test should actually run.
 *  Invokes tool specific test running.
 */
static void
run_tool(
        BWLEndpoint    ep
        )
{
    BWLTestSession      tsess = ep->tsess;
    BWLContext          ctx = tsess->cntrl->ctx;
    int                 nullfd;
    int                 outfd = fileno(tsess->localfp);
    struct sigaction    act;
    BWLTimeStamp        currtime;
    BWLNum64            reltime;
    struct timespec     ts_sleep;
    struct timespec     ts_remain;
    void                *closure;
    const char          *tname;
    char                addr_str[INET6_ADDRSTRLEN];

    /*
     * Open /dev/null to dup to stdin before the exec.
     */
    if( (nullfd = open(_BWL_DEV_NULL,O_RDONLY)) < 0){
	BWLError(ctx,BWLErrFATAL,errno,"open(/dev/null): %M");
	exit(BWL_CNTRL_FAILURE);
    }

    /*
     * Dup std in/out/err so exec'd tools see a normal environment
     */
    if(        (dup2(nullfd,STDIN_FILENO) < 0) ||
	       (dup2(outfd,STDOUT_FILENO) < 0) ||
	       (dup2(outfd,STDERR_FILENO) < 0)){
	BWLError(ctx,BWLErrFATAL,errno,"dup2(): %M");
	exit(BWL_CNTRL_FAILURE);
    }

    /*
     * Update the tsess local file fp to use the dup'd fd
     */
    if(!(tsess->localfp = fdopen(STDOUT_FILENO,"a"))){
	BWLError(ctx,BWLErrFATAL,errno,"fdopen(STDOUT): %M");
	exit(BWL_CNTRL_FAILURE);
    }

    /*
     * Tool specific test preparation:
     * Also should put a comment in the output file indicating the 'args'
     * that were actually run.)
     */
    if( !(closure = _BWLToolPreRunTest(ctx,tsess))){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "run_tool: Unable to prepare test");
        exit(BWL_CNTRL_FAILURE);
    }

    /*
     * Reset ignored signals to default
     *
     * (exec will reset set signals to default, but leaves ignored signals
     * as is - this is confusing for some tools. i.e. some tools depend
     * on getting sigpipe.)
     */
    memset(&act,0,sizeof(act));
    act.sa_handler = SIG_DFL;
    sigemptyset(&act.sa_mask);
    if( (sigaction(SIGPIPE,&act,NULL) != 0) ||
            (sigaction(SIGALRM,&act,NULL) != 0)){
	BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"sigaction(): %M");
	exit(BWL_CNTRL_FAILURE);
    }

    /*
     * Compute the time until the test should start.
     */
    if(!BWLGetTimeStamp(ctx,&currtime)){
	BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
		 "BWLGetTimeStamp(): %M");
	exit(BWL_CNTRL_FAILURE);
    }
    if(ipf_term) exit(BWL_CNTRL_FAILURE);

    if(BWLNum64Cmp(tsess->reserve_time,currtime.tstamp) < 0){
	BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
		 "run_tool(): Too LATE!");
	exit(BWL_CNTRL_FAILURE);
    }

    reltime = BWLNum64Sub(tsess->reserve_time,currtime.tstamp);

    /*
     * Use the error estimates rounded up to 1 second, and start the
     * recv side that much before the test time.
     */
    if(tsess->conf_server){
	if(BWLNum64Cmp(reltime,tsess->fuzz) > 0){
	    reltime = BWLNum64Sub(reltime,tsess->fuzz);
	}
	else{
	    reltime = BWLULongToNum64(0);
	}
    }

    timespecclear(&ts_sleep);
    timespecclear(&ts_remain);
    BWLNum64ToTimespec(&ts_sleep,reltime);

    while(timespecisset(&ts_sleep)){
	if(nanosleep(&ts_sleep,&ts_remain) == 0){
	    break;
	}
	if(ipf_term) exit(BWL_CNTRL_FAILURE);
	ts_sleep = ts_remain;
    }

    /*
     * Report some information about this test.
     */
    if (tsess->test_spec.verbose) {
        tname = BWLToolGetNameByID(ctx,tsess->test_spec.tool_id);
        fprintf(tsess->localfp,"bwctl: run_tool: tester: %s\n",((tname)?tname:"unknown"));

        if( BWLAddrNodeName(ctx, tsess->test_spec.server, addr_str, sizeof(addr_str), NI_NUMERICHOST) != 0) {
            fprintf(tsess->localfp,"bwctl: run_tool: %s: %s\n", (tsess->test_spec.server_sends?"sender":"receiver"),addr_str);
        }

        if( BWLAddrNodeName(ctx, tsess->test_spec.client, addr_str, sizeof(addr_str), NI_NUMERICHOST) != 0) {
            fprintf(tsess->localfp,"bwctl: run_tool: %s: %s\n", (tsess->test_spec.server_sends?"receiver":"sender"),addr_str);
        }

        BWLGetTimeStamp(ctx,&currtime);
        fprintf(tsess->localfp,"bwctl: start_tool: %f\n",
                BWLNum64ToDouble(currtime.tstamp));
    }

    fflush(tsess->localfp);

    _BWLToolRunTest(ctx,tsess,closure);
    /*NOTREACHED*/
}

BWLBoolean
_BWLEndpointStart(
        BWLTestSession  tsess,
        uint16_t        *peerport,
        BWLErrSeverity  *err_ret
        )
{
    BWLContext          ctx = tsess->cntrl->ctx;
    BWLEndpoint         ep;
    BWLGetAESKeyFunc    getaeskey = getsidaeskey;
    sigset_t            sigs;
    sigset_t            osigs;
    struct sigaction    act;
    BWLTimeStamp        currtime;
    BWLTimeStamp        rtime;
    BWLTimeStamp        currtime2;
    BWLNum64            reltime;
    struct itimerval    itval;
    BWLAcceptType       aval = BWL_CNTRL_FAILURE;
    fd_set              readfds;
    fd_set              exceptfds;
    int                 max_readfd;
    int                 rc=0;
    int                 do_read=0;
    int                 do_write=0;
    BWLRequestType      msgtype = BWLReqInvalid;
    uint32_t            mode;
    int                 dead_child;
    int                 alarm_set;
    char                nambuf[MAXHOSTNAMELEN+8]; /* 8 chars for '[]:port\0' */
    size_t              nambuflen = sizeof(nambuf);
    char                addr_str[INET6_ADDRSTRLEN];


    if( !(tsess->localfp = tfile(tsess)) ||
            !(tsess->remotefp = tfile(tsess))){
        return False;
    }

    if( !(ep=EndpointAlloc(tsess))){
        return False;
    }

    if(tsess->conf_server && !tsess->test_spec.no_server_endpoint){
        if((ep->ssockfd = epssock(tsess,peerport)) < 0){
            EndpointFree(ep);
            return False;
        }
    }

    /*
     * sigprocmask to block signals before the fork. Then
     * install new sig handlers in the child before unblocking
     * them. In the parent, just unblock them. (The sigprocmask
     * is needed to stop the possible race condition of the parent registered
     * sig hanglers being called in the child process before the child ones
     * are registered.)
     */
    sigemptyset(&sigs);
    sigaddset(&sigs,SIGTERM);
    sigaddset(&sigs,SIGINT);
    sigaddset(&sigs,SIGCHLD);
    sigaddset(&sigs,SIGALRM);

    if(sigprocmask(SIG_BLOCK,&sigs,&osigs) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"sigprocmask(): %M");
        EndpointFree(ep);
        return False;
    }
    tsess->endpoint = ep;

    ep->child = fork();

    if(ep->child < 0){
        /* fork error */
        int    serr = errno;
        (void)sigprocmask(SIG_SETMASK,&osigs,NULL);
        BWLError(ctx,BWLErrFATAL,serr,"fork(): %M");
        EndpointFree(ep);
        tsess->endpoint = NULL;
        return False;
    }

    if(ep->child > 0){
        /* parent */
        int    cstatus;

        if(sigprocmask(SIG_SETMASK,&osigs,NULL) != 0){
            BWLError(ctx,BWLErrFATAL,errno,"sigprocmask(): %M");
            killpg(ep->child,SIGINT);
            ep->wopts &= ~WNOHANG;
            while((waitpid(ep->child,&cstatus,ep->wopts) < 0) &&
                    (errno == EINTR));
            EndpointFree(ep);
            tsess->endpoint = NULL;
            return False;
        }

        EndpointClear(ep);

        /*
         * Keep localfp and remotefp open. The ProcessResults
         * function is called from this process.
         */

        return True;
    }

    /* child */

    /*
     * Set the process group to the PID of the child. This will get overwritten
     * later, but do it here so we can do "killpg(ep->child)" whether we have
     * forked the tester or not.
     */
    setpgid(0, 0); 

    /*
     * Set sig handlers
     */
    ipf_alrm = ipf_term = ipf_intr = ipf_chld = 0;
    memset(&act,0,sizeof(act));
    act.sa_handler = sig_catch;
    sigemptyset(&act.sa_mask);
    if(        (sigaction(SIGTERM,&act,NULL) != 0) ||
            (sigaction(SIGINT,&act,NULL) != 0) ||
            (sigaction(SIGCHLD,&act,NULL) != 0) ||
            (sigaction(SIGALRM,&act,NULL) != 0) ||
            (sigaction(SIGHUP,&act,NULL) != 0)
      ){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"sigaction(): %M");
        exit(BWL_CNTRL_FAILURE);
    }

    if(sigprocmask(SIG_SETMASK,&osigs,NULL) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"sigprocmask(): %M");
        exit(BWL_CNTRL_FAILURE);
    }

    if(ipf_term){
        BWLError(ctx,BWLErrFATAL,errno,"Caught SIGTERM!");
        exit(BWL_CNTRL_FAILURE);
    }

#ifndef    NDEBUG
    /*
     * busy loop to wait for debugger attachment
     */
    {
        void    *waitfor = BWLContextConfigGetV(ctx,BWLChildWait);

        /*
         * Syslog will print the PID making it easier to 'attach'
         * from a debugger.
         */
        if(waitfor){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"waitfor!");
        }

        while(waitfor);
    }
#endif

    /*
     * Now setup the peer control connection
     */

    /*
     * Reset the GetAESKey function to use the SID for the AESKey in
     * the Endpoint to Endpoint control connection setup.
     */
    if(        !BWLContextConfigSet(ctx,BWLGetAESKey,(BWLFunc)getaeskey) ||
            !BWLContextConfigSet(ctx,_BWLGetSIDAESKEY,(void *)tsess->sid) ||
            !BWLContextConfigSet(ctx,BWLInterruptIO,(void*)&ipf_intr)
      ){
        BWLError(ctx,BWLErrFATAL,errno,
                "Unable to set for Context vars for endpoint: %M");
        goto end;
    }
    (void)BWLContextConfigDelete(ctx,BWLCheckControlPolicy);
    (void)BWLContextConfigDelete(ctx,BWLCheckTestPolicy);
    (void)BWLContextConfigDelete(ctx,BWLTestComplete);
    (void)BWLContextConfigDelete(ctx,BWLProcessResults);

    /*
     * Set a timer - if we have not established a connection with
     * the remote endpoint before the time the test should start,
     * exit.
     */
    if(!BWLGetTimeStamp(ctx,&currtime)){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "BWLGetTimeStamp(): %M");
        goto end;
    }

    if (tsess->test_spec.verbose) {
        fprintf(tsess->localfp,"bwctl: start_endpoint: %f\n",
                BWLNum64ToDouble(currtime.tstamp));

        if( BWLAddrNodeName(ctx, tsess->test_spec.server, addr_str, sizeof(addr_str), NI_NUMERICHOST) != 0) {
            fprintf(tsess->localfp,"bwctl: run_endpoint: %s: %s\n", (tsess->test_spec.server_sends?"sender":"receiver"),addr_str);
        }

        if( BWLAddrNodeName(ctx, tsess->test_spec.client, addr_str, sizeof(addr_str), NI_NUMERICHOST) != 0) {
            fprintf(tsess->localfp,"bwctl: run_endpoint: %s: %s\n", (tsess->test_spec.server_sends?"receiver":"sender"),addr_str);
        }

        fflush(tsess->localfp);
    }

    if(BWLNum64Cmp(tsess->reserve_time,currtime.tstamp) < 0){
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                "endpoint to endpoint setup too late");
        goto end;
    }

    reltime = BWLNum64Sub(tsess->reserve_time,currtime.tstamp);

#if	defined NOT
    BWLError(ctx,BWLErrDEBUG,BWLErrINVALID,
            "currtime = %f, reservation = %f, reltime = %f",
            BWLNum64ToDouble(currtime.tstamp),
            BWLNum64ToDouble(tsess->reserve_time),
            BWLNum64ToDouble(reltime)
            );
    BWLError(ctx,BWLErrDEBUG,BWLErrINVALID,
            "inter = %d, catchval = %d",ipf_intr,signo_caught);
#endif

    memset(&itval,0,sizeof(itval));
    BWLNum64ToTimeval(&itval.it_value,reltime);
    if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"setitimer(): %M");
        goto end;
    }

    /*
     * Determine what "mode" the peer connection should happen at.
     * The server side should be willing to do anything as strict or
     * more strict than it does. The client should be the same, but
     * it should use the "least" strict mode that matches so set
     * the BWL_MODE_LEAST_RESTRICTIVE bit for the call to BWLControlOpen.
     */
    mode = BWL_MODE_LEAST_RESTRICTIVE;
    switch(tsess->cntrl->mode){
        case BWL_MODE_OPEN:
            mode |= BWL_MODE_OPEN;
            /*fall through*/
        case BWL_MODE_AUTHENTICATED:
            mode |= BWL_MODE_AUTHENTICATED;
            /*fall through*/
        case BWL_MODE_ENCRYPTED:
            mode |= BWL_MODE_ENCRYPTED;
            break;
        default:
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "Endpoint: Invalid session mode");
    }

    if(tsess->conf_server && !tsess->test_spec.no_server_endpoint){
        struct sockaddr         *ssaddr;
        socklen_t               ssaddrlen;
        struct sockaddr_storage sbuff;
        socklen_t               sbuff_len;
        int                     connfd;

        if( !(ssaddr = I2AddrSAddr(tsess->test_spec.client,&ssaddrlen))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                    "_BWLEndpointStart: Invalid client I2Addr");
            goto end;
        }

ACCEPT:
        sbuff_len = sizeof(sbuff);
        connfd = accept(ep->ssockfd,(struct sockaddr *)&sbuff,
                &sbuff_len);
        if(connfd < 0){
            if(errno == EINTR && !ipf_intr){
                goto ACCEPT;
            }
            BWLError(ctx,BWLErrFATAL,errno,
                    "Endpoint peer connection could not accept(): listening at port(%d) : %M",
                    *peerport);
            fprintf(tsess->localfp,
                    "bwctl: Remote \'client\' (%s) never initiated handshake: listening at port(%d) - canceling\n",
                    I2AddrNodeName(tsess->test_spec.client,nambuf,&nambuflen),
                    *peerport
                   );
            if(ipf_intr){
                BWLError(tsess->cntrl->ctx,BWLErrFATAL,
                        BWLErrINVALID,
                        "Endpoint: Signal = %d",signo_caught);
            }
            goto end;
        }

        /*
         * Only allow connections from the remote testaddr
         */
        if(I2SockAddrEqual(ssaddr,ssaddrlen,
                    (struct sockaddr *)&sbuff,sbuff_len,
                    I2SADDR_ADDR) <= 0){
            BWLError(ctx,BWLErrFATAL,BWLErrPOLICY,
                    "Connect from unknown addr, assuming NAT");
        }

        close(ep->ssockfd);
        ep->ssockfd = -1;

        ep->rcntrl = BWLControlAccept(ctx,connfd,
                (struct sockaddr *)&sbuff,sbuff_len,
                mode,currtime.tstamp,
                &ipf_intr,err_ret);
    }

    if (tsess->conf_client && !tsess->test_spec.no_server_endpoint) {
        /*
         * Copy remote address, with modified port number
         * and other fields for contacting remote host.
         */
        const char          *local = NULL;
        char                local_addr_str[1024];
        I2Addr              remote;
        struct sockaddr     *saddr;
        socklen_t           saddrlen;
        BWLToolAvailability tavail = 0;

        if( BWLAddrNodeName(ctx, tsess->test_spec.client, local_addr_str, sizeof(local_addr_str), NI_NUMERICHOST) != 0) {
            local = local_addr_str;
        }

        remote = I2AddrCopy(tsess->test_spec.server);
        if (remote) {
            if(!(I2AddrSetPort(remote,*peerport))){
                I2AddrFree(remote);
                remote = NULL;
            }

            BWLAddrNodeName(ctx, remote, addr_str, sizeof(addr_str), NI_NUMERICHOST);
        }

        if(!local || !remote){
            BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                    "Endpoint: Unable to alloc peer addrs: %M");
            goto end;
        }

        ep->rcntrl = BWLControlOpen(ctx,local,remote,mode,"endpoint",NULL,
                &tavail,err_ret);

        if(!ep->rcntrl){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                    "Endpoint: Unable to connect to Peer([%s]:%d): %M",
                    addr_str, *peerport
                    );
            fprintf(tsess->localfp,
                    "bwctl: Unable to initiate peer handshake with [%s]:%d - canceling\n",
                    addr_str, *peerport
                    );
        }
    }

    if((!tsess->test_spec.no_server_endpoint && !ep->rcntrl) || ipf_term || ipf_alrm){
        goto end;
    }

    /*
     * Setup dynamic window if tcp test.
     */
    if(!tsess->test_spec.udp && tsess->test_spec.dynamic_window_size){
        /*
         * TODO:
         *     gets bottleneck capacity from context (set via config)
         *     Uses BWLGetRTTBound(ep->rcntrl) for rtt estimate
         *
         * Eventually, this could send ICMP packets and use
         * inter-packet arrival times to estimate bottleneck capacity.
         * (Will this take too much time for scheduling purposes?)
         *
         * Reset window_size based on the results.
         */
        uint64_t    bnc;

        if( BWLContextConfigGetU64(ctx,BWLBottleNeckCapacity,&bnc)){
            double  dbnc = (double)bnc;
            double  rtt;

            if (ep->rcntrl) {
                rtt = BWLNum64ToDouble(BWLGetRTTBound(ep->rcntrl));
            }
            else {
                rtt = 1.0;
            }

            dbnc *= rtt / 8 * 1.1;

            /*
             * Don't worry about overflow... We wouldn't want a window
             * larger than can be represented as a 32bit int anyway...
             */
            tsess->test_spec.window_size = (uint32_t)dbnc;
        }
    }

    /*
     * Now fork again. The child will go on to "exec" iperf at the
     * appropriate time. The parent will exchange timestamps with the other
     * endpoint for time-sync validation and then trade the test results
     * upon completion of the test.
     */
    ep->child = fork();

    if(ep->child < 0){
        /* fork error */
        BWLError(ctx,BWLErrFATAL,errno,"fork(): %M");
        exit(BWL_CNTRL_FAILURE);
    }

    if(ep->child == 0){
        /* Run the tool in the child process. */

        /*
         * Set the process group to the PID of the child. All its children should
         * inherit that process group.
         */
        setpgid(0, 0); 

        run_tool(ep);
        /* NOTREACHED */
    }

    /*
     * Now that we have established communication, and forked off the
     * test: reset the timer for just past the end of the test period.
     * (one second past the session time plus the fuzz time.)
     */
    if(!BWLGetTimeStamp(ctx,&currtime)){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "PeerAgent: BWLGetTimeStamp(): %M");
        goto end;
    }

    if(BWLNum64Cmp(tsess->reserve_time,currtime.tstamp) < 0){
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                "PeerAgent: endpoint to endpoint setup too late");
        goto end;
    }

    /* Timer for end-of-test */
    reltime = BWLNum64Sub(tsess->reserve_time,currtime.tstamp);
    reltime = BWLNum64Add(reltime,tsess->fuzz);
    reltime = BWLNum64Add(reltime,
            BWLULongToNum64(tsess->test_spec.duration));
    reltime = BWLNum64Add(reltime,
            BWLULongToNum64(tsess->test_spec.omit));

    memset(&itval,0,sizeof(itval));
    BWLNum64ToTimeval(&itval.it_value,reltime);
    if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"PeerAgent: setitimer(): %M");
        goto end;
    }

    if(ipf_term){
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                "PeerAgent: Catching SIGTERM...");
        goto end;
    }

    if (ep->rcntrl) {
        if(tsess->conf_server){
            if(BWLReadRequestType(ep->rcntrl,&ipf_intr) != BWLReqTime){
                BWLError(ctx,BWLErrFATAL,errno,
                        "PeerAgent: Invalid message from peer");
                goto end;
            }

            if(BWLProcessTimeRequest(ep->rcntrl,&ipf_intr) != BWLErrOK){
                BWLError(ctx,BWLErrFATAL,errno,
                        "PeerAgent: Unable to process time request for peer");
                goto end;
            }
        }else{
            /*
             * Make sure two clocks are synchronized enough that
             * sessions will start when they should.
             */

            double        t1,t2,tr;
            double        e1,e2,er;

            if(BWLControlTimeCheck(ep->rcntrl,&rtime) != BWLErrOK){
                BWLError(ctx,BWLErrFATAL,errno,
                        "PeerAgent: BWLControlTimeCheck(): %M");
                goto end;
            }
            if(!BWLGetTimeStamp(ctx,&currtime2)){
                BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                        "PeerAgent: BWLGetTimeStamp(): %M");
                goto end;
            }

            t1 = BWLNum64ToDouble(currtime.tstamp);
            t2 = BWLNum64ToDouble(currtime2.tstamp);
            tr = BWLNum64ToDouble(rtime.tstamp);
            e1 = BWLNum64ToDouble(BWLGetTimeStampError(&currtime));
            e2 = BWLNum64ToDouble(BWLGetTimeStampError(&currtime2));
            er = BWLNum64ToDouble(BWLGetTimeStampError(&rtime));
    
            if((t1-e1) > (tr+er)){
                BWLError(ctx,BWLErrFATAL,errno,
                        "PeerAgent: Remote clock is at least %f(secs) "
                        "ahead of local, NTP only indicates %f(secs) error, failing",
                        t1-tr,e1+er);
                fprintf(tsess->localfp,
                        "bwctl: Remote clock is at least %f(secs) ahead of local,"
                        " NTP only indicates %f(secs) error, failing\n",
                        t1-tr,e1+er);
                ipf_intr = 1;
            }
            else if((tr-er) > (t2+e2)){
                BWLError(ctx,BWLErrFATAL,errno,
                        "PeerAgent: Remote clock is at least %f(secs) "
                        "behind local, NTP only indicates %f(secs) error, failing",
                        tr-t2,e2+er);
                fprintf(tsess->localfp,
                        "PeerAgent: Remote clock is at least %f(secs) behind local,"
                        " NTP only indicates %f(secs) error, failing\n",
                        tr-t2,e2+er);
                ipf_intr = 1;
            }
        }

        /*
         * Fake rcntrl socket into "test" mode and set it up to trade results.
         */
        ep->rcntrl->tests = tsess;
        tsess->cntrl = ep->rcntrl;
        tsess->closure = NULL;
        ep->rcntrl->state |= _BWLStateTest;
    }

    FD_ZERO(&readfds);
    if (ep->rcntrl) {
       FD_SET(ep->rcntrl->sockfd,&readfds);
       max_readfd = ep->rcntrl->sockfd;
    }
    else {
       max_readfd = -1;
    }
    exceptfds = readfds;
    do_read=do_write=1;

    /* Earliest time test should complete */
    currtime2.tstamp = BWLNum64Sub(tsess->reserve_time,tsess->fuzz);
    currtime2.tstamp = BWLNum64Add(currtime2.tstamp,
            BWLULongToNum64(tsess->test_spec.duration));
    currtime2.tstamp = BWLNum64Add(currtime2.tstamp,
            BWLULongToNum64(tsess->test_spec.omit));

    /*
     * Wait for something to do:
     *  Peer message - remote stopping test
     *  Child exit - local side complete (or failed)
     *  Timer expire - test hung?
     *  TERM signal - parent killing this.
     */
    while(!rc && !ipf_intr){
        rc = select(max_readfd + 1,&readfds,NULL,&exceptfds,NULL);
    }

    /*
     * Did alarm go off? (Is the test hung?)
     */
    alarm_set = ipf_alrm;

    /*
     * We ran into an issue where the client would finish and send a
     * StopSession message before the server was finished (The race condition
     * described in comments below). The idea with the subsequent sleep is to
     * pause for (hopefully) long enough for iperf to finish up. 
     *
     * FIXME: we need a more elegant way to do this
     */
    if(rc > 0){
        struct timeval tv;

        BWLNum64ToTimeval(&tv, tsess->fuzz);

        assert(tv.tv_sec >= 0);
        sleep((unsigned)tv.tv_sec);
    }

    /*
     * Get current time
     */
    BWLGetTimeStamp(ctx,&currtime);

    /*
     * unset itimer
     */
    memset(&itval,0,sizeof(itval));
    if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"PeerAgent: setitimer(): %M");
    }

    /*
     * Is tester dead before it is killed?
     */
    dead_child = ipf_chld;

    /*
     * send a graceful kill to the child (If already dead, errno will be ESRCH)
     *
     * There is an unlikely race condition:
     * The client side will finish first, it is technically possible that it
     * will exit, and the PeerAgent watching it exit will send the StopSession
     * message to the reciever PeerAgent. It is *possible* that the StopSession
     * message could get to the reciver PeerAgent before the tester-tool
     * server process ends.
     *
     * This is unlikely since it will do things like fetch the timestamp
     * above before sending the message, and it will have to traverse the
     * same network as the tester tool... However, it may eventually be
     * prudent to wait 'errest' after the client process finishes before
     * sending the StopSession message.
     */
    if(!ipf_chld && ep->child){

        /*
         * Send the kill signal twice, iperf does not exit after receiving one
         */
        if(killpg(ep->child,SIGTERM) == 0){
            /*
             * Ignore any errors from the second one since some testing tools
             * will actually die from just the first one.
             */
            (void)killpg(ep->child,SIGTERM);
            ep->killed = True;

        }
        else if(errno != ESRCH){
            /* kill failed */
            BWLError(ctx,BWLErrFATAL,errno,
                    "PeerAgent: kill(): Unable to gracefully kill test endpoint, pid=%d: %M",
                    ep->child);
            exit(BWL_CNTRL_FAILURE);
        }
    }

    if(ipf_term){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "PeerAgent: Caught termination signal, test exiting");
        goto end;
    }


    /*
     * Handle unexpected error condition - goto is C's exception
     * handler.
     */
    if(rc > 0){
        if(!FD_ISSET(ep->rcntrl->sockfd,&readfds)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "PeerAgent: select(): peer connection not ready?");
            goto end;
        }
    }

    /*
     *
     * Get child exit status
     *
     */
    if(!_BWLEndpointStatus(ctx,tsess,&ep->acceptval,err_ret)){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "PeerAgent: _BWLEndpointStatus failed");
        exit(BWL_CNTRL_FAILURE);
    }

    /*
     * If acceptval < 0, then test process is still running. Pull-out the
     * big gun (SIGKILL).
     */
    if(ep->child && (ep->acceptval < 0)){
        BWLError(ctx,BWLErrDEBUG,errno,
                "PeerAgent: Killing tester with SIGKILL, pid=%d",
                ep->child);
        if((killpg(ep->child,SIGKILL) != 0) && (errno != ESRCH)){
            /* kill failed */
            BWLError(ctx,BWLErrFATAL,errno,
                    "PeerAgent: Unable to kill test endpoint, pid=%d: %M",
                    ep->child);
            exit(BWL_CNTRL_FAILURE);
        }

        /*
         * call Status again, but this time wait for the process to end.
         */
        ep->wopts &= ~WNOHANG;
        if(!_BWLEndpointStatus(ctx,tsess,&ep->acceptval,err_ret)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "PeerAgent: _BWLEndpointStatus failed");
            exit(BWL_CNTRL_FAILURE);
        }
    }

    /*
     * Report if test completed early.
     */
    if(BWLNum64Cmp(currtime.tstamp,currtime2.tstamp) < 0){

        /*
         * Child exited early
         */
        if(dead_child && ep->exit_status){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "PeerAgent: Local tool exited before expected with status=%d",
                    ep->exit_status);
            fprintf(tsess->localfp,
                    "bwctl: local tool exited before expected with status=%d\n",
                    ep->exit_status);
        }

        /*
         * Peer stopped test early
         */
        if(rc > 0){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "PeerAgent: Peer cancelled test before expected");
            fprintf(tsess->localfp,"\nbwctl: remote peer cancelled test\n");
        }

    }

    /*
     * Report if the local test had to be killed.
     */
    if(alarm_set){
            // try to make sure these print on their own line
            fprintf(tsess->localfp,
                    "\nbwctl: local tool did not complete in allocated time frame and was killed\n");
    }

    /*
     * Prepare data to send to peer
     * Print 'final' data of local tool
     */
    if (tsess->test_spec.verbose) {
        fprintf(tsess->localfp,"bwctl: stop_tool: %f\n",
                BWLNum64ToDouble(currtime.tstamp));
        fflush(tsess->localfp);
    }

    if (ep->rcntrl) {
        /*
         * Write StopSession to peer to send test results from this side.
         */
        *err_ret = _BWLWriteStopSession(ep->rcntrl,&ipf_intr,ep->acceptval,
                tsess->localfp);
        if(*err_ret != BWLErrOK){
            BWLError(ctx,BWLErrFATAL,errno,
                    "PeerAgent: Unable to send StopSession to peer");
            goto end;
        }

        /*
         * Is socket readable? Select again. If it was readable before, this
         * is a no-op. If not, this will wait until the peer StopSession
         * message comes.
         *
         * XXX: Need a timeout here?
         */
        /* if earlier selected ended due to intr, reset rc to 0 so select called */
        if(rc < 0) rc=0;
        while(!rc && !ipf_term){
            rc = select(ep->rcntrl->sockfd+1,&readfds,NULL,&exceptfds,NULL);
        }
        if(ipf_term){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "PeerAgent: Caught termination signal, test exiting");
            goto end;
        }

        /*
         * Socket ready, read StopSession message from peer.
         */
        if(rc > 0){

            msgtype = BWLReadRequestType(ep->rcntrl,&ipf_intr);

            switch(msgtype){

                /* socket closed */
                case 0:
                    BWLError(ctx,BWLErrFATAL,errno,"PeerAgent: Test peer closed connection.");
                    break;

                    /* stop session message */
                case 3:
                    *err_ret = _BWLReadStopSession(ep->rcntrl,&ipf_intr,&aval,
                            tsess->remotefp);
                    break;

                    /* anything else */
                default:
                    BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                            "PeerAgent: Invalid protocol message from test peer");
                    break;

            }

        }
    }

end:

    BWLGetTimeStamp(ctx,&currtime);

    if (tsess->test_spec.verbose) {
        fprintf(tsess->localfp,"bwctl: stop_endpoint: %f\n",
                BWLNum64ToDouble(currtime.tstamp));
    }

    /*
     * aval == remote status
     * ep->acceptval == local status
     *
     * return status to parent.
     */
    exit(aval & ep->acceptval);
}

BWLBoolean
_BWLEndpointStatus(
        BWLContext      ctx,
        BWLTestSession  tsess,
        BWLAcceptType   *aval,        /* out */
        BWLErrSeverity  *err_ret
        )
{
    pid_t       p;
    int         childstatus;
    BWLEndpoint ep = tsess->endpoint;

    *err_ret = BWLErrOK;

    if(!ep)
        return True;

    if(ep->acceptval < 0){
AGAIN:
        p = waitpid(ep->child,&childstatus,ep->wopts);
        if(p < 0){
            if(errno == EINTR)
                goto AGAIN;
            BWLError(ctx,BWLErrWARNING,
                    BWLErrUNKNOWN,
                    "_BWLEndpointStatus: Can't query child #%d: %M",
                    ep->child);
            ep->acceptval = BWL_CNTRL_FAILURE;
            *err_ret = BWLErrWARNING;
            return False;
        }
        else if(p > 0){
            if(WIFEXITED(childstatus)){
                ep->exit_status = WEXITSTATUS(childstatus);
                ep->acceptval = (ep->exit_status)?
                    BWL_CNTRL_FAILURE : BWL_CNTRL_ACCEPT;
            }
            else if(WIFSIGNALED(childstatus)){
                if(ep->killed){
                    ep->acceptval = BWL_CNTRL_REJECT;
                    ep->exit_status = 0;
                }
                else{
                    BWLError(ctx,BWLErrWARNING,errno,
                            "_BWLEndpointStatus: Child #%d exited from signal #%d",
                            ep->child,WTERMSIG(childstatus));
                    ep->acceptval = BWL_CNTRL_FAILURE;
                    /* signal number for exit value */
                    ep->exit_status = WTERMSIG(childstatus);
                }
                *err_ret = BWLErrWARNING;
            }
        }
        /*
         * if(p==0) process still running just fine - fall through.
         */
    }

    *aval = ep->acceptval;
    return True;
}


BWLBoolean
_BWLEndpointStop(
        BWLContext        ctx,
        BWLTestSession    tsess,
        BWLAcceptType    aval,
        BWLErrSeverity    *err_ret
        )
{
    int        teststatus;
    BWLBoolean    retval;
    BWLEndpoint    ep = tsess->endpoint;

    if(!ep)
        return True;

    if((ep->acceptval >= 0) || (ep->child == 0)){
        *err_ret = BWLErrOK;
        goto done;
    }

    *err_ret = BWLErrFATAL;

    /*
     * If child already exited, kill will come back with ESRCH
     */
    if(!ep->dont_kill){
        if(killpg(ep->child,SIGTERM) != 0){
            if(errno != ESRCH){
                goto error;
            }
        }
        else{
            fprintf(tsess->localfp,"bwctl: kill(%d,TERM): tester\n",ep->child);
        }
        ep->killed = True;
    }

    /*
     * Remove the WNOHANG bit. We need to wait until the exit status
     * is available.
     * (Should we add a timer to break out? No - not that paranoid yet.)
     */
    ep->wopts &= ~WNOHANG;
    retval = _BWLEndpointStatus(ctx,tsess,&teststatus,err_ret);
    if(teststatus >= 0)
        goto done;

error:
    BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
            "EndpointStop:Can't signal child #%d: %M",ep->child);
done:
    if(aval < ep->acceptval){
        aval = ep->acceptval;
    }
    ep->tsess->endpoint = NULL;
    EndpointFree(ep);

    return retval;
}
