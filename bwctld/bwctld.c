/*! \file bwctld.c */
/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabls-mode: nil -*-
 *      $Id$
 */
/************************************************************************
*                                                                       *
*                           Copyright (C)  2003                         *
*                               Internet2                               *
*                           All Rights Reserved                         *
*                                                                       *
************************************************************************/
/*
 *    File:         bwctld.c
 *
 *    Author:       Jeff Boote
 *                  Internet2
 *
 *    Date:         Tue Sep  9 16:05:50 MDT 2003
 *
 *    Description:    
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>

#include <I2util/util.h>
#include <bwlib/bwlib.h>

#include "bwctldP.h"
#include "policy.h"

/* Global variable - the total number of allowed Control connections. */
static pid_t                mypid;
static int                  ipfd_chld = 0;
static int                  ipfd_exit = 0;
static int                  ipfd_alrm = 0;
static int                  ipfd_intr = 0;
static bwctld_opts          opts;
static I2ErrLogSyslogAttr   syslogattr;
static I2ErrHandle          errhand;
static I2Table              fdtable=NULL;
static I2Table              pidtable=NULL;
static BWLNum64             uptime;
static BWLPortRangeRec      peerports;

#if defined HAVE_DECL_OPTRESET && !HAVE_DECL_OPTRESET
int optreset;
#endif

static void
usage(
        const char *progname,
        const char *msg    __attribute__((unused))
     )
{
    fprintf(stderr, "\nUsage: %s [options]\n\n", progname);
    fprintf(stderr, "Where \"options\" are:\n\n");

    fprintf(stderr,
            "   -a authmode       Default supported authmodes:[E]ncrypted,[A]uthenticated,[O]pen\n"
            "   -c confdir        Configuration directory\n"
            "   -d datadir        Data directory\n"
            "   -e facility       syslog facility to log errors\n"
            "   -f                Allow daemon to run as \"root\" (folly!)\n"
            "   -G group          Run as group \"group\" :-gid also valid\n"
            "   -h                Print this message and exit\n"
            "   -R vardir         Location for pid file\n"
           );
    fprintf(stderr,
            "   -S nodename:port  Srcaddr to bind to\n"
            "      -U/-G options only used if run as root\n"
            "   -U user           Run as user \"user\" :-uid also valid\n"
            "   -v                verbose output\n"
#ifndef    NDEBUG
            "   -w                Debugging: busy-wait children after fork to allow attachment\n"
            "   -Z                Debugging: Run in foreground\n"
#endif
            "\n"
           );
    fprintf(stderr, "\nVersion: %s\n\n", PACKAGE_VERSION);
    return;
}

/*
 ** Handler function for SIG_CHLD.
 */
static void
signal_catch(
        int    signo
        )
{
    switch(signo){
        case SIGTERM:
        case SIGINT:
        case SIGHUP:
        case SIGUSR1:
        case SIGUSR2:
            if(!ipfd_exit){
                ipfd_exit = 1;
            }
            break;
        case SIGCHLD:
            ipfd_chld = 1;
            break;
        case SIGALRM:
            ipfd_alrm = 1;
            break;
        default:
            I2ErrLog(errhand,"signal_catch(): Invalid signal(%d)",
                    signo);
            _exit(BWL_CNTRL_FAILURE);
    }

    ipfd_intr++;

    return;
}

typedef struct ReservationRec ReservationRec, *Reservation;
struct ReservationRec{
    BWLSID      sid;
    BWLNum64    restime;
    BWLNum64    start;    /* fuzz applied */
    BWLNum64    end;    /* fuzz applied */
    BWLNum64    fuzz;
    uint32_t   duration;
    uint16_t   port;
    Reservation next;
};

typedef struct ChldStateRec ChldStateRec, *ChldState;
struct ChldStateRec{
    BWLDPolicy      policy;
    pid_t           pid;
    int             fd;
    BWLDPolicyNode  node;
    Reservation     res;
};

static Reservation
AllocReservation(
        ChldState   cstate,
        BWLSID      sid,
        uint16_t   *port
        )
{
    Reservation res;

    if(cstate->res){
        BWLError(cstate->policy->ctx,BWLErrFATAL,BWLErrINVALID,
                "AllocReservation: cstate->res != NULL");
        return NULL;
    }

    if( !(res = calloc(1,sizeof(*res)))){
        BWLError(cstate->policy->ctx,BWLErrFATAL,ENOMEM,"malloc(): %M");
        return NULL;
    }

    memcpy(res->sid,sid,sizeof(sid));

    /*
     * Get next port in range
     * Could add randomness... For now just step through.
     */
    if(!*port){
        res->port = opts.iperfports[
            opts.port_count++ % opts.port_range_len];
    }
    else{
        res->port = *port;
    }

    cstate->res = res;

    return res;
}

static void
FreeReservation(
        Reservation res
        )
{
    if(!res)
        return;

    /*
     * If there are any extended resources in a res record, free them here.
     * (There were in previous versions of the code, so I just left this
     * here when I removed those parts. If I really cared about cleaning
     * this up, I could replace this with free().)
     */

    free(res);

    return;
}

static Reservation  ResHead = NULL;

static BWLBoolean
ResRemove(
        Reservation res
        )
{
    Reservation *rptr = &ResHead;

    while(*rptr && (*rptr != res))
        rptr = &(*rptr)->next;

    if(!*rptr)
        return False;

    *rptr = (*rptr)->next;

    return True;
}

static void
DeleteReservation(
        ChldState   cstate
        )
{
    if(!cstate->res)
        return;

    ResRemove(cstate->res);
    FreeReservation(cstate->res);
    cstate->res = NULL;

    return;
}

static BWLBoolean
ChldReservationDemand(
        ChldState   cstate,
        BWLSID      sid,
        BWLNum64    rtime,
        BWLNum64    ftime,
        BWLNum64    ltime,
        uint32_t   duration,
        BWLNum64    rtttime,
        BWLNum64    *restime,
        uint16_t   *port,
        int         *err)
{
    BWLContext      ctx = cstate->policy->ctx;
    BWLTimeStamp    currtime;
    Reservation     res;
    Reservation     *rptr;
    BWLDLimitT      hsecs;
    BWLNum64        dtime;    /* duration with fuzz applied */
    BWLNum64        minstart;

    *err = 1;

    if(!BWLDGetFixedLimit(cstate->node,BWLDLimEventHorizon,&hsecs))
        return False;

    if(cstate->res){
        if(memcmp(sid,cstate->res->sid,sizeof(sid)))
            return False;
        /*
         * Remove cstate->res from pending_queue
         */
        if(!ResRemove(cstate->res))
            return False;
        cstate->res->port = *port;
    }
    else if(!AllocReservation(cstate,sid,port)){
        /*
         * Alloc failed.
         */
        return False;
    }
    /*
     * Initialize fields
     */
    res = cstate->res;

    /*
     * At this point cstate->res is ready to be inserted into
     * the pending test queue.
     */

    if(!BWLGetTimeStamp(ctx,&currtime)){
        I2ErrLogP(errhand, errno, "BWLGetTimeOfDay: %M");
        FreeReservation(cstate->res);
        cstate->res = NULL;
        return False;
    }

    /*
     * Determine earliest time the test can happen.
     * This is the max of the earliest time the deamon is willing
     * to have a test and the requested time.
     * The algorithm being used to determine the "earliest time
     * the daemon" is willing to have a test is:
     *
     *    2 X (rtt(client) + fuzztime(otherserver))
     *
     * The actual message time is:
     *    server            client
     *    request response ->
     *            <-    start sessions
     *    start response    ->
     *    (This is only 1.5 rtt, but it is potentially 2 rtt's to the
     *    other server for a request/response and a start/response
     *     and that is the value "fuzztime" represents. So, a possible
     *    extra delay of .5 rtt is acceptible.)
     *
     * The reservation is defined by the following vars:
     * res->restime == time of reservation
     * res->start == fuzz applied to beginning of that
     * res->end == fuzz applied to res->restime + duration
     * The time period from res->start to res->end is completely
     * allocated to this test.
     */
    res->start = BWLNum64Sub(rtime,ftime);
#if    NOT
    I2ErrLog(errhand,"ResReq: %24.10f, Fuzz: %24.10f",
            BWLNum64ToDouble(rtime),
            BWLNum64ToDouble(ftime));
    I2ErrLog(errhand,"Current: %24.10f, Start: %24.10f",
            BWLNum64ToDouble(currtime.tstamp),
            BWLNum64ToDouble(res->start));
#endif
    minstart =BWLNum64Add(currtime.tstamp,
            BWLNum64Mult(
                BWLNum64Add(rtttime,ftime),
                BWLULongToNum64(2)));
    /*
     * If the start time is less than the minimum start time, then
     * reset the start time to one second past the minimum start time.
     * minstart should take into account rtt times. The one second is
     * simply a small buffer space so that rounding error and random
     * extra delay to the other server will still allow a reservation.
     */
    if(BWLNum64Cmp(res->start,minstart) < 0){
        res->start = BWLNum64Add(minstart,BWLULongToNum64(1));
    }
    res->restime = BWLNum64Add(res->start,ftime);

#if    NOT
    I2ErrLog(errhand,"ResCompute: %24.10f, NewStart: %24.10f",
            BWLNum64ToDouble(res->restime),
            BWLNum64ToDouble(res->start));
#endif
    dtime = BWLNum64Add(BWLULongToNum64(duration),ftime);
    res->end = BWLNum64Add(res->restime,dtime);
    res->fuzz = ftime;
    res->duration = duration;

    /*
     * Determine the latest time the test could happen.
     * (Min of the EventHorizon of the daemon and the latest time from
     * the request.)
     */
    if(hsecs){
        ltime = BWLNum64Min(ltime,BWLNum64Add(currtime.tstamp,
                    BWLULongToNum64(hsecs)));
    }

    /*
     * Open slot too late
     */
    if(ltime && (BWLNum64Cmp(res->restime,ltime) > 0)){
        *restime = res->restime;
        goto denied;
    }

    /********************************
     * Find an open slot        *
     ********************************/
    rptr = &ResHead;
    while(*rptr){
        Reservation    tres;

        tres = *rptr;

        /*
         * If the current res->end is before the current rptr,
         * insert here!
         */
        if(BWLNum64Cmp(res->end,tres->start) < 0)
            break;

        /*
         * If the current res->start is after the current rptr,
         * go to the next node and see if it can be inserted before
         * it.
         */
        if(BWLNum64Cmp(res->start,tres->end) > 0){
            goto next_slot;
        }

        /*
         * Adjust res->start,res->restime,res->end to be just past
         * the current reservation.
         */
        /*
         * new start is the expected endtime + Max of the two
         * fuzz factors.
         */
        res->start = BWLNum64Add(tres->restime,
                BWLULongToNum64(tres->duration));
        res->start = BWLNum64Add(res->start,
                BWLNum64Max(res->fuzz,tres->fuzz));

        res->restime = BWLNum64Add(res->start,res->fuzz);
        res->end = BWLNum64Add(res->restime,dtime);

        /*
         * Open slot too late
         */
        if(ltime && (BWLNum64Cmp(res->restime,ltime) > 0))
            goto denied;

next_slot:
        rptr = &(*rptr)->next;
    }

    /*
     * rptr now points to the position res needs to be inserted.
     */
    res->next = *rptr;
    *rptr = res;

    *restime = res->restime;
    *port = res->port;

    return True;

denied:
    *err = 0;
    I2ErrLogP(errhand,errno,
            "Unable to find reservation before \"last time\"");
    DeleteReservation(cstate);
    return False;
}

static BWLBoolean
ChldReservationComplete(
        ChldState       cstate,
        BWLSID          sid,
        BWLAcceptType   aval    __attribute__((unused)),
        int             *err)
{
    *err = 1;

    if(!cstate->res || memcmp(sid,cstate->res->sid,sizeof(sid)))
        return False;

    DeleteReservation(cstate);

    return True;
}

static ChldState
AllocChldState(
        BWLDPolicy  policy,
        pid_t       pid,
        int         fd
        )
{
    ChldState   cstate = calloc(1,sizeof(*cstate));
    I2Datum     k,v;

    if(!cstate){
        BWLError(policy->ctx,BWLErrFATAL,ENOMEM,"malloc(): %M");
        return NULL;
    }

    cstate->policy = policy;
    cstate->pid = pid;
    cstate->fd = fd;

    /*
     * Add cstate into the hash's.
     */
    v.dptr = (void*)cstate;
    v.dsize = sizeof(*cstate);

    /*
     * add cstate to the pidtable hash
     */
    k.dptr = NULL;
    k.dsize = pid;
    if(I2HashStore(pidtable,k,v) != 0){
        free(cstate);
        return NULL;
    }

    /*
     * add cstate to the fdtable hash
     */
    k.dsize = fd;
    if(I2HashStore(fdtable,k,v) != 0){
        k.dsize = pid;
        I2HashDelete(pidtable,k);
        free(cstate);
        return NULL;
    }

    return cstate;
}

static void
FreeChldState(
        ChldState   cstate,
        fd_set      *readfds
        )
{
    I2Datum k;

    k.dptr = NULL;

    if(cstate->fd >= 0){

        while((close(cstate->fd) < 0) && (errno == EINTR));
        FD_CLR(cstate->fd, readfds);

        k.dsize = cstate->fd;
        if(I2HashDelete(fdtable,k) != 0){
            BWLError(cstate->policy->ctx,BWLErrWARNING,
                    BWLErrUNKNOWN,
                    "fd(%d) not in fdtable!?!",cstate->fd);
        }
    }

    k.dsize = cstate->pid;
    if(I2HashDelete(pidtable,k) != 0){
        BWLError(cstate->policy->ctx,BWLErrWARNING,BWLErrUNKNOWN,
                "pid(%d) not in pidtable!?!",cstate->pid);
    }

    /*
     * TODO: Release resources here if there are any left?
     * (should not need to..., but perhaps I should check and
     * and report errors if there are still any allocated?)
     */

    DeleteReservation(cstate);

    free(cstate);

    return;
}

static void
ReapChildren(
        int     *maxfd,
        fd_set  *readfds
        )
{
    int         status;
    pid_t       child;
    I2Datum     key;
    I2Datum     val;
    ChldState   cstate;

    if(!ipfd_chld)
        return;

    key.dptr = NULL;
    while ( (child = waitpid(-1, &status, WNOHANG)) > 0){
        key.dsize = child;
        if(!I2HashFetch(pidtable,key,&val)){
            BWLError(cstate->policy->ctx,BWLErrWARNING,
                    BWLErrUNKNOWN,
                    "pid(%d) not in pidtable!?!",child);
        }
        cstate = val.dptr;

        /*
         * Let main loop know maxfd needs to be recomputed.
         */
        if(cstate->fd == *maxfd)
            *maxfd = -1;

        FreeChldState(cstate,readfds);
    }


    ipfd_chld = 0;
}

struct CleanPipeArgRec{
    int     *maxfd;
    fd_set  *avail;
    fd_set  *readfds;
    int     nready;
};

static I2Boolean
CheckFD(
        I2Datum fdkey       __attribute__((unused)),
        I2Datum fdval,
        void    *app_data
       )
{
    struct CleanPipeArgRec  *arg = (struct CleanPipeArgRec *)app_data;
    ChldState               cstate = fdval.dptr;
    int                     err=1;

    /*
     * If this fd is not ready, return.
     */
    if(!FD_ISSET(cstate->fd,arg->avail))
        return True;

    /*
     * This fd needs processing - reduce the "ready" count.
     */
    arg->nready--;

    /*
     * child initialization - first message.
     * Get classname and find policy node for that class.
     */
    if(!cstate->node){
        cstate->node = BWLDReadClass(cstate->policy,cstate->fd,
                &ipfd_exit,&err);
    }
    else{
        BWLDMesgT       query;
        BWLDMesgT       resp;
        BWLDLimRec      lim;

        BWLSID          sid;
        BWLNum64        rtime,ftime,ltime,restime,rtttime;
        uint32_t       duration;
        uint16_t       port;
        BWLAcceptType   aval;

        switch(BWLDReadReqType(cstate->fd,&ipfd_exit,&err)){
            case BWLDMESGRESOURCE:

                /* read child request for resources */
                if(!BWLDReadQuery(cstate->fd,&ipfd_exit,&query,
                            &lim,&err)){
                    goto done;
                }

                /*
                 * parse tree for resource request/release
                 */
                resp = BWLDResourceDemand(cstate->node,query,
                        lim) ?
                    BWLDMESGOK : BWLDMESGDENIED;
                /*
                 * Send response
                 */
                err = BWLDSendResponse(cstate->fd,&ipfd_exit,
                        resp);
                break;
            case BWLDMESGRESERVATION:

                /* read child request for reservation */
                if(!BWLDReadReservationQuery(cstate->fd,
                            &ipfd_exit,sid,
                            &rtime,&ftime,&ltime,
                            &duration,&rtttime,
                            &port,&err)){
                    goto done;
                }

                /*
                 * Look for open slot to run test
                 */
                if(ChldReservationDemand(cstate,
                            sid,rtime,ftime,ltime,
                            duration,rtttime,
                            &restime,&port,&err)){
                    resp = BWLDMESGOK;
                }
                else if(err){
                    goto done;
                }
                else{
                    resp = BWLDMESGDENIED;
                }

                /*
                 * Send response
                 */
                err = BWLDSendReservationResponse(cstate->fd,
                        &ipfd_exit,resp,restime,port);
                break;
            case BWLDMESGCOMPLETE:

                if(!BWLDReadTestComplete(cstate->fd,&ipfd_exit,
                            sid,&aval,&err)){
                    goto done;
                }

                /*
                 * Mark reservation complete (free memory?)
                 */
                if(ChldReservationComplete(cstate,sid,aval,
                            &err)){
                    resp = BWLDMESGOK;
                }
                else if(err){
                    goto done;
                }
                else{
                    resp = BWLDMESGDENIED;
                }

                /*
                 * Send response
                 */
                err = BWLDSendResponse(cstate->fd,&ipfd_exit,
                        resp);
                break;
            default:
                break;
        }

    }

done:
    if(err){
        BWLError(cstate->policy->ctx,BWLErrWARNING,BWLErrUNKNOWN,
                "Invalid message from child pid=%d",cstate->pid);
        (void)kill(cstate->pid,SIGTERM);
    }

    /*
     * Return true if there are more fd's to process.
     */
    return (arg->nready > 0);
}

/*
 * avail contains the fd_set of fd's that are currently readable, readfds is
 * the set of all fd's that the server needs to pay attention to.
 * maxfd is the largest of those.
 */
static void
CleanPipes(
        fd_set  *avail,
        int     *maxfd,
        fd_set  *readfds,
        int     nready
        )
{
    struct CleanPipeArgRec  cpargs;

    cpargs.avail = avail;
    cpargs.maxfd = maxfd;
    cpargs.readfds = readfds;
    cpargs.nready = nready;

    I2HashIterate(fdtable,CheckFD,&cpargs);

    return;
}

static I2Boolean
ClosePipes(
        I2Datum key,
        I2Datum value,
        void    *app_data   __attribute__((unused))
        )
{
    ChldState   cstate = value.dptr;

    while((close(cstate->fd) < 0) && (errno == EINTR));
    if(I2HashDelete(fdtable,key) != 0){
        BWLError(cstate->policy->ctx,BWLErrWARNING,BWLErrUNKNOWN,
                "fd(%d) not in fdtable!?!",cstate->fd);
    }
    cstate->fd = -1;

    return True;
}

/*
 * This function needs to create a new child process with a pipe to
 * communicate with it. It needs to add the new pipefd into the readfds,
 * and update maxfd if the new pipefd is greater than the current max.
 */
static void
NewConnection(
        BWLDPolicy  policy,
        BWLAddr     listenaddr,
        int         *maxfd,
        fd_set      *readfds
        )
{
    int                     connfd;
    struct sockaddr_storage sbuff;
    socklen_t               sbufflen;
    int                     new_pipe[2];
    pid_t                   pid;
    BWLSessionMode          mode = opts.auth_mode;
    int                     listenfd = BWLAddrFD(listenaddr);
    BWLControl              cntrl=NULL;
    BWLErrSeverity          out;

ACCEPT:
    sbufflen = sizeof(sbuff);
    connfd = accept(listenfd, (struct sockaddr *)&sbuff, &sbufflen);
    if (connfd < 0){
        switch(errno){
            case EINTR:
                /*
                 * Go ahead and reap since it could make
                 * more free connections.
                 */
                if(ipfd_exit){
                    return;
                }
                ReapChildren(maxfd,readfds);
                goto ACCEPT;
                break;
            case ECONNABORTED:
                return;
                break;
            default:
                BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
                        "accept(): %M");
                return;
                break;
        }
    }

    if (socketpair(AF_UNIX,SOCK_STREAM,0,new_pipe) < 0){
        BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,"socketpair(): %M");
        (void)close(connfd);
        return;
    }

    pid = fork();

    /* fork error */
    if (pid < 0){
        BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,"fork(): %M");
        (void)close(new_pipe[0]);
        (void)close(new_pipe[1]);
        (void)close(connfd);
        return;
    }

    /* Parent */
    if (pid > 0){
        ChldState    chld;

        /*
         * If close is interupted, continue to try and close,
         * otherwise, ignore the error.
         */
        while((close(new_pipe[1]) < 0) && (errno == EINTR));
        while((close(connfd) < 0) && (errno == EINTR));

        if(!(chld = AllocChldState(policy,pid,new_pipe[0]))){
            (void)close(new_pipe[0]);
            (void)kill(pid,SIGKILL);
            return;
        }

        FD_SET(chld->fd, readfds);
        if((*maxfd > -1) && (chld->fd > *maxfd))
            *maxfd = chld->fd;
    }
    /* Child */
    else{
        struct itimerval    itval;
        BWLRequestType        msgtype=BWLReqInvalid;

#ifndef    NDEBUG
        int        childwait;

        if((childwait = opts.childwait)){
            BWLError(policy->ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "Waiting for Debugger.");
            /* busy loop to wait for debug-attach */
            while(childwait);

            /*
             * set BWLChildWait if you want to attach
             * to them... (by resetting childwait back to non-zero)
             */
            if(childwait && !BWLContextConfigSet(policy->ctx,
                        BWLChildWait,(void*)childwait)){
                BWLError(policy->ctx,BWLErrWARNING,
                        BWLErrUNKNOWN,
                        "BWLContextConfigSet(): "
                        "Unable to set BWLChildWait?!");
            }
        }
#endif
        /*
         * TODO: Close all open file descriptors not needed by this
         * child.
         */
        while((close(new_pipe[0]) < 0) && (errno == EINTR));
        while((close(listenfd) < 0) && (errno == EINTR));
        I2HashIterate(fdtable,ClosePipes,NULL);

        /*
         * check/set signal vars.
         */
        if(ipfd_exit){
            exit(0);
        }
        ipfd_intr = 0;

        /*
         * Initialize itimer struct. The it_value.tv_sec will be
         * set to interrupt socket i/o if the message is not received
         * within the timeout as described by owdp draft section 4
         * (BWLIB-Control).
         */
        memset(&itval,0,sizeof(itval));

        /*
         * save the pipe fd in the policy record for the hooks to
         * pick it up.
         */
        policy->fd = new_pipe[1];

        /*
         * If the daemon is configured to do open_mode, check if
         * there is an open_mode limit defined for the given
         * address.
         */
        if((mode & BWL_MODE_OPEN) &&
                !BWLDAllowOpenMode(policy,
                    (struct sockaddr *)&sbuff,&out)){
            if(out != BWLErrOK){
                exit(out);
            }
            mode &= ~BWL_MODE_OPEN;
        }

        ipfd_intr = 0;
        itval.it_value.tv_sec = opts.controltimeout;
        if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
            I2ErrLog(errhand,"setitimer(): %M");
            exit(BWLErrFATAL);
        }
        cntrl = BWLControlAccept(policy->ctx,connfd,
                (struct sockaddr *)&sbuff,sbufflen,
                mode,uptime,&ipfd_intr,&out);
        /*
         * session not accepted.
         */
        if(!cntrl){
            exit(out);    
        }

        /*
         * Process all requests - return when complete.
         */
        while(1){
            BWLErrSeverity    rc;

            rc = BWLErrOK;

            /*
             * reset signal vars
             * TODO: If there is a pending reservation,
             * timer should be reduced to:
             *     MIN(time-util-start,reserve-timeout)
             */
            ipfd_intr = ipfd_alrm = ipfd_chld = 0;
            itval.it_value.tv_sec = opts.controltimeout;
            if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
                I2ErrLog(errhand,"setitimer(): %M");
                goto done;
            }

            msgtype = BWLReadRequestType(cntrl,&ipfd_intr);

            switch (msgtype){

                case BWLReqTest:
                    rc = BWLProcessTestRequest(cntrl,&ipfd_intr);
                    break;

                case BWLReqTime:
                    rc = BWLProcessTimeRequest(cntrl,&ipfd_intr);
                    break;

                case BWLReqStartSession:
                    rc = BWLProcessStartSession(cntrl,&ipfd_intr);
                    if(rc < BWLErrOK){
                        break;
                    }
                    /*
                     * Test session started - unset timer - wait
                     * until all sessions are complete, then
                     * reset the timer and wait for stopsessions
                     * to complete.
                     */
                    ipfd_intr = 0;
                    itval.it_value.tv_sec = 0;
                    if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
                        I2ErrLog(errhand,"setitimer(): %M");
                        goto done;
                    }
                    if(ipfd_exit)
                        goto done;

                    /*
                     * This loop is here so StopSessionWait
                     * can be told to return on ipfd_intr. In
                     * other words, SIGCHLD will cause it to
                     * return. This is done so the alrm timer
                     * can be set before the StopSessions
                     * command is sent in the case where the
                     * child working exits before the StopSessions
                     * messages exchange.
                     */
                    while(BWLSessionsActive(cntrl,NULL)){
                        int    wstate;

                        rc = BWLErrOK;
                        ipfd_intr = 0;
                        wstate = BWLStopSessionWait(cntrl,NULL,
                                &ipfd_intr,NULL,&rc);
                        if(ipfd_exit || (wstate < 0)){
                            goto done;
                        }
                        if(wstate == 0){
                            goto nextreq;
                        }
                    }
                    /*
                     * Sessions are complete, but StopSession
                     * message has not been exchanged - set the
                     * timer and trade StopSession messages
                     */
                    ipfd_intr = 0;
                    itval.it_value.tv_sec = opts.controltimeout;
                    if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
                        I2ErrLog(errhand,"setitimer(): %M");
                        goto done;
                    }
                    rc = BWLStopSession(cntrl,&ipfd_intr,NULL);

                    break;

                case BWLReqSockClose:
                default:
                    rc = BWLErrFATAL;
                    break;
            }
nextreq:
            if(rc < BWLErrWARNING){
                break;
            }

        }

done:
        BWLControlClose(cntrl);

        if(ipfd_exit){
            exit(0);
        }

        /*
         * Normal socket close
         */
        if(msgtype == BWLReqSockClose){
            exit(0);
        }

        I2ErrLog(errhand,"Control session terminated abnormally...");

        exit(1);
    }
}

/*
 * hash functions...
 * I cheat - I use the "dsize" part of the datum for the key data since
 * pid and fd are both integers.
 */
static int
intcmp(
        const I2Datum   x,
        const I2Datum   y
      )
{
    return(x.dsize != y.dsize);
}

static uint32_t
inthash(
        I2Datum    key
       )
{
    return (uint32_t)key.dsize;
}

static I2Boolean
FindMaxFD(
        I2Datum key,
        I2Datum value       __attribute__((unused)),
        void    *app_data
        )
{
    int *maxfd = (int *)app_data;

    if((*maxfd < 0) || ((int)key.dsize > *maxfd)){
        *maxfd = (int)key.dsize;
    }

    return True;
}

static void
LoadConfig(
        char    **lbuf,
        size_t  *lbuf_max
        )
{
    FILE    *conf;
    char    conf_file[MAXPATHLEN+1];
    char    keybuf[MAXPATHLEN],valbuf[MAXPATHLEN];
    char    *key = keybuf;
    char    *val = valbuf;
    int     rc=0;

    conf_file[0] = '\0';

    rc = strlen(BWCTLD_CONF_FILE);
    if(rc > MAXPATHLEN){
        fprintf(stderr,"strlen(BWCTLD_CONF_FILE) > MAXPATHLEN\n");
        exit(1);
    }
    if(opts.confdir){
        rc += strlen(opts.confdir) + strlen(BWL_PATH_SEPARATOR);
        if(rc > MAXPATHLEN){
            fprintf(stderr,"Path to %s > MAXPATHLEN\n",
                    BWCTLD_CONF_FILE);
            exit(1);
        }
        strcpy(conf_file, opts.confdir);
        strcat(conf_file, BWL_PATH_SEPARATOR);
    }
    strcat(conf_file, BWCTLD_CONF_FILE);

    if(!(conf = fopen(conf_file, "r"))){
        if(opts.confdir){
            fprintf(stderr,"Unable to open %s: %s\n",conf_file,
                    strerror(errno));
            exit(1);
        }
        return;
    }

    while((rc = I2ReadConfVar(conf,rc,key,val,MAXPATHLEN,lbuf,lbuf_max))
            > 0){

        /* syslog facility */
        if(!strncasecmp(key,"facility",9)){
            int fac = I2ErrLogSyslogFacility(val);
            if(fac == -1){
                fprintf(stderr,
                        "Invalid -e: Syslog facility \"%s\" unknown\n",
                        val);
                rc = -rc;
                break;
            }
            syslogattr.facility = fac;
        }
        else if(!strncasecmp(key,"priority",9)){
            int prio = I2ErrLogSyslogPriority(val);
            if(prio == -1){
                fprintf(stderr,
                        "Invalid syslog priority \"%s\" unknown\n",
                        val);
                rc = -rc;
                break;
            }
            syslogattr.priority = prio;
        }
        else if(!strncasecmp(key,"rootfolly",10)){
            opts.allowRoot = True;
        }
        else if(!strncasecmp(key,"accesspriority",15)){
            opts.access_prio = I2ErrLogSyslogPriority(val);
            if(opts.access_prio == -1){
                fprintf(stderr,
                        "Invalid syslog priority \"%s\" unknown\n",
                        val);
                rc = -rc;
                break;
            }
        }
        else if(!strncasecmp(key,"loglocation",12)){
            syslogattr.line_info |= I2FILE|I2LINE;
        }
        else if(!strncasecmp(key,"iperfcmd",9)){
            if(!(opts.iperfcmd = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"iperfport",10)){
            char        *hpstr = NULL;
            uint16_t    lport,hport;
            char        *end=NULL;
            uint32_t    tlng;


            if( (hpstr = strchr(val,'-'))){
                *hpstr++ = '\0';
            }
            errno = 0;
            tlng = strtoul(val,&end,10);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtoul(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            lport = (uint16_t)tlng;
            if(lport != tlng){
                rc=-rc;
                break;
            }

            if(hpstr){
                errno = 0;
                tlng = strtoul(hpstr,&end,10);
                if((end == hpstr) || (errno == ERANGE)){
                    fprintf(stderr,"strtoul(): %s\n",
                            strerror(errno));
                    rc=-rc;
                    break;
                }
                hport = (uint16_t)tlng;
                if(hport != tlng){
                    rc=-rc;
                    break;
                }
            }
            else{
                hport = lport;
            }

            if(hport < lport){
                fprintf(stderr,
                        "iperfport: invalid range specified");
                rc=-rc;
                break;
            }

            opts.port_range_len = hport-lport+1;
            if(!(opts.iperfports = calloc(sizeof(uint16_t),
                            opts.port_range_len))){
                fprintf(stderr,"calloc(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }

            for(tlng=0;tlng<opts.port_range_len;tlng++){
                opts.iperfports[tlng] = tlng + lport;
            }
        }
        else if(!strncasecmp(key,"peerports",10)){
            if(!BWLParsePorts(val,&peerports,&opts.peerports,NULL,stderr)){
                fprintf(stderr,"Invalid peerports range specified.");
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"datadir",8)){
            if(!(opts.datadir = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"user",5)){
            if(!(opts.user = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"group",6)){
            if(!(opts.group = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"verbose",8)){
            opts.verbose = True;
        }
        else if(!strncasecmp(key,"authmode",9)){
            if(!(opts.authmode = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"srcnode",8)){
            if(!(opts.srcnode = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"vardir",7)){
            if(!(opts.vardir = strdup(val))) {
                fprintf(stderr,"strdup(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
        }
        else if(!strncasecmp(key,"dieby",6)){
            char        *end=NULL;
            uint32_t    tlng;

            errno = 0;
            tlng = strtoul(val,&end,10);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtoul(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            opts.dieby = tlng;
        }
        else if(!strncasecmp(key,"controltimeout",15)){
            char        *end=NULL;
            uint32_t    tlng;

            errno = 0;
            tlng = strtoul(val,&end,10);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtoul(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            opts.controltimeout = tlng;
        }
        else if(!strncasecmp(key,"bottleneckcapacity",19)){
            BWLDLimitT    bneck;
            if(I2StrToNum(&bneck,val)){
                fprintf(stderr,"Invalid value: %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            opts.bottleneckcapacity = (uint64_t)bneck;
        }
        else if(!strncasecmp(key,"syncfuzz",9)){
            char    *end=NULL;
            double    tdbl;

            errno = 0;
            tdbl = strtod(val,&end);
            if((end == val) || (errno == ERANGE)){
                fprintf(stderr,"strtod(): %s\n",
                        strerror(errno));
                rc=-rc;
                break;
            }
            if(tdbl < 0.0){
                fprintf(stderr,"Invalid value syncfuzz: %f\n",
                        tdbl);
                rc=-rc;
                break;
            }
            opts.syncfuzz = tdbl;
        }
        else{
            fprintf(stderr,"Unknown key=%s\n",key);
            rc = -rc;
            break;
        }
    }

    if(rc < 0){
        fprintf(stderr,"%s:%d Problem parsing config file\n",
                conf_file,-rc);
        exit(1);
    }

    return;
}

int
main(int argc, char *argv[])
{
    char                *progname;
    BWLErrSeverity      out = BWLErrFATAL;
    char                pid_file[MAXPATHLEN];
    char                info_file[MAXPATHLEN];

    fd_set              readfds;
    int                 maxfd;    /* max fd in readfds */
    BWLContext          ctx;
    BWLDPolicy          policy;
    BWLAddr             listenaddr = NULL;
    int                 listenfd;
    int                 rc;
    I2Datum             data;
    struct flock        flk;
    int                 pid_fd;
    FILE                *pid_fp;
    FILE                *info_fp;
    BWLTimeStamp        currtime;    
    int                 ch;
    uid_t               setuser=0;
    gid_t               setgroup=0;
    char                *lbuf=NULL;
    size_t              lbuf_max=0;

    struct sigaction    ignact;
    struct sigaction    setact;
    sigset_t            sigs;

#ifndef NDEBUG
    char                *optstring = "hvc:d:fR:a:S:e:ZU:G:w";
#else    
    char                *optstring = "hvc:d:fR:a:S:e:ZU:G:";
#endif

    /*
     * Start an error loggin session for reporting errors to the
     * standard error
     */
    if((progname = strrchr(argv[0],'/'))){
        progname++;
    }else{
        progname = *argv;
    }
    syslogattr.ident = progname;
    syslogattr.logopt = LOG_PID;
    syslogattr.facility = LOG_DAEMON;
    syslogattr.priority = LOG_ERR;
    syslogattr.line_info = I2MSG;

    /* Set up options defaults */
    memset(&opts,0,sizeof(opts));
    opts.access_prio = -1;
    opts.daemon = 1;
    opts.dieby = 30;
    opts.controltimeout = 7200;

    if(!getcwd(opts.cwd,sizeof(opts.cwd))){
        perror("getcwd()");
        exit(1);
    }

    /*
     * Fetch config file option if present
     */
    opterr = 0;
    while((ch = getopt(argc, argv, optstring)) != -1){
        switch (ch){
            case 'c':    /* -c "Config directory" */
                if (!(opts.confdir = strdup(optarg))) {
                    /* eh isn't setup yet...*/
                    perror("strdup()");
                    exit(1);
                }
                break;
            default:
                break;
        }
    }
    opterr = optreset = optind = 1;

    /*
     * Load Config file.
     * lbuf/lbuf_max keep track of a dynamically grown "line" buffer.
     * (It is grown using realloc.)
     * This will be used throughout all the config file reading and
     * should be free'd once all config files have been read.
     */
    LoadConfig(&lbuf,&lbuf_max);

    /*
     * Read cmdline options that effect syslog so the rest of cmdline
     * processing can be reported via syslog.
     */
    opterr = 0;
    while((ch = getopt(argc, argv, optstring)) != -1){
        switch (ch){
            int fac;
            case 'e':    /* -e "syslog err facility" */
                fac = I2ErrLogSyslogFacility(optarg);
                if(fac == -1){
                    fprintf(stderr,
                            "Invalid -e: Syslog facility \"%s\" unknown\n",
                            optarg);
                    exit(1);
                }
                syslogattr.facility = fac;
                break;
            case 'Z':
                opts.daemon = 0;
                break;
            default:
                break;
        }
    }
    opterr = optreset = optind = 1;

    /*
     * Always use LOG_PERROR if it exists
     * If daemonizing, stderr will be closed, and this hurts nothing.
     * And... commandline reporting is good until after the fork.
     */
    syslogattr.logopt |= LOG_PERROR;
    errhand = I2ErrOpen(progname, I2ErrLogSyslog, &syslogattr, NULL, NULL);
    if(! errhand) {
        fprintf(stderr, "%s : Couldn't init error module\n", progname);
        exit(1);
    }

    /*
     * Now deal with "all" cmdline options.
     */
    while ((ch = getopt(argc, argv, optstring)) != -1){

        switch (ch) {
            /* Connection options. */
            case 'v':    /* -v "verbose" */
                opts.verbose = True;
                break;
            case 'd':    /* -d "data directory" */
                if (!(opts.datadir = strdup(optarg))) {
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'f':
                opts.allowRoot = True;
                break;
            case 'a':    /* -a "authmode" */
                if (!(opts.authmode = strdup(optarg))) {
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'S':  /* -S "src addr" */
                if (!(opts.srcnode = strdup(optarg))) {
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'U':
                if(!(opts.user = strdup(optarg))){
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'G':
                if(!(opts.group = strdup(optarg))){
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'R':    /* -R "var/run directory" */
                if (!(opts.vardir = strdup(optarg))) {
                    I2ErrLog(errhand,"strdup(): %M");
                    exit(1);
                }
                break;
            case 'c':
            case 'e':
            case 'Z':
                break;
#ifndef NDEBUG
            case 'w':
                opts.childwait = True;
                break;
#endif
            case 'h':
            case '?':
            default:
                usage(progname, "");
                exit(0);
                /* UNREACHED */ 
        }
    }
    argc -= optind;
    argv += optind;

    if (argc) {
        usage(progname, "");
        exit(1);
    }

    if(!opts.vardir)
        opts.vardir = opts.cwd;
    if(!opts.confdir)
        opts.confdir = opts.cwd;
    if(!opts.datadir)
        opts.datadir = opts.cwd;
    if(!opts.iperfports){
        opts.def_port = 5001;
        opts.iperfports = &opts.def_port;
        opts.port_range_len = 1;
    }

    /*  Get exclusive lock for pid file. */
    strcpy(pid_file, opts.vardir);
    strcat(pid_file, BWL_PATH_SEPARATOR);
    strcat(pid_file, "bwctld.pid");
    if ((pid_fd = open(pid_file, O_RDWR|O_CREAT,
                    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) < 0) {
        I2ErrLog(errhand, "open(%s): %M", pid_file);
        exit(1);
    }
    flk.l_start = 0;
    flk.l_len = 0;
    flk.l_type = F_WRLCK;
    flk.l_whence = SEEK_SET; 
    while((rc=fcntl(pid_fd, F_SETLK, &flk)) < 0 && errno == EINTR);
    if(rc < 0){
        I2ErrLog(errhand,"Unable to lock file %s: %M", pid_file);
        exit(1);
    }
    if ((pid_fp = fdopen(pid_fd, "wr")) == NULL) {
        I2ErrLog(errhand, "fdopen(): %M");
        exit(1);
    }

    /*
     * Initialize the context. (Set the error handler to the app defined
     * one.)
     */
    if(!(ctx = BWLContextCreate(errhand))){
        exit(1);
    }

    if(opts.access_prio != -1){
        BWLContextSetAccessLogPriority(ctx,opts.access_prio);
    }

    if((opts.syncfuzz != 0.0) &&
            !BWLContextConfigSet(ctx,BWLSyncFuzz,
                (void*)&opts.syncfuzz)){
        I2ErrLog(errhand,"Unable to set SyncFuzz.");
        exit(1);
    }

    if((opts.peerports) &&
            !BWLContextConfigSet(ctx,BWLPeerPortRange,
                (void*)opts.peerports)){
        I2ErrLog(errhand,"Unable to set PeerPorts.");
        exit(1);
    }

    /*
     * Install policy for "ctx" - and return policy record.
     */
    if(!(policy = BWLDPolicyInstall(ctx,opts.datadir,opts.confdir,
                    opts.iperfcmd,
                    &opts.bottleneckcapacity,
                    &ipfd_exit,
                    &lbuf,&lbuf_max))){
        I2ErrLog(errhand, "PolicyInit failed. Exiting...");
        exit(1);
    };

    /*
     * Done with the line buffer. (reset to 0 for consistancy.)
     */
    if(lbuf){
        free(lbuf);
    }
    lbuf = NULL;
    lbuf_max = 0;

    /*
     * If running as root warn if the -U/-G flags not set.
     */
    if(!geteuid()){
        struct passwd   *pw;
        struct group    *gr;

        /*
         * Validate user option.
         */
        if(!opts.user){
            /* no-op */
            ;
        }
        else if((pw = getpwnam(opts.user))){
            setuser = pw->pw_uid;
        }
        else if(opts.user[0] == '-'){
            setuser = strtoul(&opts.user[1],NULL,10);
            if(errno || !getpwuid(setuser)){
                I2ErrLog(errhand,"Invalid user/-U option: %s",
                    opts.user);
                exit(1);
            }
        }

        if(!setuser && !opts.allowRoot){
            I2ErrLog(errhand,"Running bwctld as root is folly!");
            I2ErrLog(errhand,
                    "Use the -U option! (or allow root with the -f option)");
            exit(1);
        }


        /*
         * Validate group option.
         */
        if(opts.group){
            if((gr = getgrnam(opts.group))){
                setgroup = gr->gr_gid;
            }
            else if(opts.group[0] == '-'){
                setgroup = strtoul(&opts.group[1],NULL,10);
                if(errno || !getgrgid(setgroup))
                    setgroup = 0;
            }
            if(!setgroup){
                I2ErrLog(errhand,"Invalid user/-G option: %s",
                        opts.group);
                exit(1);
            }
        }

        /*
         * Only setting effective id for now. This will catch
         * errors, and will still allow the rename of the
         * pid/info file later.
         */
        if(setgroup && (setegid(setgroup) != 0)){
            I2ErrLog(errhand,"Unable to setgid to \"%s\": %M",
                    opts.group);
            exit(1);
        }
        if(setuser && seteuid(setuser) != 0){
            I2ErrLog(errhand,"Unable to setuid to \"%s\": %M",
                    opts.user);
            exit(1);
        }

    }

    /*
     * Setup the "default_mode".
     */
    if(opts.authmode){
        char    *s = opts.authmode;
        opts.auth_mode = 0;
        while(*s != '\0'){
            switch(toupper(*s)){
                case 'O':
                    opts.auth_mode |= BWL_MODE_OPEN;
                    break;
                case 'A':
                    opts.auth_mode |= BWL_MODE_AUTHENTICATED;
                    break;
                case 'E':
                    opts.auth_mode |= BWL_MODE_ENCRYPTED;
                    break;
                default:
                    I2ErrLogP(errhand,EINVAL,
                            "Invalid -authmode %c",*s);
                    usage(progname,NULL);
                    exit(1);
            }
            s++;
        }
    }
    else{
        /*
         * Default to all modes.
         */
        opts.auth_mode = BWL_MODE_OPEN|BWL_MODE_AUTHENTICATED|
            BWL_MODE_ENCRYPTED;
    }

    /*
     * TODO: a config test for this would probably be cleaner...
     */
    {    /* ensure intcmp will work */
        size_t    psize = sizeof(pid_t);
        assert(psize<=sizeof(data.dsize));
    }

    pidtable = I2HashInit(errhand,0,intcmp,inthash);
    fdtable = I2HashInit(errhand,0,intcmp,inthash);
    if(!pidtable || !fdtable){
        I2ErrLogP(errhand,0,"Unable to setup hash tables...");
        exit(1);
    }

    /*
     * daemonize here
     */
    mypid = 0;
    if(opts.daemon){

        /*
         * chdir to '/' so filesystems can be unmounted.
         */
        if(chdir("/") < 0){
            I2ErrLog(errhand,"Unable to chdir to /: %M");
            exit(1);
        }

        /*
         * reopen stdin/stdout/stderr fd's
         */
        for(rc=0;rc<3;rc++){
            if(close(rc) == -1 || open("/dev/null",O_RDWR) != rc){
                I2ErrLog(errhand,"Unable to reopen fd(%d): %M",
                        rc);
                exit(1);
            }
        }

        /*
         * respawn self to detach from terminal.
         */
        mypid = fork();
        if(mypid < 0){
            I2ErrLog(errhand,"Unable to fork: %M");
            exit(1);
        }
        if((mypid == 0) && (setsid() == -1)){
            I2ErrLog(errhand,"setsid(): %M");
            exit(1);
        }
    }
    else{
        /*
         * Depending upon the shell that starts this -Z "foreground"
         * daemon, this process may or may not be the Process Group
         * leader... This will make sure. (Needed so HUP/TERM
         * catching can kill the whole process group with one
         * kill call.) setsid handles this when daemonizing.
         */
        mypid = getpid();
        if(setpgid(0,mypid) != 0){
            I2ErrLog(errhand,"setpgid(): %M");
            exit(1);
        }
    }

    /*
     * Temporarily take root permissions back.
     * (If this is parent of daemonizing - exit immediately after
     * updating pid/info files. If not daemonizing, setuid/setgid
     * is called after the mypid if to return to lesser
     * permissions.)
     */
    if((setuser) && (seteuid(getuid()) != 0)){
        I2ErrLog(errhand,"seteuid(): %M");
        kill(mypid,SIGTERM);
        exit(1);
    }
    if((setgroup) && (setegid(getgid()) != 0)){
        I2ErrLog(errhand,"setegid(): %M");
        kill(mypid,SIGTERM);
        exit(1);
    }

    /*
     * If this is the parent process (or not daemonizing) - write the pid
     * and info files.
     */
    if(mypid > 0){

        /* Record pid.  */
        fprintf(pid_fp, "%lld\n", (long long)mypid);
        if (fflush(pid_fp) < 0) {
            I2ErrLogP(errhand, errno, "fflush: %M");
            kill(mypid,SIGTERM);
            exit(1);
        }

        /* Record the start timestamp in the info file. */
        strcpy(info_file, opts.vardir);
        strcat(info_file, BWL_PATH_SEPARATOR);
        strcat(info_file, "bwctld.info");
        if ((info_fp = fopen(info_file, "w")) == NULL) {
            I2ErrLog(errhand, "fopen(%s): %M", info_file);
            kill(mypid,SIGTERM);
            exit(1);
        }

        if(!BWLGetTimeStamp(ctx,&currtime)){
            I2ErrLogP(errhand, errno, "BWLGetTimeStamp: %M");
            kill(mypid,SIGTERM);
            exit(1);
        }
        uptime = currtime.tstamp;
        fprintf(info_fp, "START="BWL_TSTAMPFMT"\n", currtime.tstamp);
        fprintf(info_fp, "PID=%lld\n", (long long)mypid);
        while ((rc = fclose(info_fp)) < 0 && errno == EINTR);
        if(rc < 0){
            I2ErrLog(errhand,"fclose(): %M");
            kill(mypid,SIGTERM);
            exit(1);
        }

        /*
         * If daemonizing - this is parent - exit.
         */
        if(opts.daemon) exit(0);
    }

    /*
     * If the local interface was specified, use it - otherwise use NULL
     * for wildcard.
     */
    if(opts.srcnode && !(listenaddr = BWLAddrByNode(ctx,opts.srcnode))){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "Invalid source address specified: %s",opts.srcnode);
        exit(1);
    }
    listenaddr = BWLServerSockCreate(ctx,listenaddr,&out);
    if(!listenaddr){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "Unable to create server socket. Exiting...");
        exit(1);
    }

    /*
     * set real uid/gid, not just effective.
     */
    if((setgroup) && (setgid(setgroup) != 0)){
        I2ErrLog(errhand,"setegid(): %M");
        exit(1);
    }
    if((setuser) && (setuid(setuser) != 0)){
        I2ErrLog(errhand,"setuid(): %M");
        exit(1);
    }

    /*
     * Set up signal handling.
     */
    memset(&ignact,0,sizeof(ignact));
    memset(&setact,0,sizeof(setact));

    ignact.sa_handler = SIG_IGN;
    setact.sa_handler = signal_catch;
    sigemptyset(&ignact.sa_mask);
    sigemptyset(&setact.sa_mask);
    ignact.sa_flags = setact.sa_flags = 0;

    if(        (sigaction(SIGPIPE,&ignact,NULL) != 0)    ||
            (sigaction(SIGUSR1,&setact,NULL) != 0)    ||
            (sigaction(SIGUSR2,&setact,NULL) != 0)    ||
            (sigaction(SIGINT,&setact,NULL) != 0)    ||
            (sigaction(SIGTERM,&setact,NULL) != 0)    ||
            (sigaction(SIGHUP,&setact,NULL) != 0)    ||
            (sigaction(SIGCHLD,&setact,NULL) != 0)    ||
            (sigaction(SIGALRM,&setact,NULL) != 0)    ){
        I2ErrLog(errhand,"sigaction(): %M");
        exit(1);
    }

    listenfd = BWLAddrFD(listenaddr);
    FD_ZERO(&readfds);
    FD_SET(listenfd,&readfds);
    maxfd = listenfd;

    while (1) {
        int nfound;
        fd_set ready;

        if(maxfd < 0){
            I2HashIterate(fdtable,FindMaxFD,&maxfd);
            maxfd = MAX(maxfd,listenfd);
        }
        ready = readfds;

        if(ipfd_exit){
            break;
        }

        nfound = select(maxfd+1,&ready,NULL,NULL,NULL);

        /*
         * Handle select interupts/errors.
         */
        if(nfound < 0){
            if(errno == EINTR){
                if(ipfd_exit){
                    break;
                }
                ReapChildren(&maxfd,&readfds);
                continue;
            }
            BWLError(ctx,BWLErrFATAL,errno,"select(): %M");
            exit(1);
        }

        /*
         * shouldn't happen, but for completeness...
         */
        if(nfound == 0)
            continue;

        if(FD_ISSET(listenfd, &ready)){ /* new connection */
            NewConnection(policy,listenaddr,&maxfd,&readfds);
        }
        else{
            CleanPipes(&ready,&maxfd,&readfds,nfound);
        }

        if(ipfd_exit){
            break;
        }

        ReapChildren(&maxfd,&readfds);
    }

    I2ErrLog(errhand,"%s: exiting...",progname);
    /*
     * Close the server socket. reset the readfds/maxfd so they
     * can't confuse later ReapChildren calls.
     */
    BWLAddrFree(listenaddr);
    FD_ZERO(&readfds);
    maxfd = -1;

    /*
     * Signal the process group to exit.
     */
    kill(-mypid,SIGTERM);

    /*
     * Set an alarm to exit by even if graceful shutdown doesn't occur.
     */
    ipfd_alrm = 0;
    alarm(opts.dieby);

    /*
     * Close all the pipes so pipe i/o can stay simple. (Don't have
     * to deal with interrupts for this.)
     */
    I2HashIterate(fdtable,ClosePipes,NULL);

    /*
     * Loop until all children have been waited for, or until
     * alarm goes off.
     */
    sigemptyset(&sigs);
    while(!ipfd_alrm && (I2HashNumEntries(pidtable) > 0)){
        if(!ipfd_chld){
            (void)sigsuspend(&sigs);
        }
        ReapChildren(&maxfd,&readfds);
    }

    /*
     * If children didn't die, report the error - send SIGKILL and exit.
     */
    if(I2HashNumEntries(pidtable) > 0){
        I2ErrLog(errhand,
                "Children still alive... Time for brute force.");
        kill(-mypid,SIGKILL);
        exit(1);
    }

    I2ErrLog(errhand,"%s: exited.",progname);

    exit(0);
}
