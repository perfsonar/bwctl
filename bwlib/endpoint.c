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


    if( !(lsaddr = I2AddrSAddr(tsess->test_spec.receiver,&lsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "epssock: Invalid receiver I2Addr");
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
        BWLPortsSetI(tsess->cntrl->ctx,portrange,tsess->peer_port);
        p = port = BWLPortsNext(portrange);
    }
    else{
        p = port = 0;
    }

    do{
        memset(&sbuff,0,sizeof(sbuff));
        memcpy(&sbuff,lsaddr,lsaddrlen);

        /* type-punning!!! */
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
            I2AddrNodeName(tsess->test_spec.receiver,nodebuff,&nodebufflen),p);
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

static char *
uint32dup(
        BWLContext    ctx,
        uint32_t    n
        )
{
    char    nbuf[100];
    int     len;
    char    *ret;

    nbuf[sizeof(nbuf)-1] = '\0';
    len = snprintf(nbuf,sizeof(nbuf)-1,"%llu",(unsigned long long)n);
    if((len < 0) || ((unsigned)len >= sizeof(nbuf))){
        BWLError(ctx,BWLErrFATAL,errno,"snprintf(): %M");
        exit(BWL_CNTRL_FAILURE);
    }

    if((ret = strdup(nbuf)))
        return ret;

    BWLError(ctx,BWLErrFATAL,errno,"strdup(): %M");
    exit(BWL_CNTRL_FAILURE);
}

static void
prepare_and_wait_for_test(
			BWLContext    ctx, 
			BWLTestSession   tsess,
			int    outfd,
			char    *ipargs[]
			)
{
    int                 a = 0;
    int                 nullfd;
    struct sigaction    act;
    BWLTimeStamp        currtime;
    BWLNum64            reltime;
    struct timespec     ts_sleep;
    struct timespec     ts_remain;
    FILE                *nstdout;

    /*
     * Open /dev/null to dup to stdin before the exec.
     */
    if( (nullfd = open(_BWL_DEV_NULL,O_RDONLY)) < 0){
	BWLError(ctx,BWLErrFATAL,errno,"open(/dev/null): %M");
	exit(BWL_CNTRL_FAILURE);
    }

    if(        (dup2(nullfd,STDIN_FILENO) < 0) ||
	       (dup2(outfd,STDOUT_FILENO) < 0) ||
	       (dup2(outfd,STDERR_FILENO) < 0)){
	BWLError(ctx,BWLErrFATAL,errno,"dup2(): %M");
	exit(BWL_CNTRL_FAILURE);
    }

    if(!(nstdout = fdopen(STDOUT_FILENO,"a"))){
	BWLError(ctx,BWLErrFATAL,errno,"fdopen(STDOUT): %M");
	exit(BWL_CNTRL_FAILURE);
    }

    /*
     * Reset ignored signals to default
     * (exec will reset set signals to default)
     */
    memset(&act,0,sizeof(act));
    act.sa_handler = SIG_DFL;
    sigemptyset(&act.sa_mask);
    if(    (sigaction(SIGPIPE,&act,NULL) != 0) ||
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
		 "run_tester(): Too LATE!");
	exit(BWL_CNTRL_FAILURE);
    }

    reltime = BWLNum64Sub(tsess->reserve_time,currtime.tstamp);

    /*
     * Use the error estimates rounded up to 1 second, and start the
     * recv side that much before the test time.
     */
    if(tsess->conf_receiver){
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
     * Now run iperf!
     */
    fprintf(nstdout,"bwctl: exec_line: ");

    for(a=0;ipargs[a];a++){
	fprintf(nstdout," %s",ipargs[a]);
    }
    fprintf(nstdout,"\n");

    BWLGetTimeStamp(ctx,&currtime);
    fprintf(nstdout,"bwctl: start_exec: %f\n",
            BWLNum64ToDouble(currtime.tstamp));
    fflush(nstdout);

    return;
}

/*
 * This function redirects stdout to the tmpfile that was created
 * to hold the result, and then waits until it should fire off
 * the test - and then exec's.
 */
static void
run_tester(
        BWLEndpoint    ep
        )
{
    BWLTestSession      tsess = ep->tsess;
    BWLContext          ctx = tsess->cntrl->ctx;
    int                 outfd = fileno(ep->tsess->localfp);
    int                 a = 0;
    char                recvhost[MAXHOSTNAMELEN];
    char                sendhost[MAXHOSTNAMELEN];
    size_t              hlen = sizeof(recvhost);
    char                *ipargs[_BWL_MAX_IPERFARGS*2];
    struct sockaddr     *rsaddr;
    socklen_t           rsaddrlen;

    if( !(rsaddr = I2AddrSAddr(tsess->test_spec.receiver,&rsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "run_tester: Invalid receiver I2Addr");
	exit(BWL_CNTRL_FAILURE);
    }

    BWLError(tsess->cntrl->ctx,BWLErrINFO,BWLErrUNKNOWN,
            "run_tester: tester = %lu",tsess->test_spec.tool);

    if(BWL_TOOL_THRULAY == tsess->test_spec.tool){
#if defined(HAVE_LIBTHRULAY) && defined(HAVE_THRULAY_SERVER_H) && defined(HAVE_THRULAY_CLIENT_H)
	int rc;
	if(tsess->conf_receiver){
	    /* Run thrulay server through its API */
	    int port, window, num_streams;

	    I2AddrNodeName(tsess->test_spec.receiver,recvhost,&hlen);
	    if(!hlen){
		exit(BWL_CNTRL_FAILURE);
	    }

	    hlen = sizeof(sendhost);
	    I2AddrNodeName(tsess->test_spec.sender,sendhost,&hlen);
	    if(!hlen){
		exit(BWL_CNTRL_FAILURE);
	    }

	    /* -p server port */
	    port = tsess->tool_port;

	    /* -w window size in bytes */
	    if(tsess->test_spec.window_size){
		window = tsess->test_spec.window_size;
	    }
	    else{
		window = THRULAY_DEFAULT_WINDOW;
	    }

	    /* -m parallel test streams */
	    if(tsess->test_spec.parallel_streams > 0){
		num_streams = tsess->test_spec.parallel_streams;
	    }
	    else{
		num_streams = 1;
	    }

	    /* Log through stderr and verbose reports. */
	    rc = thrulay_server_init(LOGTYPE_STDERR,1);
	    if (rc < 0)
		BWLError(ctx,BWLErrFATAL,errno,"Initializing thrulay server: "
			 "%s", thrulay_server_strerror(rc));

	    prepare_and_wait_for_test(ctx,tsess,outfd,ipargs);

	    /*
	     * Now run thrulay server!
	     */
	    rc = thrulay_server_listen(port,window);
	    if (rc < 0)
		BWLError(ctx,BWLErrFATAL,errno,"Thrulay server listen: %s", 
			 thrulay_server_strerror(rc));
	    rc = thrulay_server_start(num_streams, NULL);
	    if (rc < 0)
		BWLError(ctx,BWLErrFATAL,errno,"Thrulay server: %s", 
			 thrulay_server_strerror(rc));
	    exit(0);
	}
	else{
	    /* Run thrulay client through its API */
	    thrulay_opt_t thrulay_opt;

	    /* Give default values to the test spec struct */
	    thrulay_client_options_init(&thrulay_opt);
	    /* But disable output. */
	    thrulay_opt.reporting_verbosity = -1;

	    hlen = sizeof(sendhost);
	    I2AddrNodeName(tsess->test_spec.sender,sendhost,&hlen);
	    if(!hlen){
		exit(BWL_CNTRL_FAILURE);
	    }

	    /* server to send test data to */
	    I2AddrNodeName(tsess->test_spec.receiver,recvhost,&hlen);
	    if(!hlen){
		exit(BWL_CNTRL_FAILURE);
	    }

	    thrulay_opt.server_name = recvhost;

	    /* -t test duration in seconds */
	    thrulay_opt.test_duration = tsess->test_spec.duration;

	    /* -i reporting interval in seconds */
	    if(tsess->test_spec.report_interval){
		thrulay_opt.reporting_interval = 
		    tsess->test_spec.report_interval;
	    }

	    /* -w window size in bytes */
	    if(tsess->test_spec.window_size){
		thrulay_opt.window = tsess->test_spec.window_size;
	    }

	    /* -l block size */
	    if(tsess->test_spec.len_buffer){
		thrulay_opt.block_size = tsess->test_spec.len_buffer;
	    }

	    /* -p server port */
	    thrulay_opt.port = tsess->tool_port;

	    /* Rate, if UDP test */
	    if(tsess->test_spec.udp){
		thrulay_opt.rate = tsess->test_spec.bandwidth;
	    }

	    /* -m parallel test streams */
	    if(tsess->test_spec.parallel_streams > 0){
		thrulay_opt.num_streams = tsess->test_spec.parallel_streams;
	    }

	    /* -b (busy wait in UDP test) and -D (DSCP value for TOS
                byte): not used for the moment. */
	    /* Multicast options not used too. */
	    rc = thrulay_client_init(thrulay_opt);
	    if (rc < 0)
		BWLError(ctx,BWLErrFATAL,errno,"Initializing thrulay "
			 "client: %s", thrulay_client_strerror(rc));

	    prepare_and_wait_for_test(ctx,tsess,outfd,ipargs);

	    /*
	     * Now run thrulay client!
	     */
	    rc = thrulay_client_start();
	    if (rc < 0)
		BWLError(ctx,BWLErrFATAL,errno,"While performing thrulay "
			 "test: %s", thrulay_client_strerror(rc));
	    rc = thrulay_client_report_final();
	    if (rc < 0)
		BWLError(ctx,BWLErrFATAL,errno,"While generating thrulay"
			 " final report: %s", thrulay_client_strerror(rc));
	    thrulay_client_exit();
	    exit(0);
	}
#else
	BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"A thrulay test was requested, "
		 "but libthrulay is not available. Something must have gone "
		 "wrong with the tool negotiation.");
	exit(BWL_CNTRL_FAILURE);
#endif
    }
    else if(BWL_TOOL_IPERF == tsess->test_spec.tool){
	/* Run iperf */
	char *iperf = (char*)BWLContextConfigGetV(ctx,BWLIperfCmd);
	if(!iperf) iperf = _BWL_IPERF_CMD;

	/*
	 * First figure out the args for iperf
	 */
	ipargs[a++] = iperf;

	if(tsess->conf_receiver){
	    ipargs[a++] = "-B";
	    ipargs[a++] = recvhost;

	    if(tsess->test_spec.parallel_streams > 0){
		ipargs[a++] = "-P";
		ipargs[a++] = uint32dup(ctx,tsess->test_spec.parallel_streams);
	    }
	    ipargs[a++] = "-s";
	}
	else{
	    ipargs[a++] = "-c";
	    ipargs[a++] = recvhost;
	    ipargs[a++] = "-B";
	    ipargs[a++] = sendhost;
	    if(tsess->test_spec.tos){
		ipargs[a++] = "-S";
		ipargs[a++] = uint32dup(ctx,tsess->test_spec.tos);
	    }
	}

	ipargs[a++] = "-f";
	ipargs[a++] = "b";

	if(tsess->test_spec.len_buffer){
	    ipargs[a++] = "-l";
	    ipargs[a++] = uint32dup(ctx,tsess->test_spec.len_buffer);
	}

	ipargs[a++] = "-m";

	ipargs[a++] = "-p";
	ipargs[a++] = uint32dup(ctx,tsess->tool_port);

	if(tsess->test_spec.udp){
	    ipargs[a++] = "-u";
	    if((!tsess->conf_receiver) && (tsess->test_spec.bandwidth)){
		ipargs[a++] = "-b";
		ipargs[a++] = uint32dup(ctx,tsess->test_spec.bandwidth);
	    }
	}

	if(tsess->test_spec.window_size){
	    ipargs[a++] = "-w";
	    ipargs[a++] = uint32dup(ctx,tsess->test_spec.window_size);
	}

	ipargs[a++] = "-t";
	ipargs[a++] = uint32dup(ctx,tsess->test_spec.duration);

	if(tsess->test_spec.report_interval){
	    ipargs[a++] = "-i";
	    ipargs[a++] = uint32dup(ctx,tsess->test_spec.report_interval);
	}

	switch(rsaddr->sa_family){
#ifdef    AF_INET6
        case AF_INET6:
            ipargs[a++] = "-V";
            break;
#endif
        case AF_INET:
        default:
            break;
	}

	I2AddrNodeName(tsess->test_spec.receiver,recvhost,&hlen);
	if(!hlen){
	    exit(BWL_CNTRL_FAILURE);
	}

	hlen = sizeof(sendhost);
	I2AddrNodeName(tsess->test_spec.sender,sendhost,&hlen);
	if(!hlen){
	    exit(BWL_CNTRL_FAILURE);
	}

	ipargs[a++] = NULL;

	prepare_and_wait_for_test(ctx,tsess,outfd,ipargs);

	/*
	 * Now run iperf!
	 */
	execvp(iperf,ipargs);

	BWLError(ctx,BWLErrFATAL,errno,"execv(%s): %M",iperf);
	exit(BWL_CNTRL_FAILURE);
    
    }
    else if(BWL_TOOL_NUTTCP == tsess->test_spec.tool){
	/* Run nuttcp. We use the client/server mode. */
	char *nuttcp = (char*)BWLContextConfigGetV(ctx,BWLNuttcpCmd);
	if(!nuttcp) nuttcp = _BWL_NUTTCP_CMD;

	/* Figure out arguments. */
	ipargs[a++] = nuttcp;
	/* Be verbose */
	ipargs[a++] = "-vv";
	if(tsess->conf_receiver){
	    ipargs[a++] = "-r";

	    if(tsess->test_spec.parallel_streams > 0){
		ipargs[a++] = "-N";
		ipargs[a++] = uint32dup(ctx,tsess->test_spec.parallel_streams);
	    }
	}
	else{
	    if(tsess->test_spec.tos){
		ipargs[a++] = "-c";
		ipargs[a++] = uint32dup(ctx,tsess->test_spec.tos);
	    }
	}

	if(tsess->test_spec.len_buffer){
	    ipargs[a++] = "-l";
	    ipargs[a++] = uint32dup(ctx,tsess->test_spec.len_buffer);
	}

	ipargs[a++] = "-p";
	ipargs[a++] = uint32dup(ctx,tsess->tool_port);

	if(tsess->test_spec.udp){
	    ipargs[a++] = "-u";
	    if((!tsess->conf_receiver) && (tsess->test_spec.bandwidth)){
		ipargs[a++] = "-R";
		/* nuttcp expects a number of Kbytes. */
		ipargs[a++] = uint32dup(ctx,tsess->test_spec.bandwidth / 1024);
	    }
	}

	if(tsess->test_spec.window_size){
	    ipargs[a++] = "-w";
	    /* nuttcp expects a number of Kbytes. */
	    ipargs[a++] = uint32dup(ctx,tsess->test_spec.window_size / 1024);
	}

	ipargs[a++] = "-T";
	ipargs[a++] = uint32dup(ctx,tsess->test_spec.duration);

	/* tsess->test_spec.report_interval (-i) is ignored, as the
	   transmitter/receiver mode of nuttcp does not support is.*/

	switch(rsaddr->sa_family){
#ifdef    AF_INET6
        case AF_INET6:
            ipargs[a++] = "-6";
            break;
#endif
        case AF_INET:
        default:
            break;
	}

	if(!tsess->conf_receiver){
	    ipargs[a++] = "-t";
	    ipargs[a++] = recvhost;
	}

	I2AddrNodeName(tsess->test_spec.receiver,recvhost,&hlen);
	if(!hlen){
	    exit(BWL_CNTRL_FAILURE);
	}

	hlen = sizeof(sendhost);
	I2AddrNodeName(tsess->test_spec.sender,sendhost,&hlen);
	if(!hlen){
	    exit(BWL_CNTRL_FAILURE);
	}

	ipargs[a++] = NULL;

	prepare_and_wait_for_test(ctx,tsess,outfd,ipargs);

	/*
	 * Now run nuttcp!
	 */
	execvp(nuttcp,ipargs);

	BWLError(ctx,BWLErrFATAL,errno,"execv(%s): %M",nuttcp);
	exit(BWL_CNTRL_FAILURE);
    }
    else{
	BWLError(ctx,BWLErrFATAL,errno,"Unknown tester tool: %x",
		 tsess->test_spec.tool);
	exit(BWL_CNTRL_UNSUPPORTED);
    }
}

BWLBoolean
_BWLEndpointStart(
        BWLTestSession  tsess,
        uint16_t       *peerport,
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
    int                 rc=0;
    int                 do_read=0;
    int                 do_write=0;
    BWLRequestType      msgtype = BWLReqInvalid;
    uint32_t            mode;
    int                 dead_child;


    if( !(tsess->localfp = tfile(tsess)) ||
            !(tsess->remotefp = tfile(tsess))){
        return False;
    }

    if( !(ep=EndpointAlloc(tsess))){
        return False;
    }

    if(tsess->conf_receiver){
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
            kill(ep->child,SIGINT);
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

    if(BWLNum64Cmp(tsess->reserve_time,currtime.tstamp) < 0){
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                "endpoint to endpoint setup too late");
        goto end;
    }

    reltime = BWLNum64Sub(tsess->reserve_time,currtime.tstamp);

#if	NOT
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

    if(tsess->conf_receiver){
        struct sockaddr         *ssaddr;
        socklen_t               ssaddrlen;
        struct sockaddr_storage sbuff;
        socklen_t               sbuff_len;
        int                     connfd;

        if( !(ssaddr = I2AddrSAddr(tsess->test_spec.sender,&ssaddrlen))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                    "_BWLEndpointStart: Invalid sender I2Addr");
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
                    "Unable to accept() endpoint cntrl: %M");
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
                    "Connect from invalid addr");
            while((close(connfd) != 0) && (errno == EINTR));
            goto ACCEPT;
        }

        close(ep->ssockfd);
        ep->ssockfd = -1;

        ep->rcntrl = BWLControlAccept(ctx,connfd,
                (struct sockaddr *)&sbuff,sbuff_len,
                mode,tsess->test_spec.tool,currtime.tstamp,
                &ipf_intr,err_ret);
    }
    else{
        /*
         * Copy remote address, with modified port number
         * and other fields for contacting remote host.
         */
        I2Addr              local;
        I2Addr              remote;
        struct sockaddr     *saddr;
        socklen_t           saddrlen;
        BWLToolAvailability tavail = 0;

        if( (saddr = I2AddrSAddr(tsess->test_spec.sender,&saddrlen)) &&
                (local = I2AddrBySAddr(BWLContextErrHandle(ctx),
                                       saddr,saddrlen,
                                       I2AddrSocktype(tsess->test_spec.sender),
                                       I2AddrProtocol(tsess->test_spec.sender)
                                       ))){
            if(!(I2AddrSetPort(local,0))){
                I2AddrFree(local);
                local = NULL;
            }
        }
        if( (saddr = I2AddrSAddr(tsess->test_spec.receiver,&saddrlen)) &&
                (remote =I2AddrBySAddr(BWLContextErrHandle(ctx),
                                       saddr,saddrlen,
                                       I2AddrSocktype(tsess->test_spec.receiver),
                                       I2AddrProtocol(tsess->test_spec.receiver)
                                      ))){
            if(!(I2AddrSetPort(remote,*peerport))){
                I2AddrFree(remote);
                remote = NULL;
            }
        }

        if(!local || !remote){
            BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                    "Endpoint: Unable to alloc peer addrs: %M");
            goto end;
        }

        ep->rcntrl = BWLControlOpen(ctx,local,remote,mode,"endpoint",NULL,
                &tavail,err_ret);
    }

    if(!ep->rcntrl){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                "Endpoint: Unable to connect to Peer!: %M");
        if(ipf_intr){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                    "Endpoint: Signal = %d",signo_caught);
        }
        goto end;
    }

    if(ipf_term || ipf_alrm)
        goto end;

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
        uint64_t    *bottleneckcapacity;

        if((bottleneckcapacity = (uint64_t*)BWLContextConfigGetV(ctx,
                        BWLBottleNeckCapacity))){
            double    dbnc = (double)*bottleneckcapacity;
            double    rtt = BWLNum64ToDouble(
                    BWLGetRTTBound(ep->rcntrl));
            tsess->test_spec.window_size = dbnc * rtt / 8 * 1.1;
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
        /* go run tester. */
        run_tester(ep);
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

    memset(&itval,0,sizeof(itval));
    BWLNum64ToTimeval(&itval.it_value,reltime);
    if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"PeerAgent: setitimer(): %M");
        goto end;
    }

    if(ipf_term){
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,"PeerAgent: Catching SIGTERM...");
        goto end;
    }

    if(tsess->conf_receiver){
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
                    "ahead of local, time error specified: %f(secs)",
                    t1-tr,e1+er);
            goto end;
        }
        else if((tr-er) > (t2+e2)){
            BWLError(ctx,BWLErrFATAL,errno,
                    "PeerAgent: Remote clock is at least %f(secs) "
                    "behind local, time error specified: %f(secs)",
                    tr-t2,e2+er);
            goto end;
        }
    }

    /*
     * Fake rcntrl socket into "test" mode and set it up to trade results.
     */
    ep->rcntrl->tests = tsess;
    tsess->cntrl = ep->rcntrl;
    tsess->closure = NULL;
    ep->rcntrl->state |= _BWLStateTest;

    FD_ZERO(&readfds);
    FD_SET(ep->rcntrl->sockfd,&readfds);
    exceptfds = readfds;
    do_read=do_write=1;

    /* Earliest time test should complete */
    currtime2.tstamp = BWLNum64Sub(tsess->reserve_time,tsess->fuzz);
    currtime2.tstamp = BWLNum64Add(currtime2.tstamp,
            BWLULongToNum64(tsess->test_spec.duration));

    /*
     * Wait for something to do:
     *  Peer message - remote stopping test
     *  Child exit - local side complete (or failed)
     *  Timer expire - test hung?
     *  TERM signal - parent killing this.
     */
    while(!rc && !ipf_intr){
        rc = select(ep->rcntrl->sockfd+1,&readfds,NULL,&exceptfds,NULL);
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
     * XXX:possible race condition (sender side finishies first, it sends
     * the StopSessions message, and it could be received and acted upon
     * before the receiver iperf process finishes)
     */
    if(!ipf_chld && ep->child){
        if(kill(ep->child,SIGTERM) == 0){
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
    if(!_BWLEndpointStatus(tsess,&ep->acceptval,err_ret)){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "PeerAgent: _BWLEndpointStatus failed");
        exit(BWL_CNTRL_FAILURE);
    }

    /*
     * If acceptval < 0, then test process is still running. Pull-out the
     * big gun (SIGKILL).
     */
    if(ep->child && (ep->acceptval < 0)){
        if((kill(ep->child,SIGKILL) != 0) && (errno != ESRCH)){
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
        if(!_BWLEndpointStatus(tsess,&ep->acceptval,err_ret)){
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
                    "bwctl: tool exited before expected with status=%d\n",
                    ep->exit_status);
        }

        /*
         * Peer stopped test early
         */
        if(rc > 0){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "PeerAgent: Peer cancelled test before expected");
        }

    }

    /*
     * Prepare data to send to peer
     * Print 'final' data of local tool
     */
    fprintf(tsess->localfp,"bwctl: stop_exec: %f\n",
            BWLNum64ToDouble(currtime.tstamp));
    fflush(tsess->localfp);

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

end:

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
            BWLError(ep->cntrl->ctx,BWLErrWARNING,
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
                    BWLError(ep->cntrl->ctx,BWLErrWARNING,errno,
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
        if((kill(ep->child,SIGTERM) != 0) && (errno != ESRCH)){
            goto error;
        }
        ep->killed = True;
    }

    /*
     * Remove the WNOHANG bit. We need to wait until the exit status
     * is available.
     * (Should we add a timer to break out? No - not that paranoid yet.)
     */
    ep->wopts &= ~WNOHANG;
    retval = _BWLEndpointStatus(tsess,&teststatus,err_ret);
    if(teststatus >= 0)
        goto done;

error:
    BWLError(ep->cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
            "EndpointStop:Can't signal child #%d: %M",ep->child);
done:
    if(aval < ep->acceptval){
        aval = ep->acceptval;
    }
    ep->tsess->endpoint = NULL;
    EndpointFree(ep);

    return retval;
}
