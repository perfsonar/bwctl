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
 *	File:		endpoint.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:25:57 MDT 2003
 *
 *	Description:	
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "bwlibP.h"

static int ipf_term;
static int ipf_chld;
static int ipf_intr;

/*
 * Function:	EndpointAlloc
 *
 * Description:	
 * 	Allocate a record to keep track of the state information for
 * 	this endpoint. (Much of this state is also in the control record
 * 	and the TestSession record... May simplify this in the future
 * 	to just reference the other records.)
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
	BWLTestSession	tsess
	)
{
	BWLEndpoint	ep = calloc(1,sizeof(BWLEndpointRec));

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
 * Function:	EndpointClear
 *
 * Description:	
 * 	Clear out any resources that are used in the Endpoint record
 * 	that are not needed in the parent process after the endpoint
 * 	forks off to do the actual test.
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
	BWLEndpoint	ep
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
 * Function:	EndpointFree
 *
 * Description:	
 * 	completely free all resoruces associated with an endpoint record.
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
	BWLEndpoint	ep
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
	BWLTestSession	tsess
	)
{
	char	fname[PATH_MAX+1];
	int	fd;
	FILE	*fp;

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

#if	TODO
	if(unlink(fname) != 0){
		BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
					"unlink(%s): %M",fname);
		while((fclose(fp) != 0) && (errno == EINTR));
		return NULL;
	}
#endif

	return fp;
}

static int
epssock(
		BWLTestSession	tsess,
		u_int16_t	*dataport
		)
{
	BWLAddr			localaddr;
	int			fd;
	int			on;
	struct sockaddr_storage	sbuff;
	socklen_t		sbuff_len = sizeof(sbuff);
	struct sockaddr		*saddr = (struct sockaddr *)&sbuff;

	localaddr = tsess->test_spec.receiver;

	fd = socket(localaddr->ai->ai_family,SOCK_STREAM,IPPROTO_IP);
	if(fd < 0){
		BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
				"Unable to open Endpoint Server Socket: %M");
		return fd;
	}

	on=1;
	if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) != 0){
		BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
				"setsockopt(SO_REUSEADDR): %M");
		goto failsock;
	}

#if	defined(AF_INET6) && defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
	on=0;
	if((localaddr->ai->ai_family == AF_INET6) &&
				setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,
				&on,sizeof(on)) != 0){
		BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
				"setsockopt(!IPV6_V6ONLY): %M");
		goto failsock;
	}
#endif

	if(bind(fd,localaddr->ai->ai_addr,localaddr->ai->ai_addrlen) != 0){
		BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"bind(): %M");
		goto failsock;
	}

	/* set listen backlog to 1 - we only expect 1 client */
	if(listen(fd,1) != 0){
		BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"listen(): %M");
		goto failsock;
	}

	/*
	 * Retrieve the ephemeral port picked by the system.
	 */
	memset(&sbuff,0,sizeof(sbuff));
	if(getsockname(fd,(void*)&sbuff,&sbuff_len) != 0){
		BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
							"getsockname(): %M");
		goto failsock;
	}

	switch(saddr->sa_family){
		struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
		struct sockaddr_in6	*saddr6;

		case AF_INET6:
			saddr6 = (struct sockaddr_in6 *)saddr;
			*dataport = ntohs(saddr6->sin6_port);
			break;
#endif
		case AF_INET:
			saddr4 = (struct sockaddr_in *)saddr;
			*dataport = ntohs(saddr4->sin_port);
			break;
		default:
			BWLError(tsess->cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
				"Endpoint control socket: Invalid AF(%d)",
				saddr->sa_family);
			goto failsock;
	}

	return fd;

failsock:
	while((close(fd) < 0) && (errno == EINTR));
	return -1;
}

#define	_BWLGetSIDAESKEY	"_BWLGetSIDAESKEY"

static BWLBoolean
getsidaeskey(
	BWLContext	ctx,
	const BWLUserID	userid	__attribute__((unused)),
	BWLKey		key_ret,
	BWLErrSeverity	*err_ret
	)
{
	u_int8_t	*sidbytes;

	if(!(sidbytes = (u_int8_t*)BWLContextConfigGet(ctx,_BWLGetSIDAESKEY))){
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"getsidaeskey: _BWLGetSIDAESKEY not set");
		*err_ret = BWLErrFATAL;
		return False;
	}

	memcpy(key_ret,sidbytes,sizeof(key_ret));

	return True;
}

static void
sig_catch(
		int	signo
		)
{
	switch(signo){
		case SIGTERM:
		case SIGINT:
		case SIGHUP:
		case SIGALRM:
			ipf_term++;
			break;
		case SIGCHLD:
			ipf_chld++;
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
		BWLContext	ctx,
		u_int32_t	n
		)
{
	char			nbuf[10];
	int			len;
	char			*ret;

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

/*
 * This function redirects stdout to the tmpfile that was created
 * to hold the result, and then waits until it should fire off
 * the test - and then exec's.
 */
static void
run_iperf(
		BWLEndpoint	ep
		)
{
	BWLTestSession		tsess = ep->tsess;
	BWLContext		ctx = tsess->cntrl->ctx;
	int			outfd = fileno(ep->tsess->localfp);
	int			nullfd;
	struct sigaction	act;
	BWLTimeStamp		currtime;
	BWLNum64		reltime;
	struct timespec		ts_sleep;
	struct timespec		ts_remain;
	int			a = 0;
	char			hostname[MAXHOSTNAMELEN];
	size_t			hlen = sizeof(hostname);
	char			*ipargs[_BWL_MAX_IPERFARGS*2];
	char			*iperf = (char*)BWLContextConfigGet(ctx,
								BWLIperfCmd);
	FILE			*nstdout;

#if	NOT
	{
		int	waitfor=1;

		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"Waiting!!!:ipf_term=%d",ipf_term);
		while(waitfor);
	}
#endif

	/*
	 * First figure out the args for iperf
	 */
	if(!iperf) iperf = _BWL_IPERF_CMD;
	ipargs[a++] = iperf;

	ipargs[a++] = "-f";
	ipargs[a++] = "b";

	if(tsess->test_spec.len_buffer){
		ipargs[a++] = "-l";
		ipargs[a++] = uint32dup(ctx,tsess->test_spec.len_buffer);
	}

	ipargs[a++] = "-m";

	ipargs[a++] = "-p";
	ipargs[a++] = uint32dup(ctx,tsess->recv_port);

	if(tsess->test_spec.udp){
		ipargs[a++] = "-u";
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

	switch(tsess->test_spec.receiver->saddr->sa_family){
#ifdef	AF_INET6
		case AF_INET6:
			ipargs[a++] = "-V";
			break;
#endif
		case AF_INET:
		default:
			break;
	}

	BWLAddrNodeName(tsess->test_spec.receiver,hostname,&hlen);
	if(!hlen){
		exit(BWL_CNTRL_FAILURE);
	}

	if(tsess->conf_receiver){
		ipargs[a++] = "-B";
		ipargs[a++] = hostname;

		ipargs[a++] = "-s";
	}
	else{
		ipargs[a++] = "-c";
		ipargs[a++] = hostname;
	}

	ipargs[a++] = NULL;

	/*
	 * Open /dev/null to dup to stdin before the exec.
	 */
	if( (nullfd = open(_BWL_DEV_NULL,O_RDONLY)) < 0){
		BWLError(ctx,BWLErrFATAL,errno,"open(/dev/null): %M");
		exit(BWL_CNTRL_FAILURE);
	}

	if(		(dup2(nullfd,STDIN_FILENO) < 0) ||
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
	if(	(sigaction(SIGPIPE,&act,NULL) != 0) ||
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
				"run_iperf(): Too LATE!");
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
	BWLGetTimeStamp(ctx,&currtime);
	fprintf(nstdout,"%f:",BWLNum64ToDouble(currtime.tstamp));
	for(a=0;ipargs[a];a++){
		fprintf(nstdout," %s",ipargs[a]);
	}
	fprintf(nstdout,"\n");
	fflush(nstdout);

	execv(iperf,ipargs);

	BWLError(ctx,BWLErrFATAL,errno,"execv(): %M");
	exit(BWL_CNTRL_FAILURE);
}

BWLBoolean
_BWLEndpointStart(
	BWLTestSession	tsess,
	u_int16_t	*dataport,
	BWLErrSeverity	*err_ret
	)
{
	BWLContext		ctx = tsess->cntrl->ctx;
	BWLEndpoint		ep;
	BWLGetAESKeyFunc	getaeskey = getsidaeskey;
	sigset_t		sigs;
	sigset_t		osigs;
	struct sigaction	act;
	BWLTimeStamp		currtime;
	BWLNum64		reltime;
	struct itimerval	itval;
	BWLAcceptType		aval;
	fd_set			readfds;
	fd_set			exceptfds;
	int			rc=0;
	int			do_read=0;
	int			do_write=0;
	BWLRequestType		msgtype = BWLReqInvalid;


	if( !(tsess->localfp = tfile(tsess)) ||
					!(tsess->remotefp = tfile(tsess))){
		return False;
	}

	if( !(ep=EndpointAlloc(tsess))){
		return False;
	}

	if(tsess->conf_receiver){
		if((ep->ssockfd = epssock(tsess,dataport)) < 0){
			EndpointFree(ep);
			return False;
		}
	}

	/*
	 * sigprocmask to block signals before the fork. Then
	 * install new sig handlers in the child before unblocking
	 * them. In the parent, just unblock them. (The sigprocmask
	 * is needed to stop the possible race condition.)
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
		int	serr = errno;
		/* fork error */
		(void)sigprocmask(SIG_SETMASK,&osigs,NULL);
		BWLError(ctx,BWLErrFATAL,serr,"fork(): %M");
		EndpointFree(ep);
		tsess->endpoint = NULL;
		return False;
	}

	if(ep->child > 0){
		/* parent */
		int	cstatus;

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
	ipf_term = ipf_intr = ipf_chld = 0;
	memset(&act,0,sizeof(act));
	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	if(		(sigaction(SIGTERM,&act,NULL) != 0) ||
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

#ifndef	NDEBUG
	/*
	 * busy loop to wait for debugger attachment
	 */
	{
		int	waitfor = (int)BWLContextConfigGet(ctx,BWLChildWait);

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
	 * Now fork again. The child will go on to "exec" iperf at the
	 * appropriate time. The parent will open a connection to the other
	 * endpoint for the test results exchange.
	 */
	ep->child = fork();

	if(ep->child < 0){
		/* fork error */
		BWLError(ctx,BWLErrFATAL,errno,"fork(): %M");
		exit(BWL_CNTRL_FAILURE);
	}

	if(ep->child == 0){
		/* go run iperf */
		run_iperf(ep);
		/* NOTREACHED */
	}

	/********************************************************************
	 * The remainder of this procedure is the endpoint control process  *
	 ********************************************************************/

	/*
	 * Reset the GetAESKey function to use the SID for the AESKey in
	 * the Endpoint to Endpoint control connection setup.
	 */
	if(		!BWLContextConfigSet(ctx,BWLGetAESKey,
							(void*)getaeskey) ||
			!BWLContextConfigSet(ctx,_BWLGetSIDAESKEY,
							(void*)tsess->sid)
			){
		BWLError(ctx,BWLErrFATAL,errno,
				"Unable to setup SID for endpoint: %M");
		goto end;
	}
	(void)BWLContextConfigDelete(ctx,BWLCheckControlPolicy);
	(void)BWLContextConfigDelete(ctx,BWLCheckTestPolicy);
	(void)BWLContextConfigDelete(ctx,BWLTestComplete);
	(void)BWLContextConfigDelete(ctx,BWLProcessResults);

	/*
	 * TODO: If ctx variable for client-side retn_on_intr gets
	 * added - change the ctx variable here!
	 */

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

	memset(&itval,0,sizeof(itval));
	BWLNum64ToTimeval(&itval.it_value,reltime);
	if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
		BWLError(ctx,BWLErrFATAL,errno,"setitimer(): %M");
		goto end;
	}

	if(tsess->conf_receiver){
		struct sockaddr_storage	sbuff;
		socklen_t		sbuff_len;
		int			connfd;

ACCEPT:
		sbuff_len = sizeof(sbuff);
		connfd = accept(ep->ssockfd,(struct sockaddr *)&sbuff,
								&sbuff_len);
		if(ipf_intr)
			goto end;

		if(connfd < 0){
			if(errno == EINTR && !ipf_intr){
				goto ACCEPT;
			}
			BWLError(ctx,BWLErrFATAL,errno,
				"Unable to accept() endpoint cntrl: %M");
			goto end;
		}

		/*
		 * Only allow connections from the remote testaddr
		 */
		if(I2SockAddrEqual(tsess->test_spec.sender->saddr,
					tsess->test_spec.sender->saddrlen,
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
				tsess->cntrl->mode,currtime.tstamp,
				&ipf_term,err_ret);
	}
	else{
		/*
		 * Copy remote address, then modify port number
		 * for contacting remote host.
		 */
		BWLAddr	remote = _BWLAddrCopy(tsess->test_spec.receiver);
		switch(remote->saddr->sa_family){
			struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
			struct sockaddr_in6	*saddr6;

			case AF_INET6:
				saddr6 = (struct sockaddr_in6 *)remote->saddr;
				saddr6->sin6_port = htons(*dataport);
				break;
#endif
			case AF_INET:
				saddr4 = (struct sockaddr_in *)remote->saddr;
				saddr4->sin_port = htons(*dataport);
				break;
			default:
				BWLError(tsess->cntrl->ctx,BWLErrFATAL,
						BWLErrINVALID,
				"Endpoint control socket: Invalid AF(%d)",
					remote->saddr->sa_family);
				goto end;
		}

		ep->rcntrl = BWLControlOpen(ctx,
				_BWLAddrCopy(tsess->test_spec.sender),
				remote,tsess->cntrl->mode,"endpoint",NULL,
				err_ret);
	}
	if(!ep->rcntrl)
		goto end;
	if(ipf_term)
		goto end;

	/*
	 * Now that we have established communication, reset the timer
	 * for just past the end of the test period. (one second past
	 * the session time plus the fuzz time.)
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
	reltime = BWLNum64Add(reltime,tsess->fuzz);
	reltime = BWLNum64Add(reltime,
			BWLULongToNum64(tsess->test_spec.duration));
	/* TODO: remove after debugging */
	reltime = BWLNum64Add(reltime,BWLULongToNum64(5));

	memset(&itval,0,sizeof(itval));
	BWLNum64ToTimeval(&itval.it_value,reltime);
	if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
		BWLError(ctx,BWLErrFATAL,errno,"setitimer(): %M");
		goto end;
	}

	if(ipf_term)
		goto end;

	/*
	 * Fake lcntrl socket into "test" mode and set it up to trade results.
	 */
	ep->rcntrl->tests = tsess;
	tsess->cntrl = ep->rcntrl;
	tsess->closure = NULL;
	ep->rcntrl->state |= _BWLStateTest;
	
	FD_ZERO(&readfds);
	FD_SET(ep->rcntrl->sockfd,&readfds);
	exceptfds = readfds;
	do_read=do_write=1;

select:
	rc = select(ep->rcntrl->sockfd+1,&readfds,NULL,&exceptfds,NULL);

	/*
	 * Is socket readable?
	 */
	if(!ipf_term && (rc > 0)){
		if(!FD_ISSET(ep->rcntrl->sockfd,&readfds)){
			BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"select(): peer connection not ready?");
			aval = BWL_CNTRL_FAILURE;
			ipf_term++;
		}
		else{
			do_read=0;
			msgtype = BWLReadRequestType(ep->rcntrl,&ipf_term);
			if(msgtype == 0){
				BWLError(ctx,BWLErrFATAL,errno,
						"Test peer closed connection.");
				aval = BWL_CNTRL_FAILURE;
				ipf_term++;
				do_write=0;
			}
			else if(msgtype != 3){
				BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"Invalid protocol message from test peer");
				aval = BWL_CNTRL_FAILURE;
				do_write=0;
			}
			else{
				*err_ret = _BWLReadStopSession(ep->rcntrl,
					&ipf_term,&aval,tsess->remotefp);
				if((*err_ret == BWLErrOK) &&
						(aval == BWL_CNTRL_ACCEPT) &&
						!ipf_term){
					FD_ZERO(&readfds);
					exceptfds = readfds;
					goto select;
				}
			}
		}
	}

end:
	if((kill(ep->child,SIGINT) != 0) && (errno != ESRCH)){
		BWLError(ctx,BWLErrFATAL,errno,
				"Unable to kill test endpoint, pid=%d: %M",
				ep->child);
		exit(BWL_CNTRL_FAILURE);
	}
	ep->wopts &= ~WNOHANG;
	if(!_BWLEndpointStatus(tsess,&ep->acceptval,err_ret)){
		exit(BWL_CNTRL_FAILURE);
	}
	if(ep->acceptval != BWL_CNTRL_ACCEPT){
		ep->acceptval = BWL_CNTRL_FAILURE;
		tsess->localfp = NULL;
	}

	if(do_write){
		*err_ret = _BWLWriteStopSession(ep->rcntrl,&ipf_term,
				ep->acceptval,tsess->localfp);
		if(*err_ret != BWLErrOK){
			do_read = 0;
		}
	}

	if(do_read && !ipf_term){
#if	NOT
	{
		int	waitfor=1;

		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"Waiting!!!:ipf_term=%d",ipf_term);
		while(waitfor);
	}
#endif
		msgtype = BWLReadRequestType(ep->rcntrl,&ipf_term);
		if(msgtype == 0){
			BWLError(ctx,BWLErrFATAL,errno,
						"Test peer closed connection.");
			aval = BWL_CNTRL_FAILURE;
		}
		else if(msgtype != 3){
			BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"Invalid protocol message from test peer: %d,ipf_term=%d",
				msgtype,ipf_term);
			aval = BWL_CNTRL_FAILURE;
		}
		else{
			(void)_BWLReadStopSession(ep->rcntrl,
					&ipf_term,&aval,tsess->remotefp);
		}
	}

	exit(aval & ep->acceptval);
}

BWLBoolean
_BWLEndpointStatus(
	BWLTestSession	tsess,
	BWLAcceptType	*aval,		/* out */
	BWLErrSeverity	*err_ret
	)
{
	pid_t			p;
	int			childstatus;
	BWLEndpoint		ep = tsess->endpoint;

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
				"_BWLEndpointStatus:Can't query child #%d: %M",
				ep->child);
			ep->acceptval = BWL_CNTRL_FAILURE;
			*err_ret = BWLErrWARNING;
			return False;
		}
		else if(p > 0){
			if(WIFEXITED(childstatus)){
				ep->acceptval =
					(BWLAcceptType)WEXITSTATUS(childstatus);
			}
			else if(!WIFSTOPPED(childstatus)){
				ep->acceptval = BWL_CNTRL_FAILURE;
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
	BWLTestSession	tsess,
	BWLAcceptType	aval,
	BWLErrSeverity	*err_ret
	)
{
	int		teststatus;
	BWLBoolean	retval;
	BWLEndpoint	ep = tsess->endpoint;

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
	if((kill(ep->child,SIGTERM) != 0) && (errno != ESRCH))
		goto error;

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
