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

#include "ipcntrlP.h"

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
static IPFEndpoint
EndpointAlloc(
	IPFTestSession	tsess
	)
{
	IPFEndpoint	ep = calloc(1,sizeof(IPFEndpointRec));

	if(!ep){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,
						"malloc(EndpointRec)");
		return NULL;
	}

	ep->cntrl = tsess->cntrl;
	ep->tsess = tsess;

	ep->ssockfd = -1;

	ep->acceptval = IPF_CNTRL_INVALID;
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
	IPFEndpoint	ep
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
	IPFEndpoint	ep
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
	IPFTestSession	tsess
	)
{
	char	fname[PATH_MAX+1];
	int	fd;
	FILE	*fp;

	strcpy(fname,tsess->cntrl->ctx->tmpdir);
	strcat(fname,_IPF_PATH_SEPARATOR);
	strcat(fname,_IPF_TMPFILEFMT);

	if((fd = mkstemp(fname)) < 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,
						"mkstemp(%s): %M",fname);
		return NULL;
	}

	if( !(fp = fdopen(fd,"w+"))){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,
						"fdopen(%s:(%d)): %M",fname,fd);
		return NULL;
	}

	if(unlink(fname) != 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,
					"unlink(%s): %M",fname);
		while((fclose(fp) != 0) && (errno == EINTR));
		return NULL;
	}

	return fp;
}

static int
epssock(
		IPFTestSession	tsess,
		u_int16_t	*dataport
		)
{
	IPFAddr			localaddr;
	int			fd;
	int			on;
	struct sockaddr_storage	sbuff;
	socklen_t		sbuff_len = sizeof(sbuff);
	struct sockaddr		*saddr = (struct sockaddr *)&sbuff;

	localaddr = tsess->test_spec.receiver;

	fd = socket(localaddr->ai->ai_family,SOCK_STREAM,IPPROTO_IP);
	if(fd < 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,
				"Unable to open Endpoint Server Socket: %M");
		return fd;
	}

	on=1;
	if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) != 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,
				"setsockopt(SO_REUSEADDR): %M");
		goto failsock;
	}

#if	defined(AF_INET6) && defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
	on=0;
	if((localaddr->ai->ai_family == AF_INET6) &&
				setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,
				&on,sizeof(on)) != 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,
				"setsockopt(!IPV6_V6ONLY): %M");
		goto failsock;
	}
#endif

	if(bind(fd,localaddr->ai->ai_addr,localaddr->ai->ai_addrlen) != 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,"bind(): %M");
		goto failsock;
	}

	/* set listen backlog to 1 - we only expect 1 client */
	if(listen(fd,1) != 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,"listen(): %M");
		goto failsock;
	}

	/*
	 * Retrieve the ephemeral port picked by the system.
	 */
	memset(&sbuff,0,sizeof(sbuff));
	if(getsockname(fd,(void*)&sbuff,&sbuff_len) != 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,
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
			IPFError(tsess->cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"Endpoint control socket: Invalid AF(%d)",
				saddr->sa_family);
			goto failsock;
	}

	return fd;

failsock:
	while((close(fd) < 0) && (errno == EINTR));
	return -1;
}

#define	_IPFGetSIDAESKEY	"_IPFGetSIDAESKEY"

static IPFBoolean
getsidaeskey(
	IPFContext	ctx,
	const IPFUserID	userid	__attribute__((unused)),
	IPFKey		key_ret,
	IPFErrSeverity	*err_ret
	)
{
	u_int8_t	*sidbytes;

	if(!(sidbytes = (u_int8_t*)IPFContextConfigGet(ctx,_IPFGetSIDAESKEY))){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"getsidaeskey: _IPFGetSIDAESKEY not set");
		*err_ret = IPFErrFATAL;
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
			IPFError(NULL,IPFErrFATAL,IPFErrUNKNOWN,
					"sig_catch: Invalid signal(%d)",signo);
			abort();
	}

	ipf_intr++;

	return;
}

static char *
uint32dup(
		IPFContext	ctx,
		u_int32_t	n
		)
{
	char			nbuf[10];
	int			len;
	char			*ret;

	nbuf[sizeof(nbuf)-1] = '\0';
	len = snprintf(nbuf,sizeof(nbuf)-1,"%llu",(unsigned long long)n);
	if((len < 0) || ((unsigned)len >= sizeof(nbuf))){
		IPFError(ctx,IPFErrFATAL,errno,"snprintf(): %M");
		exit(IPF_CNTRL_FAILURE);
	}

	if((ret = strdup(nbuf)))
		return ret;

	IPFError(ctx,IPFErrFATAL,errno,"strdup(): %M");
	exit(IPF_CNTRL_FAILURE);
}

/*
 * This function redirects stdout to the tmpfile that was created
 * to hold the result, and then waits until it should fire off
 * the test - and then exec's.
 */
static void
run_iperf(
		IPFEndpoint	ep
		)
{
	IPFTestSession		tsess = ep->tsess;
	IPFContext		ctx = tsess->cntrl->ctx;
	int			outfd = fileno(ep->tsess->localfp);
	int			nullfd;
	struct sigaction	act;
	IPFTimeStamp		currtime;
	IPFNum64		reltime;
	struct timespec		ts_sleep;
	struct timespec		ts_remain;
	int			a = 0;
	char			hostname[MAXHOSTNAMELEN];
	size_t			hlen = sizeof(hostname);
	char			*ipargs[_IPF_MAX_IPERFARGS*2];
	char			*iperf = (char*)IPFContextConfigGet(ctx,
								IPFIperfCmd);

	/*
	 * First figure out the args for iperf
	 */
	if(!iperf) iperf = _IPF_IPERF_CMD;
	ipargs[a++] = iperf;

	ipargs[a++] = "-f";
	ipargs[a++] = "b";

	ipargs[a++] = "-l";
	ipargs[a++] = uint32dup(ctx,tsess->test_spec.len_buffer);

	ipargs[a++] = "-m";

	ipargs[a++] = "-p";
	ipargs[a++] = uint32dup(ctx,tsess->recv_port);

	if(tsess->test_spec.udp){
		ipargs[a++] = "-u";
	}

	ipargs[a++] = "-w";
	ipargs[a++] = uint32dup(ctx,tsess->test_spec.window_size);

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

	if(tsess->conf_receiver){
		IPFAddrNodeName(tsess->test_spec.receiver,hostname,&hlen);
		if(!hlen){
			exit(IPF_CNTRL_FAILURE);
		}
		ipargs[a++] = "-B";
		ipargs[a++] = hostname;

		ipargs[a++] = "-s";
	}
	else{
		IPFAddrNodeName(tsess->test_spec.sender,hostname,&hlen);
		if(!hlen){
			exit(IPF_CNTRL_FAILURE);
		}

		ipargs[a++] = "-c";
		ipargs[a++] = hostname;
	}

	ipargs[a++] = NULL;

	/*
	 * Reset ignored signals to default
	 * (exec will reset set signals to default)
	 */
	memset(&act,0,sizeof(act));
	act.sa_handler = SIG_DFL;
	sigemptyset(&act.sa_mask);
	if(sigaction(SIGPIPE,&act,NULL) != 0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"sigaction(): %M");
		exit(IPF_CNTRL_FAILURE);
	}

	/*
	 * Open /dev/null to dup to stdin before the exec.
	 */
	if( (nullfd = open(_IPF_DEV_NULL,O_RDONLY)) < 0){
		IPFError(ctx,IPFErrFATAL,errno,"open(/dev/null): %M");
		exit(IPF_CNTRL_FAILURE);
	}

	if(		(dup2(nullfd,STDIN_FILENO) < 0) ||
			(dup2(outfd,STDOUT_FILENO) < 0) ||
			(dup2(outfd,STDERR_FILENO) < 0)){
		IPFError(ctx,IPFErrFATAL,errno,"dup2(): %M");
		exit(IPF_CNTRL_FAILURE);
	}

	/*
	 * Compute the time until the test should start.
	 */
	if(!IPFGetTimeStamp(ctx,&currtime)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"IPFGetTimeStamp(): %M");
		exit(IPF_CNTRL_FAILURE);
	}
	if(ipf_term) exit(IPF_CNTRL_FAILURE);

	if(IPFNum64Cmp(tsess->reserve_time,currtime.ipftime) < 0){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"run_iperf(): Too LATE!");
		exit(IPF_CNTRL_FAILURE);
	}

	reltime = IPFNum64Sub(tsess->reserve_time,currtime.ipftime);

	/*
	 * Use the error estimates rounded up to 1 second, and start the
	 * recv side that much before the test time.
	 */
	if(tsess->conf_receiver){
		if(IPFNum64Cmp(reltime,tsess->fuzz) > 0){
			reltime = IPFNum64Sub(reltime,tsess->fuzz);
		}
		else{
			reltime = IPFULongToNum64(0);
		}
	}

	timespecclear(&ts_sleep);
	timespecclear(&ts_remain);
	IPFNum64ToTimespec(&ts_sleep,reltime);

	while(timespecisset(&ts_sleep)){
		if(nanosleep(&ts_sleep,&ts_remain) == 0){
			break;
		}
		if(ipf_term) exit(IPF_CNTRL_FAILURE);
		ts_sleep = ts_remain;
	}

	/*
	 * Now run iperf!
	 */
	execv(iperf,ipargs);

	IPFError(ctx,IPFErrFATAL,errno,"execv(): %M");
	exit(IPF_CNTRL_FAILURE);
}

IPFBoolean
_IPFEndpointStart(
	IPFTestSession	tsess,
	u_int16_t	*dataport,
	IPFErrSeverity	*err_ret
	)
{
	IPFContext		ctx = tsess->cntrl->ctx;
	IPFEndpoint		ep;
	IPFGetAESKeyFunc	getaeskey = getsidaeskey;
	sigset_t		sigs;
	sigset_t		osigs;
	struct sigaction	act;
	IPFTimeStamp		currtime;
	IPFNum64		reltime;
	struct itimerval	itval;
	IPFAcceptType		aval;
	int			wstatus;

	if( !(tsess->localfp = tfile(tsess)) ||
					!(tsess->remotefp = tfile(tsess))){
		return False;
	}

	if( !(ep=EndpointAlloc(tsess))){
		return False;
	}

	if(tsess->conf_receiver &&
			((ep->ssockfd = epssock(tsess,dataport)) < 0)){
		EndpointFree(ep);
		return False;
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
		IPFError(ctx,IPFErrFATAL,errno,"sigprocmask(): %M");
		EndpointFree(ep);
		return False;
	}
	tsess->endpoint = ep;

	ep->child = fork();

	if(ep->child < 0){
		int	serr = errno;
		/* fork error */
		(void)sigprocmask(SIG_SETMASK,&osigs,NULL);
		IPFError(ctx,IPFErrFATAL,serr,"fork(): %M");
		EndpointFree(ep);
		tsess->endpoint = NULL;
		return False;
	}

	if(ep->child > 0){
		/* parent */
		int	cstatus;

		if(sigprocmask(SIG_BLOCK,&osigs,NULL) != 0){
			IPFError(ctx,IPFErrFATAL,errno,"sigprocmask(): %M");
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
		 * close the remotefp - this process no longer needs it.
		 * keep localfp so the test results can be sent to client.
		 */
		fclose(tsess->remotefp);
		tsess->remotefp = NULL;

		return True;
	}

	/* child */

#ifndef	NDEBUG
	/*
	 * busy loop to wait for debugger attachment
	 */
	{
		int	waitfor = (int)IPFContextConfigGet(ctx,IPFChildWait);

		while(waitfor);
	}
#endif

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
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"sigaction(): %M");
		exit(IPF_CNTRL_FAILURE);
	}

	if(sigprocmask(SIG_BLOCK,&osigs,NULL) != 0){
		IPFError(ctx,IPFErrFATAL,errno,"sigprocmask(): %M");
		exit(IPF_CNTRL_FAILURE);
	}

	if(ipf_term){
		exit(IPF_CNTRL_FAILURE);
	}

	/*
	 * Now fork again. The child will go on to "exec" iperf at the
	 * appropriate time. The parent will open a connection to the other
	 * endpoint for the test results exchange.
	 */
	ep->child = fork();

	if(ep->child < 0){
		/* fork error */
		IPFError(ctx,IPFErrFATAL,errno,"fork(): %M");
		exit(IPF_CNTRL_FAILURE);
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
	if(		!IPFContextConfigSet(ctx,IPFGetAESKey,
							(void*)getaeskey) ||
			!IPFContextConfigSet(ctx,_IPFGetSIDAESKEY,
							(void*)tsess->sid)
			){
		IPFError(ctx,IPFErrFATAL,errno,
				"Unable to setup SID for endpoint: %M");
		goto end;
	}

	/*
	 * Set a timer - if we have not established a connection with
	 * the remote endpoint before the time the test should start,
	 * exit.
	 */
	if(!IPFGetTimeStamp(ctx,&currtime)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"IPFGetTimeStamp(): %M");
		goto end;
	}

	if(IPFNum64Cmp(tsess->reserve_time,currtime.ipftime) < 0){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"endpoint to endpoint setup too late");
		goto end;
	}

	reltime = IPFNum64Sub(tsess->reserve_time,currtime.ipftime);

	memset(&itval,0,sizeof(itval));
	IPFNum64ToTimeval(&itval.it_value,reltime);
	if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
		IPFError(ctx,IPFErrFATAL,errno,"setitimer(): %M");
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
		if(ipf_term)
			goto end;

		if(connfd < 0){
			if(errno == EINTR && !ipf_term){
				goto ACCEPT;
			}
			IPFError(ctx,IPFErrFATAL,errno,
					"Unable to connect endpoint cntrl: %M");
			goto end;
		}

		/*
		 * Only allow connections from the remote testaddr
		 */
		if(I2SockAddrEqual(tsess->cntrl->remote_addr->saddr,
					tsess->cntrl->remote_addr->saddrlen,
					(struct sockaddr *)&sbuff,sbuff_len,
					I2SADDR_ADDR) <= 0){
			IPFError(ctx,IPFErrFATAL,IPFErrPOLICY,
					"Connect from invalid addr");
			while((close(connfd) != 0) && (errno == EINTR));
			goto ACCEPT;
		}

		close(ep->ssockfd);
		ep->ssockfd = -1;

		ep->rcntrl = IPFControlAccept(ctx,connfd,
				(struct sockaddr *)&sbuff,sbuff_len,
				tsess->cntrl->mode,currtime.ipftime,
				&ipf_term,err_ret);
	}
	else{
		ep->rcntrl = IPFControlOpen(ctx,
				IPFAddrByLocalControl(tsess->cntrl),
				_IPFAddrCopy(tsess->cntrl->remote_addr),
				tsess->cntrl->mode,
				"endpoint",
				NULL,
				err_ret);
	}
	if(!ep->rcntrl)
		goto end;
	if(ipf_term)
		goto end;

	/*
	 * Now that we have established communication, reset the timer
	 * for just past the end of the test period. (one second past)
	 */
	if(!IPFGetTimeStamp(ctx,&currtime)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"IPFGetTimeStamp(): %M");
		goto end;
	}

	if(IPFNum64Cmp(tsess->reserve_time,currtime.ipftime) < 0){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"endpoint to endpoint setup too late");
		goto end;
	}

	reltime = IPFNum64Sub(tsess->reserve_time,currtime.ipftime);
	reltime = IPFNum64Add(reltime,
			IPFULongToNum64(tsess->test_spec.duration + 1));

	memset(&itval,0,sizeof(itval));
	IPFNum64ToTimeval(&itval.it_value,reltime);
	if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
		IPFError(ctx,IPFErrFATAL,errno,"setitimer(): %M");
		goto end;
	}

	if(ipf_term)
		goto end;

	/*
	 * Fake lcntrl socket into "test" mode and set it up with the
	 * same tsess record as the parent process.
	 * Then wait for StopSession to trade results.
	 */
	ep->rcntrl->tests = tsess;
	ep->rcntrl->state |= _IPFStateTest;
	
wait:
	wstatus = IPFStopSessionWait(ep->rcntrl,NULL,&ipf_term,&aval,err_ret);

	if(wstatus == 0)
		exit(aval);

	if((wstatus > 0) && !ipf_term)
		goto wait;

end:

	if(ep->child > 0){
		int	cstatus;

		kill(ep->child,SIGINT);
		ep->wopts &= ~WNOHANG;
		while((waitpid(ep->child,&cstatus,ep->wopts) < 0) &&
				(errno == EINTR));
	}
	exit(IPF_CNTRL_FAILURE);
}

IPFBoolean
_IPFEndpointStatus(
	IPFTestSession	tsess,
	IPFAcceptType	*aval,		/* out */
	IPFErrSeverity	*err_ret
	)
{
	pid_t			p;
	int			childstatus;
	IPFEndpoint		ep = tsess->endpoint;

	if(!ep)
		return True;

	if(ep->acceptval < 0){
AGAIN:
		p = waitpid(ep->child,&childstatus,ep->wopts);
		if(p < 0){
			if(errno == EINTR)
				goto AGAIN;
			IPFError(ep->cntrl->ctx,IPFErrWARNING,
				IPFErrUNKNOWN,
				"_IPFEndpointStatus:Can't query child #%d: %M",
				ep->child);
			ep->acceptval = IPF_CNTRL_FAILURE;
			*err_ret = IPFErrWARNING;
			return False;
		}
		else if(p > 0)
		       ep->acceptval = (IPFAcceptType)WEXITSTATUS(childstatus);
	}

	*err_ret = IPFErrOK;
	*aval = ep->acceptval;
	return True;
}


IPFBoolean
_IPFEndpointStop(
	IPFTestSession	tsess,
	IPFAcceptType	aval,
	IPFErrSeverity	*err_ret
	)
{
	int		teststatus;
	IPFBoolean	retval;
	IPFEndpoint	ep = tsess->endpoint;

	if(!ep)
		return True;

	if((ep->acceptval >= 0) || (ep->child == 0)){
		*err_ret = IPFErrOK;
		goto done;
	}

	*err_ret = IPFErrFATAL;

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
	retval = _IPFEndpointStatus(tsess,&teststatus,err_ret);
	if(teststatus >= 0)
		goto done;

error:
	IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"EndpointStop:Can't signal child #%d: %M",ep->child);
done:
	if(aval < ep->acceptval){
		aval = ep->acceptval;
	}
	ep->tsess->endpoint = NULL;
	EndpointFree(ep);

	return retval;
}
