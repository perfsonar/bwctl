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
#include <signal.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "ipcntrlP.h"

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

	localaddr = (tsess->conf_sender)?
			tsess->test_spec.sender: tsess->test_spec.receiver;

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
				"setsockopt(SO_REUSEADDR): %M");
		goto failsock;
	}
#endif

	if(bind(fd,localaddr->ai->ai_addr,localaddr->ai->ai_addrlen) != 0){
		IPFError(tsess->cntrl->ctx,IPFErrFATAL,errno,"bind(): %M");
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
			*dataport = saddr6->sin6_port;
			break;
#endif
		case AF_INET:
			saddr4 = (struct sockaddr_in *)saddr;
			*dataport = saddr4->sin_port;
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

IPFBoolean
_IPFEndpointStart(
	IPFTestSession	tsess,
	u_int16_t	*dataport,
	IPFErrSeverity	*err_ret
	)
{
	IPFContext		ctx = tsess->cntrl->ctx;
	IPFEndpoint		ep;
	char			fname[PATH_MAX+1];
	IPFGetAESKeyFunc	getaeskey = getsidaeskey;
	sigset_t		sigs;
	sigset_t		osigs;

	if( !(tsess->localfp = tfile(tsess)) ||
			!(tsess->remotefp = tfile(tsess))){
		return False;
	}

	if( !(ep=EndpointAlloc(tsess))){
		return False;
	}

	if(tsess->conf_sender){
		if( (ep->ssockfd = epssock(tsess,dataport)) < 0){
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

	if(sigprocmask(SIG_BLOCK,&sigs,&osigs) != 0){
		IPFError(ctx,IPFErrFATAL,errno,"sigprocmask(): %M");
		EndpointFree(ep);
		return False;
	}

	ep->child = fork();

	if(ep->child < 0){
		int	serr = errno;
		/* fork error */
		(void)sigprocmask(SIG_SETMASK,&osigs,NULL);
		IPFError(ctx,IPFErrFATAL,serr,"fork(): %M");
		EndpointFree(ep);
		return False;
	}

	if(ep->child > 0){
		/* parent */
		int	cstatus;

		if(sigprocmask(SIG_BLOCK,&sigs,&osigs) != 0){
			IPFError(ctx,IPFErrFATAL,errno,"sigprocmask(): %M");
			kill(ep->child,SIGINT);
			ep->wopts &= ~WNOHANG;
			while((waitpid(ep->child,&cstatus,ep->wopts) < 0) &&
					(errno == EINTR));
			EndpointFree(ep);
			return False;
		}

		EndpointClear(ep);
		return True;
	}

	/* child */

#if	NOT
	HERE

	ep->rcntrl = IPFControlOpen(ctx,
				IPFAddrByLocalControl(tsess->cntrl),
				_IPFAddrCopy(tsess->cntrl->remote_addr),
				tsess->cntrl->mode,
				"endpoint",
				NULL,
				err_ret);
				}
#else
	return False;
#endif
}

IPFBoolean
_IPFEndpointStatus(
	IPFTestSession	tsess,
	IPFAcceptType	*aval,		/* out */
	IPFErrSeverity	*err_ret
	)
{
#if	NOT
	pid_t			p;
	int			childstatus;

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
#else
	return False;
#endif
}


IPFBoolean
_IPFEndpointStop(
	IPFTestSession	tsess,
	IPFAcceptType	aval,
	IPFErrSeverity	*err_ret
	)
{
#if	NOT
	int		sig;
	int		teststatus;
	IPFBoolean	retval;

	/*
	 * TODO: v6 This function should "retrieve" the last seq_no/or
	 * num_packets sent. From the child and it should take as an arg
	 * the last_seq from the other side if it is available to send
	 * to the endpoint if needed.
	 */

	if((ep->acceptval >= 0) || (ep->child == 0)){
		*err_ret = IPFErrOK;
		goto done;
	}

	*err_ret = IPFErrFATAL;

	if(aval)
		sig = SIGINT;
	else
		sig = SIGUSR2;

	/*
	 * If child already exited, kill will come back with ESRCH
	 */
	if((kill(ep->child,sig) != 0) && (errno != ESRCH))
		goto error;

	/*
	 * Remove the WNOHANG bit. We need to wait until the exit status
	 * is available.
	 * (Should we add a timer to break out? No - not that paranoid yet.)
	 */
	ep->wopts &= ~WNOHANG;
	retval = _IPFEndpointStatus(ep,&teststatus,err_ret);
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
	EndpointFree(ep,aval);

	return retval;
#else
	return False;
#endif
}
