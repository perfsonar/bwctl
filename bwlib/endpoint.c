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

#if	NOT
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
	IPFControl	cntrl
	)
{
	IPFEndpoint	ep = calloc(1,sizeof(IPFEndpointRec));

	if(!ep){
		IPFError(cntrl->ctx,IPFErrFATAL,errno,"malloc(EndpointRec)");
		return NULL;
	}

	ep->cntrl = cntrl;
	ep->sockfd = -1;
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

	if(ep->sockfd > -1){
		close(ep->sockfd);
		ep->sockfd = -1;
	}
	if(ep->datafile){
		fclose(ep->datafile);
		ep->datafile = NULL;
	}
	if(ep->fbuff){
		free(ep->fbuff);
		ep->fbuff = NULL;
	}

	if(ep->payload){
		free(ep->payload);
		ep->payload = NULL;
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
	IPFEndpoint	ep,
	IPFAcceptType	aval
	)
{
	if(!ep)
		return;

	EndpointClear(ep);

	if(ep->userfile){
		_IPFCallCloseFile(ep->cntrl,ep->tsession->closure,ep->userfile,
									aval);
		ep->userfile = NULL;
	}

	free(ep);

	return;
}

/*
 * Function:	reopen_datafile
 *
 * Description:	
 * 	This function takes a fp and creates a new fp to the same file
 * 	record. This is used to ensure that the fp used for the actual
 * 	test is buffered properly. And - allows the test to write to the
 * 	same file without modifying a fp passed in by an application.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static FILE*
reopen_datafile(
		IPFContext	ctx,
		FILE		*infp
		)
{
	int	newfd;
	FILE	*fp;

	if( (newfd = dup(fileno(infp))) < 0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"dup(%d): %M",
							fileno(infp));
		return NULL;
	}

	if( !(fp = fdopen(newfd,"wb"))){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN, "fdopen(%d): %M",newfd);
		return NULL;
	}

	return fp;
}

/*
 * Function:	CmpLostPacket
 *
 * Description:	
 * 	Used to compare the 64 bit keys for the IPFLostPacket records.
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
CmpLostPacket(
	I2Datum	x,
	I2Datum	y
	)
{
	u_int64_t	*xn = (u_int64_t*)x.dptr;
	u_int64_t	*yn = (u_int64_t*)y.dptr;

	return !(*xn == *yn);
}

/*
 * Function:	HashLostPacket
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
u_int32_t
HashLostPacket(
	I2Datum	k
	)
{
	u_int64_t	*kn = (u_int64_t*)k.dptr;

	return *kn & 0xFFFFFFFFUL;
}
#endif

/*
 * The endpoint init function is responsible for opening a socket, and
 * allocating a local port number.
 * If this is a recv endpoint, it is also responsible for allocating a
 * session id.
 */
#if	NOT
IPFBoolean
_IPFEndpointInit(
	IPFControl	cntrl,
	IPFTestSession	tsession,
	IPFErrSeverity	*err_ret
)
{
	struct sockaddr_storage	sbuff;
	socklen_t		sbuff_len=sizeof(sbuff);
	IPFEndpoint		ep;
	IPFPacketSizeT		tpsize;
	int			sbuf_size;
	int			sopt;
	socklen_t		opt_size;
	u_int64_t		i;
	IPFTimeStamp		tstamp;

	*err_ret = IPFErrFATAL;

	if( !(ep=EndpointAlloc(cntrl)))
		return False;

	ep->send = (localaddr == tsession->sender);

	ep->tsession = tsession;
	ep->cntrl = cntrl;

	tpsize = IPFTestPacketSize(localaddr->saddr->sa_family,
		ep->cntrl->mode,tsession->test_spec.packet_size_padding);
	tpsize += 128;	/* Add fuzz space for IP "options" */
	sbuf_size = tpsize;
	if((IPFPacketSizeT)sbuf_size != tpsize){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"Packet size overflow - invalid padding");
		goto error;
	}

	ep->len_payload = IPFTestPayloadSize(ep->cntrl->mode,
				ep->tsession->test_spec.packet_size_padding);
	if(ep->len_payload < _IPF_TESTREC_SIZE){
		ep->len_payload = _IPF_TESTREC_SIZE;
	}
	ep->payload = malloc(ep->len_payload);

	if(!ep->payload){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,"malloc(): %M");
		goto error;
	}

	tstamp.ipftime = ep->tsession->test_spec.start_time;
	(void)IPFTimestampToTimespec(&ep->start,&tstamp);

	/*
	 * Create the socket.
	 */
	ep->sockfd = socket(localaddr->saddr->sa_family,localaddr->so_type,
						localaddr->so_protocol);
	if(ep->sockfd<0){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,"socket(): %M");
		goto error;
	}

	/*
	 * bind it to the local address getting an ephemeral port number.
	 */
	if(bind(ep->sockfd,localaddr->saddr,localaddr->saddrlen) != 0){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"bind([%s]:%s): %M",localaddr->node,localaddr->port);
		goto error;
	}

	/*
	 * Retrieve the ephemeral port picked by the system.
	 */
	memset(&sbuff,0,sizeof(sbuff));
	if(getsockname(ep->sockfd,(void*)&sbuff,&sbuff_len) != 0){
		IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,"getsockname(): %M");
		goto error;
	}

	/*
	 * set saddr to the sockaddr that was actually used.
	 * (This sets the port in saddr as well.)
	 */
	assert(localaddr->saddrlen >= sbuff_len);
	memcpy(localaddr->saddr,&sbuff,sbuff_len);

	/*
	 * If we are receiver, sid is valid and we need to open file.
	 */
	if(!ep->send){
		size_t		size;
		struct stat	statbuf;
		IPFLostPacket	alist;

		/*
		 * pre-allocate nodes for lost_packet buffer.
		 * (estimate number of nodes needed to hold enough
		 * packets for 2*Loss-timeout)
		 * TODO: determine a reasonable number instead of (2).
		 * (2 is just a guess... exp distribution probably
		 * converges to 0 fast enough that we could get away
		 * with a much smaller number... say 1.2)
		 *
		 * It is possible that the actual distribution will make
		 * it necessary to hold more than this many nodes in the
		 * buffer - but it is highly unlikely. If that happens,
		 * another dynamic allocation will happen. This should
		 * at least minimize the dynamic allocations during the
		 * test.
		 */
#define PACKBUFFALLOCFACTOR	2

		ep->freelist=NULL;
		ep->numalist = IPFTestPacketRate(cntrl->ctx,
						&tsession->test_spec) *
				IPFNum64ToDouble(
					tsession->test_spec.loss_timeout) *
				PACKBUFFALLOCFACTOR;
		ep->numalist = MAX(ep->numalist,100);

		if(!(alist = calloc(sizeof(IPFLostPacketRec),ep->numalist))){
			IPFError(cntrl->ctx,IPFErrFATAL,errno,"calloc(): %M");
			goto error;
		}

		for(i=0;i<ep->numalist;i++){
			alist[i].next = ep->freelist;
			ep->freelist = &alist[i];
		}


		if(!(ep->lost_packet_buffer = I2HashInit(cntrl->ctx->eh,
					ep->numalist*PACKBUFFALLOCFACTOR,
					CmpLostPacket,HashLostPacket))){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
		"_IPFEndpointInit: Unable to initialize lost packet buffer");
			goto error;
		}

		ep->fname[0] = '\0';
		if(!fp){
			ep->userfile = fp = _IPFCallOpenFile(cntrl,
						tsession->closure,
						tsession->sid,
						ep->fname);
		}

		if(!fp){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Unable to open session file(%s): %M",
						ep->fname);
			goto error;
		}

		/*
		 * This function dup's the fd/fp so that any seeks on
		 * the fd in the parent do not effect the child reference.
		 * (It also ensures that no file i/o have happened on the
		 * ep->datafile which makes it much more likely that the
		 * call to setvbuf will work...)
		 */
		if( !(ep->datafile = reopen_datafile(cntrl->ctx,fp))){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Unable to re-open session file(%s): %M",
						ep->fname);
			goto error;
		}

		/*
		 * Determine "optimal" file buffer size. To allow "Fetch"
		 * clients to access ongoing tests - we define "optimal" as
		 * approximately 1 second of buffering. (Or 1 record - whichever
		 * takes longer.)
		 */

		/* stat to find out st_blksize */
		if(fstat(fileno(ep->datafile),&statbuf) != 0){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"fstat(): %M");
			goto error;
		}

		/*
		 * Determine data rate. i.e. size/second.
		 */
		size = IPFTestPacketRate(cntrl->ctx,&ep->tsession->test_spec) *
							_IPF_TESTREC_SIZE;

		/*
		 * Don't make buffer larger than "default"
		 */
		size = MIN(size,statbuf.st_blksize);

		/*
		 * buffer needs to be at least as large as one record.
		 */
		if(size < _IPF_TESTREC_SIZE){
			size = _IPF_TESTREC_SIZE;
		}
		if( !(ep->fbuff = malloc(size))){
			IPFError(cntrl->ctx,IPFErrFATAL,errno,"malloc(): %M");
			goto error;
		}
		setvbuf(ep->datafile,ep->fbuff,_IOFBF,size);

		/*
		 * receiver - need to set the recv buffer size large
		 * enough for the packet, so we can get it in a single
		 * recv.
		 */
		opt_size = sizeof(sopt);
		if(getsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
					(void*)&sopt,&opt_size) < 0){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"getsockopt(RCVBUF): %M");
			goto error;
		}

		if(sopt < sbuf_size){
			sopt = sbuf_size;
			if(setsockopt(ep->sockfd,SOL_SOCKET,SO_RCVBUF,
				 (void*)&sopt,sizeof(sopt)) < 0){
				IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"setsockopt(RCVBUF=%d): %M",sopt);
				goto error;
			}
		}

	}
	else{
		/*
		 * We are sender - need to set sockopt's to ensure we don't
		 * fragment our test packets in the socket api.
		 */

		opt_size = sizeof(sopt);
		if(getsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
					(void*)&sopt,&opt_size) < 0){
			IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"getsockopt(SNDBUF): %M");
			goto error;
		}

		if(sopt < sbuf_size){
			sopt = sbuf_size;
			if(setsockopt(ep->sockfd,SOL_SOCKET,SO_SNDBUF,
				 (void*)&sopt,sizeof(sopt)) < 0){
				IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
						"setsockopt(RCVBUF=%d): %M",
						sopt);
				goto error;
			}
		}

		/*
		 * Use Type-P to set DSCP
		 * (This is currently the only Type-P currently supported by
		 * this implementation.)
		 *
		 * TODO: Verify this works! (I am highly suspicious of using
		 * IP_TOS for IPv6... I have seen IP_CLASS as a possible
		 * replacement...)
		 */
		if(ep->tsession->test_spec.typeP &&
				!(ep->tsession->test_spec.typeP & ~0x3F)){
			int	optname = IP_TOS;
			int	optlevel = IP_TOS;
			switch(localaddr->saddr->sa_family){
			case AF_INET:
				optlevel = IPPROTO_IP;
				optname = IP_TOS;
				break;
#ifdef	AF_INET6
			case AF_INET6:
				optlevel = IPPROTO_IPV6;
				optname = IP_TOS;
				break;
#endif
			default:
				/*NOTREACHED*/
				break;
			}

			sopt = ep->tsession->test_spec.typeP << 2;
			if(setsockopt(ep->sockfd,optlevel,optname,
					 (void*)&sopt,sizeof(sopt)) < 0){
				IPFError(cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"setsockopt(%s,%s=%d): %M",
					((optlevel==IPPROTO_IP)?
					 	"IPPROTO_IP":"IPPROTO_IPV6"),
					((optname==IP_TOS)?"IP_TOS":"IP_CLASS"),
					sopt);
				goto error;
			}
		}
	}

	tsession->endpoint = ep;
	*err_ret = IPFErrOK;
	return True;

error:
	EndpointFree(ep,IPF_CNTRL_FAILURE);
	return False;
}

static int owp_usr1;
static int owp_usr2;
static int owp_int;

/*
 * This sighandler is used to ensure SIGCHLD events are sent to this process.
 */
static void
sig_nothing(
	int	signo
	)
{
	switch(signo){
		case SIGCHLD:
			break;
		default:
			IPFError(NULL,IPFErrFATAL,IPFErrUNKNOWN,
				       "sig_nothing:Invalid signal(%d)",signo);
			exit(IPF_CNTRL_FAILURE);
	}
	return;
}

static void
sig_catch(
	int	signo
	)
{
	switch(signo){
		case SIGUSR1:
			owp_usr1 = 1;
			break;
		case SIGUSR2:
			owp_usr2 = 1;
			break;
		case SIGINT:
			owp_int = 1;
			break;
		case SIGALRM:
			break;
		default:
			IPFError(NULL,IPFErrFATAL,IPFErrUNKNOWN,
					"sig_catch:Invalid signal(%d)",signo);
			_exit(IPF_CNTRL_FAILURE);
	}

	return;
}

/*
 * Function:	run_sender
 *
 * Description:	
 * 		This function is the main processing function for a "sender"
 * 		sub-process.
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
run_sender(
		IPFEndpoint	ep
		)
{
	u_int32_t	i;
	struct timespec	currtime;
	struct timespec	nexttime;
	struct timespec	sleeptime;
	u_int32_t	esterror;
	u_int32_t	lasterror=0;
	int		sync;
	ssize_t		sent;
	u_int32_t	*seq;
	u_int8_t	clr_buffer[32];
	u_int8_t	zeroiv[16];
	u_int8_t	*payload;
	u_int8_t	*tstamp;
	u_int8_t	*tstamperr;
	IPFTimeStamp	owptstamp;
	IPFNum64	nextoffset;

	/*
	 * Initialize pointers to various positions in the packet buffer,
	 * for data that changes for each packet. Also set zero padding.
	 */
	switch(ep->cntrl->mode){
		case IPF_MODE_OPEN:
			seq = (u_int32_t*)&ep->payload[0];
			tstamp = &ep->payload[4];
			tstamperr = &ep->payload[12];
			payload = &ep->payload[14];
			break;
		case IPF_MODE_AUTHENTICATED:
			seq = (u_int32_t*)&clr_buffer[0];
			tstamp = &ep->payload[16];
			tstamperr = &ep->payload[24];
			payload = &ep->payload[32];
			memset(clr_buffer,0,32);
			break;
		case IPF_MODE_ENCRYPTED:
			seq = (u_int32_t*)&clr_buffer[0];
			tstamp = &clr_buffer[16];
			tstamperr = &clr_buffer[24];
			payload = &ep->payload[32];
			memset(clr_buffer,0,32);
			memset(zeroiv,0,16);
			break;
		default:
			/*
			 * things would have failed way earlier
			 * but put default in to stop annoying
			 * compiler warnings...
			 */
			exit(IPF_CNTRL_FAILURE);
	}

	/*
	 * set random bits.
	 */
#if	defined(IPF_ZERO_TEST_PAYLOAD)
	memset(payload,0,ep->tsession->test_spec.packet_size_padding);
#elif	!defined(IPF_VARY_TEST_PAYLOAD)
	/*
	 * Ignore errors here - it isn't that critical that it be random.
	 * (just trying to defeat modem compression and the like.)
	 */
	(void)I2RandomBytes(ep->cntrl->ctx->rand_src,payload,
			    ep->tsession->test_spec.packet_size_padding);
#endif

	/*
	 * initialize nextoffset (running sum of next sendtime relative to
	 * start.
	 */
	nextoffset = IPFULongToNum64(0);
	i=0;
	/*
	 * Ensure schedule generation is starting at first packet in
	 * series.
	 */
	if(IPFScheduleContextReset(ep->tsession->sctx,NULL,NULL) != IPFErrOK){
		IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"ScheduleContextReset FAILED!");
		exit(IPF_CNTRL_FAILURE);
	}

	do{
		/*
		 * First setup "this" packet.
		 */
#if	defined(IPF_VARY_TEST_PAYLOAD) && !defined(IPF_ZERO_TEST_PAYLOAD)
		(void)I2RandomBytes(ep->cntrl->ctx->rand_src,payload,
			    ep->tsession->test_spec.packet_size_padding);
#endif
		nextoffset = IPFNum64Add(nextoffset,
			IPFScheduleContextGenerateNextDelta(
							ep->tsession->sctx));
		IPFNum64ToTimespec(&nexttime,nextoffset);
		timespecadd(&nexttime,&ep->start);
		*seq = htonl(i);

		/*
		 * Encrypt first block. (for MODE_AUTH we are done with AES -
		 * for MODE_ENCRYPT we will need to CBC the second block.
		 */
		if(ep->cntrl->mode & IPF_MODE_DOCIPHER){
			rijndaelEncrypt(ep->cntrl->encrypt_key.rk,
						ep->cntrl->encrypt_key.Nr,
						&clr_buffer[0],&ep->payload[0]);
			memset(&clr_buffer[16],0,16);
		}

AGAIN:
		if(owp_int){
			exit(IPF_CNTRL_FAILURE);
		}
		if(owp_usr2){
			/*
			 * TODO: v6 - send (i-1) to control process
			 * for inclusion in StopSessions message...
			 */
			exit(IPF_CNTRL_ACCEPT);
		}

		if(!_IPFGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Problem retrieving time");
			exit(IPF_CNTRL_FAILURE);
		}

		if(timespeccmp(&currtime,&nexttime,>)){
			/* send-packet */

			(void)IPFTimespecToTimestamp(&owptstamp,&currtime,
						       &esterror,&lasterror);
			lasterror = esterror;
			owptstamp.sync = sync;
			_IPFEncodeTimeStamp(tstamp,&owptstamp);
			if(!_IPFEncodeTimeStampErrEstimate(tstamperr,
								&owptstamp)){
				IPFError(ep->cntrl->ctx,IPFErrFATAL,
						IPFErrUNKNOWN,
						"Invalid Timestamp Error");
				owptstamp.multiplier = 0xFF;
				owptstamp.scale = 0x3F;
				owptstamp.sync = 0;
				(void)_IPFEncodeTimeStampErrEstimate(tstamperr,
								   &owptstamp);
			}

			/*
			 * For ENCRYPTED mode, we have to encrypt the second
			 * block after fetching the timestamp. (CBC mode)
			 */
			if(ep->cntrl->mode == IPF_MODE_ENCRYPTED){
				/*
				 * For now - do CBC mode directly here.
				 * TODO: remove AES hacks in local copy of
				 * AES code - use "standard" version. This
				 * becomes easier. (IPFSendBlocks becomes more
				 * involved...)
				 */
				((u_int32_t*)clr_buffer)[4] =
		((u_int32_t*)clr_buffer)[4] ^ ((u_int32_t*)&ep->payload)[0];
				((u_int32_t*)clr_buffer)[5] =
		((u_int32_t*)clr_buffer)[5] ^ ((u_int32_t*)&ep->payload)[1];
				((u_int32_t*)clr_buffer)[6] =
		((u_int32_t*)clr_buffer)[6] ^ ((u_int32_t*)&ep->payload)[2];
				((u_int32_t*)clr_buffer)[7] =
		((u_int32_t*)clr_buffer)[7] ^ ((u_int32_t*)&ep->payload)[3];
				rijndaelEncrypt(ep->cntrl->encrypt_key.rk,
					ep->cntrl->encrypt_key.Nr,
					&clr_buffer[16],&ep->payload[16]);
			}

			if( (sent = sendto(ep->sockfd,ep->payload,
						ep->len_payload,0,
						ep->remoteaddr->saddr,
						ep->remoteaddr->saddrlen)) < 0){
				switch(errno){
					/* retry errors */
					case ENOBUFS:
						goto AGAIN;
						break;
					/* fatal errors */
					case EBADF:
					case EACCES:
					case ENOTSOCK:
					case EFAULT:
					case EAGAIN:
						IPFError(ep->cntrl->ctx,
							IPFErrFATAL,
							IPFErrUNKNOWN,
					"Unable to send([%s]:%s:(#%d): %M",
							ep->remoteaddr->node,
							ep->remoteaddr->port,i);
						exit(IPF_CNTRL_FAILURE);
						break;
					/* ignore everything else */
					default:
						break;
				}

				/* but do note it as INFO for debugging */
				IPFError(ep->cntrl->ctx,IPFErrINFO,
					IPFErrUNKNOWN,
					"Unable to send([%s]:%s:(#%d): %M",
					ep->remoteaddr->node,
					ep->remoteaddr->port,i);
			}

			i++;
		}
		else{
			/*
			 * Sleep until we should send the next packet.
			 */

			sleeptime = nexttime;
			timespecsub(&sleeptime,&currtime);
			if((nanosleep(&sleeptime,NULL) == 0) ||
							(errno == EINTR)){
				goto AGAIN;
			}
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"nanosleep(%u.%u,nil): %M",
					sleeptime.tv_sec,sleeptime.tv_nsec);
			exit(IPF_CNTRL_FAILURE);
		}

	} while(i < ep->tsession->test_spec.npackets);

	/*
	 * Wait until lossthresh after last packet or
	 * for a signal to exit.
	 * (nexttime currently holds the time for the last packet send, so
	 * just add loss_timeout. Round up to the next second since I'm lazy.)
	 */
	nexttime.tv_sec += (int)IPFNum64ToDouble(
					ep->tsession->test_spec.loss_timeout)+1;

	while(!owp_usr2 && !owp_int){
		if(!_IPFGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"Problem retrieving time");
			exit(IPF_CNTRL_FAILURE);
		}

		if(timespeccmp(&nexttime,&currtime,<))
			break;

		sleeptime = nexttime;
		timespecsub(&sleeptime,&currtime);
		if(nanosleep(&sleeptime,NULL) == 0)
			break;
		if(errno != EINTR){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"nanosleep(%u.%u,nil): %M",
					sleeptime.tv_sec,sleeptime.tv_nsec);
			exit(IPF_CNTRL_FAILURE);
		}
	}

	exit(IPF_CNTRL_ACCEPT);
}


static IPFLostPacket
alloc_node(
		IPFEndpoint	ep,
		u_int64_t	seq
		)
{
	IPFLostPacket	node;
	I2Datum		k,v;

	if((seq >= ep->tsession->test_spec.npackets) ||
			(ep->end && (seq <= ep->end->seq))){
		IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid seq number for IPFLostPacket buf");
		return NULL;
	}

	if(!ep->freelist){
		u_int64_t	i;

		IPFError(ep->cntrl->ctx,IPFErrINFO,IPFErrUNKNOWN,
	"get_node: Allocating additional nodes for lost-packet-buffer!");
		if(!(node = calloc(sizeof(IPFLostPacketRec),ep->numalist))){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,errno,
							"calloc(): %M");
			return NULL;
		}

		for(i=0;i<ep->numalist;i++){
			node[i].next = ep->freelist;
			ep->freelist = &node[i];
		}
	}

	node = ep->freelist;
	ep->freelist = ep->freelist->next;

	node->seq = seq;
	node->hit = 0;
	node->next = NULL;

	k.dptr = &node->seq;
	k.dsize = sizeof(node->seq);
	v.dptr = node;
	v.dsize = sizeof(*node);

	if(I2HashStore(ep->lost_packet_buffer,k,v) != 0){
		return NULL;
	}

	return node;
}

static void
free_node(
		IPFEndpoint	ep,
		IPFLostPacket	node
		)
{
	I2Datum	k;

	k.dptr = &node->seq;
	k.dsize = sizeof(node->seq);

	if(I2HashDelete(ep->lost_packet_buffer,k) != 0){
		IPFError(ep->cntrl->ctx,IPFErrWARNING,IPFErrUNKNOWN,
	"I2HashDelete: Unable to remove seq #%llu from lost-packet hash",
			node->seq);
	}

	node->next = ep->freelist;
	ep->freelist = node;

	return;
}

static IPFLostPacket
get_node(
		IPFEndpoint	ep,
		u_int64_t	seq
		)
{
	IPFLostPacket	node;
	I2Datum		k,v;

	/*
	 * optimize for most frequent case.
	 */
	if(seq == ep->end->seq){
		return ep->end;
	}

	/*
	 * Need to build the list from current "end" to this number.
	 */
	if(seq > ep->end->seq){
		node = ep->end;

		while(node->seq < seq){
			IPFTimeStamp	abs;

			node->next = alloc_node(ep,node->seq+1);
			node->next->relative = IPFNum64Add(node->relative,
					IPFScheduleContextGenerateNextDelta(
							ep->tsession->sctx));
			node = node->next;

			abs.ipftime = IPFNum64Add(node->relative,
					ep->tsession->test_spec.start_time);
			(void)IPFTimestampToTimespec(&node->absolute,&abs);
		}

		ep->end = node;

		return node;
	}

	/*
	 * Shouldn't be requesting this seq number... It should already
	 * be loss_timeout in the past.
	 */
	if(seq < ep->begin->seq){
		IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrINVALID,
			"Invalid seq number request");
		return NULL;
	}

	/*
	 * seq requested in within the begin<->end range, just fetch from
	 * hash.
	 */
	k.dptr = &seq;
	k.dsize = sizeof(seq);

	if(!I2HashFetch(ep->lost_packet_buffer,k,&v)){
		IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Unable to fetch from lost-packet-buffer");
		return NULL;
	}

	return (IPFLostPacket)v.dptr;
}

static void
run_receiver(
		IPFEndpoint	ep,
		struct timespec	*signal_time
		)
{
	double			fudge;
	struct timespec		currtime;
	struct timespec		fudgespec;
	struct timespec		lostspec;
	struct timespec		expectspec;
	struct itimerval	wake;
	u_int32_t		seq_num;
	u_int32_t		*seq;
	u_int8_t		*tstamp;
	u_int8_t		*tstamperr;
	u_int8_t		*z1,*z2;
	u_int8_t		zero[12];
	u_int8_t		iv[16];
	u_int8_t		recvbuf[10];
	u_int32_t		esterror,lasterror=0;
	int			sync;
	IPFTimeStamp		sendstamp,recvstamp;
	IPFTimeStamp		expecttime;
	IPFSessionHeaderRec	hdr;
	u_int8_t		lostrec[_IPF_TESTREC_SIZE];
	IPFLostPacket		node;
	int			owp_intr;
	u_int32_t		npackets;
	u_int32_t		finished = _IPF_SESSION_FIN_NORMAL;

	/*
	 * Prepare the file header - had to wait until now so we could
	 * get the real starttime.
	 */
	hdr.header = True;
	hdr.finished = _IPF_SESSION_FIN_ERROR;
	memcpy(&hdr.sid,ep->tsession->sid,sizeof(hdr.sid));
	memcpy(&hdr.addr_sender,ep->tsession->sender->saddr,
					ep->tsession->sender->saddrlen);
	memcpy(&hdr.addr_receiver,ep->tsession->receiver->saddr,
					ep->tsession->receiver->saddrlen);
	hdr.conf_sender = ep->tsession->conf_sender;
	hdr.conf_receiver = ep->tsession->conf_receiver;
	hdr.test_spec = ep->tsession->test_spec;

	/*
	 * update TestReq section to have "real" starttime.
	 */
	(void)IPFTimespecToTimestamp(&expecttime,&ep->start,NULL,NULL);
	hdr.test_spec.start_time =
		ep->tsession->test_spec.start_time = expecttime.ipftime;

	/*
	 * Write the file header.
	 */
	if(IPFWriteDataHeader(ep->cntrl->ctx,ep->datafile,&hdr) != 0){
		exit(IPF_CNTRL_FAILURE);
	}

	/*
	 * Initialize pointers to various positions in the packet buffer.
	 * (useful for the different "modes".)
	 */
	seq = (u_int32_t*)&ep->payload[0];
	switch(ep->cntrl->mode){
		case IPF_MODE_OPEN:
			tstamp = &ep->payload[4];
			tstamperr = &ep->payload[12];
			break;
		case IPF_MODE_ENCRYPTED:
		case IPF_MODE_AUTHENTICATED:
			tstamp = &ep->payload[16];
			tstamperr = &ep->payload[24];
			z1 = &ep->payload[4];	/* 12 octets Zero Integrity */
			z2 = &ep->payload[26];	/* 6 octets Zero Integrity */
			memset(zero,0,sizeof(zero));
			break;
		default:
			/*
			 * things would have failed way earlier
			 * but put default in to stop annoying
			 * compiler warnings...
			 */
			exit(IPF_CNTRL_FAILURE);
	}

	/*
	 * Initialize the buffer we use to report "lost" packets.
	 */
	memset(lostrec,0,_IPF_TESTREC_SIZE);

	/*
	 * Get the "average" packet interval. I will use this
	 * to set the wake up timer to MIN(2*packet_interval,1) past the
	 * time it can be declared lost. (lets call this fudgespec)
	 * With luck, this will allow the next received packet to be the
	 * event that wakes up the process, instead of the timer. However,
	 * I never let this be greater than 1 second so that small
	 * packet rates still produce data at the expected rate.
	 * (This basically sets things up so the recv process will wake up
	 * 1 second past the "end-of-test" to declare it over. In most cases,
	 * the sender will already have sent the StopSession message, so
	 * that event will actually wake the process up instead of the
	 * timer.)
	 */
	fudge = 2.0/IPFTestPacketRate(ep->cntrl->ctx,&ep->tsession->test_spec);
	fudge = MIN(fudge,1.0);
	/* just using expecttime as a temp var here. */
	expecttime.ipftime = IPFDoubleToNum64(fudge);
	IPFNum64ToTimespec(&fudgespec,expecttime.ipftime);

	/*
	 * get a timespec version of loss_timeout
	 */
	IPFNum64ToTimespec(&lostspec,ep->tsession->test_spec.loss_timeout);

	/*
	 * Ensure schedule generation is starting at first packet in
	 * series.
	 */
	if(IPFScheduleContextReset(ep->tsession->sctx,NULL,NULL) != IPFErrOK){
		IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"ScheduleContextReset FAILED!");
		exit(IPF_CNTRL_FAILURE);
	}
	/*
	 * Initialize list with first node
	 */
	ep->begin = ep->end = alloc_node(ep,0);
	if(!ep->begin){
		goto error;
	}
	ep->begin->relative = IPFScheduleContextGenerateNextDelta(
							ep->tsession->sctx);
	/* just using expecttime as a temp var here. */
	expecttime.ipftime = IPFNum64Add(ep->begin->relative,
					ep->tsession->test_spec.start_time);
	(void)IPFTimestampToTimespec(&ep->begin->absolute,&expecttime);

	/*
	 * initialize  currtime to the time we were signaled to start.
	 */
	currtime = *signal_time;

	while(1){
		struct sockaddr_storage	peer_addr;
		socklen_t		peer_addr_len;
again:
		/*
		 * set itimer to go off just past loss_timeout after the time
		 * for the last seq number in the list. Adding "fudge" so we
		 * don't wake up anymore than really necessary.
		 * (With luck, a received packet will actually wake this up,
		 * and not the timer.)
		 */
		tvalclear(&wake.it_value);
		timespecadd((struct timespec*)&wake.it_value,
							&ep->end->absolute);
		timespecadd((struct timespec*)&wake.it_value,&lostspec);
		timespecadd((struct timespec*)&wake.it_value,&fudgespec);
		timespecsub((struct timespec*)&wake.it_value,&currtime);

		wake.it_value.tv_usec /= 1000;	/* convert nsec to usec	*/
		tvalclear(&wake.it_interval);

		/*
		 * Set the timer.
		 */
		owp_intr = 0;
		if(setitimer(ITIMER_REAL,&wake,NULL) != 0){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"setitimer(wake=%d,%d) seq=%llu: %M",
				wake.it_value.tv_sec,wake.it_value.tv_usec,
				ep->end->seq);
			goto error;
		}

		if(owp_int){
			goto error;
		}
		if(owp_usr2){
			goto test_over;
		}

		peer_addr_len = sizeof(peer_addr);
		memset(&peer_addr,0,sizeof(peer_addr));
		if(recvfrom(ep->sockfd,ep->payload,ep->len_payload,0,
				(struct sockaddr*)&peer_addr,
				&peer_addr_len) != (ssize_t)ep->len_payload){
			if(errno != EINTR){
				IPFError(ep->cntrl->ctx,IPFErrFATAL,
						IPFErrUNKNOWN,"recvfrom(): %M");
				goto error;
			}
			owp_intr = 1;
		}

		if(owp_int){
			goto error;
		}

		/*
		 * Fetch time before ANYTHING else to minimize time errors.
		 */
		if(!_IPFGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Problem retrieving time");
			goto error;
		}

		/*
		 * TODO: v6 If owp_usr2 - get the last seq number from other
		 * side. (Hmmm - how should I do this ipc? thinking...)
		 *
		 * if(owp_usr2){
		 * 	fetch last_seq.
		 * 	if(last_seq & 0xFFFFFFFF){
		 * 		finished = _IPF_SESSION_FIN_INCOMPLETE;
		 * 		npackets = ep->end->seq+1;
		 * 	}
		 * 	else{
		 * 		if(last_seq < ep->begin){
		 * 			CLEAN_PACKET_RECS = TRUE;
		 * 		}
		 * 		npackets = last_seq+1;
		 * 	}
		 * }
		 * else{
		 *	npackets = ep->tsession->test_spec.npackets;
		 * }
		 */
		npackets = ep->tsession->test_spec.npackets;

		/*
		 * Flush the missing packet buffer. Output missing packet
		 * records along the way.
		 */
		timespecclear(&expectspec);
		timespecadd(&expectspec,&ep->begin->absolute);
		timespecadd(&expectspec,&lostspec);
		while(timespeccmp(&expectspec,&currtime,<)){

			/*
			 * If !hit - and the seq number is less than
			 * npackets, then output a "missing packet" record.
			 * (seq number could be greater than or equal to
			 * npackets if it takes longer than "timeout" for
			 * the stopsessions message to get to us. We could
			 * already have missing packet records in our
			 * queue.)
			 */
			if(!ep->begin->hit && (ep->begin->seq < npackets)){
				/* encode seq number */
				*(u_int32_t*)&lostrec[0] =
						htonl(ep->begin->seq);
				/* encode presumed sent time */
				sendstamp.ipftime = IPFNum64Add(
					ep->tsession->test_spec.start_time,
					ep->begin->relative);
				_IPFEncodeTimeStamp(&lostrec[4],&sendstamp);

				/*
				 * Error estimates for "missing" packets is just
				 * a string of zeros, so don't encode anything
				 * to the error portion of the packet buffer.
				 */
				/* write the record */
				if(fwrite(lostrec,sizeof(u_int8_t),
					_IPF_TESTREC_SIZE,ep->datafile) !=
							_IPF_TESTREC_SIZE){
					IPFError(ep->cntrl->ctx,IPFErrFATAL,
						IPFErrUNKNOWN,"fwrite(): %M");
					goto error;
				}
			}
			/*
			 * This is not likely... But it is a sure indication
			 * of problems.
			 */
			else if((ep->begin->hit) &&
					(ep->begin->seq >= npackets)){
				IPFError(ep->cntrl->ctx,IPFErrFATAL,
						IPFErrINVALID,
						"Invalid packet seq received");
				goto error;
			}


			/*
			 * Pop the front off the queue.
			 */
			node = ep->begin;

			if(ep->begin->next){
				ep->begin = ep->begin->next;
			}
			else if((ep->begin->seq+1) < npackets){
				ep->begin = get_node(ep,ep->begin->seq+1);
			}
			else{
				free_node(ep,node);
				ep->begin = ep->end = NULL;
				goto test_over;
			}
			free_node(ep,node);

			timespecclear(&expectspec);
			timespecadd(&expectspec,&ep->begin->absolute);
			timespecadd(&expectspec,&lostspec);
		}

		/*
		 * Check signals...
		 */
		if(owp_int){
			goto error;
		}
		if(owp_usr2){
			goto test_over;
		}
		if(owp_intr){
			goto again;
		}

		/*
		 * Verify peer before looking at packet.
		 */
		if(I2SockAddrEqual(	ep->remoteaddr->saddr,
					ep->remoteaddr->saddrlen,
					(struct sockaddr*)&peer_addr,
					peer_addr_len,I2SADDR_ALL) <= 0){
			goto again;
		}

		/*
		 * Decrypt the packet if needed.
		 */
		if(ep->cntrl->mode & IPF_MODE_DOCIPHER){
			if(ep->cntrl->mode & IPF_MODE_ENCRYPTED){
				/* save encrypted block for CBC */
				memcpy(iv,&ep->payload[0],16);
			}
			rijndaelDecrypt(ep->cntrl->decrypt_key.rk,
					ep->cntrl->decrypt_key.Nr,
					&ep->payload[0],&ep->payload[0]);
			/*
			 * Check zero bits to ensure valid encryption.
			 */
			if(!memcmp(z1,zero,12)){
				goto again;
			}

			if(ep->cntrl->mode & IPF_MODE_ENCRYPTED){
				/* second block - do CBC */
				rijndaelDecrypt(ep->cntrl->decrypt_key.rk,
					ep->cntrl->decrypt_key.Nr,
					&ep->payload[16],&ep->payload[16]);
				((u_int32_t*)&ep->payload)[4] ^=
							((u_int32_t*)iv)[0];
				((u_int32_t*)&ep->payload)[5] ^=
							((u_int32_t*)iv)[1];
				((u_int32_t*)&ep->payload)[6] ^=
							((u_int32_t*)iv)[2];
				((u_int32_t*)&ep->payload)[7] ^=
							((u_int32_t*)iv)[3];
				/*
				 * Check zero bits to ensure valid encryption.
				 */
				if(!memcmp(z2,zero,6)){
					goto again;
				}
			 }
		}

		seq_num = ntohl(*seq);
		if(seq_num >= ep->tsession->test_spec.npackets)
			goto error;
		/*
		 * If it is no-longer in the buffer, than we ignore
		 * it.
		 */
		if(seq_num < ep->begin->seq)
			goto again;

		/*
		 * What time did we expect the sender to send the packet?
		 */
		if(!(node = get_node(ep,seq_num))){
			goto error;
		}
		(void)IPFTimespecToTimestamp(&expecttime,&node->absolute,
								NULL,NULL);
		/*
		 * What time did sender send this packet?
		 */
		_IPFDecodeTimeStamp(&sendstamp,tstamp);
		if(!_IPFDecodeTimeStampErrEstimate(&sendstamp,tstamperr)){
			goto again;
		}

		/*
		 * What time did we recv it?
		 */
		(void)IPFTimespecToTimestamp(&recvstamp,&currtime,
						       &esterror,&lasterror);
		lasterror = esterror;
		recvstamp.sync = sync;

		/*
		 * Encode the recv time to buffer right away to catch
		 * problems with the esterror.
		 */
		_IPFEncodeTimeStamp(&recvbuf[0],&recvstamp);
		if(!_IPFEncodeTimeStampErrEstimate(&recvbuf[8],&recvstamp)){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Invalid recv timestamp!");
			goto error;
		}


		/*
		 * Now we can start the validity tests from Section 6.1 of
		 * the spec...
		 * MUST discard if:
		 */

		/*
		 * 1.
		 * Send timestamp is more than timeout in past or future.
		 * (i.e. send/recv differ by more than "timeout")
		 */
		if(IPFNum64Diff(sendstamp.ipftime,recvstamp.ipftime) >
					ep->tsession->test_spec.loss_timeout){
			goto again;
		}

		/*
		 * 2.
		 * Send timestamp differs by more than "timeout" from
		 * "scheduled" send time.
		 */
		if(IPFNum64Diff(sendstamp.ipftime,expecttime.ipftime) >
					ep->tsession->test_spec.loss_timeout){
			goto again;
		}

		/*
		 * Made it through all validity tests. Record the packet!
		 */
		node->hit = True;

		/* write sequence number */
		if(fwrite(seq,sizeof(u_int32_t),1,ep->datafile) != 1){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"fwrite(): %M");
			goto error;
		}
		/* write "sent" tstamp straight from buffer */
		if(fwrite(tstamp,sizeof(u_int8_t),10,ep->datafile) != 10){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"fwrite(): %M");
			goto error;
		}

		/* write "recv" tstamp */
		if(fwrite(recvbuf,sizeof(u_int8_t),10,ep->datafile) != 10){
			IPFError(ep->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"fwrite(): %M");
			goto error;
		}
	}
test_over:

	/*
	 * Set the "finished" bit in the file.
	 */
	/*
	 * TODO: V6
	 * if(CLEAN_PACKET_RECS){
	 * 	parse file and truncate file after last_seq
	 * }
	 */
	if(_IPFWriteDataHeaderFinished(ep->cntrl->ctx,ep->datafile,finished)){
		goto error;
	}
	fclose(ep->datafile);
	ep->datafile = NULL;


	exit(IPF_CNTRL_ACCEPT);

error:
	if(ep->userfile && (strlen(ep->fname) > 0)){
		unlink(ep->fname);
	}
	if(ep->datafile)
		fclose(ep->datafile);

	exit(IPF_CNTRL_FAILURE);
}

/*
 * Note: We explicitly do NOT connect the send udp socket. This is because
 * each individual packet needs to be treated independant of the others. send
 * causes the socket to close if certain ICMP messages come back. We
 * specifically do NOT want this behavior.
 */
IPFBoolean
_IPFEndpointInitHook(
	IPFControl	cntrl,
	IPFTestSession	tsession,
	IPFErrSeverity	*err_ret
)
{
	IPFContext		ctx = IPFGetContext(cntrl);
	IPFEndpoint		*end_data = &tsession->endpoint;
	IPFEndpoint		ep = tsession->endpoint;
	struct sigaction	act;
	struct sigaction	chldact,usr1act,usr2act,intact,pipeact,alrmact;
	sigset_t		sigs,osigs;

	*err_ret = IPFErrFATAL;

	if(!ep){
		return False;
	}

	if(!ep->send){

		ep->remoteaddr = tsession->sender;
	}
	else{
		ep->remoteaddr = tsession->receiver;
	}

	/*
	 * call sigprocmask to block signals before the fork.
	 * (This ensures no race condition.)
	 * First we set the new sig_handler for the child, saving the
	 * currently installed handlers.
	 * Then fork.
	 * Then reset the previous sig_handlers for the parent.
	 * Then unblock the signals in the parent.
	 * (This should ensure that this routine doesn't mess with what
	 * the calling environment thinks is installed for these.)
	 *
	 * The Child then waits for the signals using sigsuspend, and the
	 * newly installed handlers get called.
	 */
	sigemptyset(&sigs);
	sigaddset(&sigs,SIGUSR1);
	sigaddset(&sigs,SIGUSR2);
	sigaddset(&sigs,SIGINT);
	sigaddset(&sigs,SIGALRM);
	sigaddset(&sigs,SIGPIPE);
	sigaddset(&sigs,SIGCHLD);
	
	if(sigprocmask(SIG_BLOCK,&sigs,&osigs) != 0){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"sigprocmask(): %M");
		EndpointFree(ep,IPF_CNTRL_FAILURE);
		*end_data = NULL;
		return False;
	}
	/*
	 * set the sig handlers for the currently blocked signals.
	 */
	owp_usr1 = 0;
	owp_usr2 = 0;
	owp_int = 0;
	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if(		(sigaction(SIGUSR1,&act,&usr1act) != 0) ||
			(sigaction(SIGUSR2,&act,&usr2act) != 0) ||
			(sigaction(SIGINT,&act,&intact) != 0) ||
			(sigaction(SIGALRM,&act,&alrmact) != 0)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"sigaction(): %M");
		EndpointFree(ep,IPF_CNTRL_FAILURE);
		*end_data = NULL;
		return False;
	}
	
	act.sa_handler = SIG_IGN;
	if(		(sigaction(SIGPIPE,&act,&pipeact) != 0)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"sigaction(): %M");
		EndpointFree(ep,IPF_CNTRL_FAILURE);
		*end_data = NULL;
		return False;
	}

	/*
	 * If there is currently no SIGCHLD handler:
	 * setup an empty CHLD handler to ensure SIGCHLD is sent
	 * to this process. (Just need the signal sent to break
	 * us out of "select" with an EINTR when we trying to
	 * determine if test sessions are complete.)
	 */
	sigemptyset(&chldact.sa_mask);
	chldact.sa_handler = SIG_DFL;
	chldact.sa_flags = 0;
	/* fetch current handler */
	if(sigaction(SIGCHLD,NULL,&chldact) != 0){
		IPFError(ctx,IPFErrWARNING,IPFErrUNKNOWN,"sigaction(): %M");
		EndpointFree(ep,IPF_CNTRL_FAILURE);
		*end_data = NULL;
		return False;
	}
	/* if there is currently no handler - set one. */
	if(chldact.sa_handler == SIG_DFL){
		chldact.sa_handler = sig_nothing;
		if(sigaction(SIGCHLD,&chldact,NULL) != 0){
			IPFError(ctx,IPFErrWARNING,IPFErrUNKNOWN,
					"sigaction(DFL) failed: %M");
			EndpointFree(ep,IPF_CNTRL_FAILURE);
			*end_data = NULL;
			return False;
		}
	}
	/* now make sure SIGCHLD won't be masked. */
	sigdelset(&osigs,SIGCHLD);

	ep->child = fork();

	if(ep->child < 0){
		/* fork error */
		(void)sigprocmask(SIG_SETMASK,&osigs,NULL);
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,"fork(): %M");
		EndpointFree(ep,IPF_CNTRL_FAILURE);
		*end_data = NULL;
		return False;
	}

	if(ep->child > 0){
		/* parent */
		int			childstatus;

		/*
		 * Reset parent's sig handlers.
		 */
		if(		(sigaction(SIGUSR1,&usr1act,NULL) != 0) ||
				(sigaction(SIGUSR2,&usr2act,NULL) != 0) ||
				(sigaction(SIGINT,&intact,NULL) != 0) ||
				(sigaction(SIGPIPE,&pipeact,NULL) != 0) ||
				(sigaction(SIGALRM,&alrmact,NULL) != 0)){
			IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
							"sigaction(): %M");
			goto parenterr;
		}
	
		/* reset sig_mask to the old one (-SIGCHLD)	*/
		if(sigprocmask(SIG_SETMASK,&osigs,NULL) != 0){
			IPFError(ctx,IPFErrWARNING,IPFErrUNKNOWN,
							"sigprocmask(): %M");
			goto parenterr;
		}


		EndpointClear(ep);
		*err_ret = IPFErrOK;
		return True;
parenterr:
		kill(ep->child,SIGINT);
		ep->wopts &= ~WNOHANG;
		while((waitpid(ep->child,&childstatus,ep->wopts) < 0)
					&& (errno == EINTR));
		EndpointFree(ep,IPF_CNTRL_FAILURE);
		*end_data = NULL;
		return False;
	}

	/*
	 * We are now in the child send/recv process.
	 */

	/*
	 * busy loop for systems where debugger doesn't support
	 * child follow_fork mode functionality...
	 */
#ifndef	NDEBUG
	{
		int	waitfor = (int)IPFContextConfigGet(ctx,IPFChildWait);

		while(waitfor);
	}
#endif

	/*
	 * SIGUSR1 is StartSessions
	 * SIGUSR2 is StopSessions
	 * SIGINT is Terminate - making session invalid.
	 */

	/*
	 * wait until signal to kick-off session.
	 */
	sigemptyset(&sigs);
	sigaddset(&sigs,SIGPIPE);
	while(!owp_usr1 && !owp_usr2 && !owp_int)
		(void)sigsuspend(&sigs);

	/*
	 * got a signal - continue.
	 */
	if(owp_int || owp_usr2){
		/* cancel the session */
		exit(IPF_CNTRL_REJECT);
	}else if(owp_usr1){
		/* start the session */
		struct timespec currtime;
		u_int32_t	esterror;
		int		sync;

		/* clear the sig mask so all sigs come through */
		if(sigprocmask(SIG_SETMASK,&sigs,NULL) != 0){
			IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"sigprocmask(): %M");
			exit(IPF_CNTRL_FAILURE);
		}

		if(!_IPFGetTimespec(ep->cntrl->ctx,&currtime,&esterror,&sync)){
			IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"Unable to fetch current time...");
			exit(IPF_CNTRL_FAILURE);
		}

		/*
		 * If start is in the past - effect an immediate start.
		 */
		if(timespeccmp(&ep->start,&currtime,<)){
			ep->start = currtime;
#ifdef	NOT
			IPFError(ctx,IPFErrINFO,IPFErrUNKNOWN,
					"Resetting test start!");
#endif
		}

		if(ep->send){
			run_sender(ep);
		}
		else{
			run_receiver(ep,&currtime);
		}
	}

	/*NOTREACHED*/
	IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"Shouldn't get to this line of code... Hmmpf.");
	exit(IPF_CNTRL_FAILURE);
}
#endif

IPFBoolean
_IPFEndpointStart(
	IPFTestSession	tsession,
	u_int16_t	*dataport,
	IPFErrSeverity	*err_ret
	)
{
#if	NOT
	*err_ret = IPFErrOK;

	if((ep->acceptval < 0) && ep->child && (kill(ep->child,SIGUSR1) == 0))
		return True;

	*err_ret = IPFErrFATAL;
	IPFError(ep->tsession->cntrl->ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"EndpointStart:Can't signal child #%d: %M",ep->child);
	return False;
#else
	return False;
#endif
}

IPFBoolean
_IPFEndpointStatus(
	IPFTestSession	tsession,
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
	IPFTestSession	tsession,
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
	ep->tsession->endpoint = NULL;
	EndpointFree(ep,aval);

	return retval;
#else
	return False;
#endif
}
