/*
**      $Id$
*/
/************************************************************************
*									*
*			     Copyright (C)  2003			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
**	File:		ipcntrlP.h
**
**	Author:		Jeff W. Boote
**
**	Date:		Thu Sep 18 13:26:19 MDT 2003
**
**	Description:	
**	This header file describes the internal-private ipcntrl API.
**
**	testing
*/
#ifndef	IPCNTRLP_H
#define	IPCNTRLP_H

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN	64
#endif

#ifndef PATH_MAX
#define	PATH_MAX	1024
#endif

#include <I2util/util.h>
#include <ipcntrl/ipcntrl.h>

/* 
** Lengths (in 16-byte blocks) of various Control messages. 
*/
#define _IPF_RIJNDAEL_BLOCK_SIZE	16
#define	_IPF_TIME_REQUEST_BLK_LEN	2
#define _IPF_TEST_REQUEST_BLK_LEN	7
#define _IPF_START_SESSIONS_BLK_LEN	2
#define _IPF_STOP_SESSIONS_BLK_LEN	2
#define _IPF_CONTROL_ACK_BLK_LEN	2
#define _IPF_MAX_MSG_BLK_LEN		_IPF_TEST_REQUEST_BLK_LEN
#define _IPF_MAX_MSG	(_IPF_MAX_MSG_BLK_LEN*_IPF_RIJNDAEL_BLOCK_SIZE)
#define _IPF_TEST_REQUEST_PREAMBLE_SIZE	(_IPF_TEST_REQUEST_BLK_LEN*_IPF_RIJNDAEL_BLOCK_SIZE)
#define	_IPF_TESTREC_SIZE	24

/*
 * Control state constants.
 */
/* initial & invalid */
#define	_IPFStateInitial		(0x0000)
#define	_IPFStateInvalid		(0x0000)
/* during negotiation */
#define	_IPFStateSetup			(0x0001)
#define	_IPFStateUptime			(_IPFStateSetup << 1)
/* after negotiation ready for requests */
#define	_IPFStateRequest		(_IPFStateUptime << 1)
/* test sessions are active  */
#define	_IPFStateTest			(_IPFStateRequest << 1)
/*
 * The following states are for partially read messages on the server.
 */
#define _IPFStateTestRequest		(_IPFStateTest << 1)
#define _IPFStateStartSession		(_IPFStateTestRequest << 1)
#define _IPFStateStopSession		(_IPFStateStartSession << 1)
#define _IPFStateTestAccept		(_IPFStateStopSession << 1)
#define _IPFStateStartAck		(_IPFStateTestAccept << 1)
#define _IPFStateTimeRequest		(_IPFStateStartAck << 1)
#define _IPFStateTimeResponse		(_IPFStateTimeRequest << 1)

/* Reading indicates partial read request-ReadRequestType without remainder */
#define _IPFStateReading	(_IPFStateTestRequest|_IPFStateStartSession|_IPFStateStopSession|_IPFStateTimeRequest)

/*
 * "Pending" indicates waiting for server response to a request.
 */
#define	_IPFStatePending	(_IPFStateTestAccept|_IPFStateStartAck|_IPFStateStopSession|_IPFStateTimeResponse)

#define	_IPFStateIsInitial(c)	(!(c)->state)
#define	_IPFStateIsSetup(c)	(!(_IPFStateSetup ^ (c)->state))

#define _IPFStateIs(teststate,c)	((teststate & (c)->state))

#define	_IPFStateIsRequest(c)	_IPFStateIs(_IPFStateRequest,c)
#define	_IPFStateIsReading(c)	_IPFStateIs((_IPFStateReading),c)
#define _IPFStateIsPending(c)	_IPFStateIs(_IPFStatePending,c)
#define	_IPFStateIsTest(c)	_IPFStateIs(_IPFStateTest,c)

/*
 * other useful constants.
 */
#define	_IPF_DEFAULT_TMPDIR	"/tmp"
#define	_IPF_DEV_NULL		"/dev/null"
#define	_IPF_IPERF_CMD		"/usr/local/bin/iperf"
#define _IPF_ERR_MAXSTRING	(1024)
#define	_IPF_PATH_SEPARATOR	"/"
#define _IPF_TMPFILEFMT		"iperfc.XXXXXX"
#define _IPF_MAX_IPERFARGS	(32)

/*
 * Data structures
 */
typedef struct IPFContextRec IPFContextRec;
typedef struct IPFAddrRec IPFAddrRec;
typedef struct IPFControlRec IPFControlRec;

#define _IPF_CONTEXT_TABLE_SIZE	64
#define _IPF_CONTEXT_MAX_KEYLEN	64

struct IPFContextRec{
	IPFBoolean		lib_eh;
	I2ErrHandle		eh;
	I2Table			table;
	I2RandomSource		rand_src;
	char			tmpdir[PATH_MAX+1];
	IPFControlRec		*cntrl_list;
};

struct IPFAddrRec{
	IPFContext	ctx;

	IPFBoolean	node_set;
	char		node[MAXHOSTNAMELEN+1];

	IPFBoolean	port_set;
	char		port[MAXHOSTNAMELEN+1];

	IPFBoolean	ai_free;	/* free ai list directly...*/
	struct addrinfo	*ai;

	struct sockaddr	*saddr;
	socklen_t	saddrlen;
	int		so_type;	/* socktype saddr works with	*/
	int		so_protocol;	/* protocol saddr works with	*/

	IPFBoolean	fd_user;
	int		fd;
};

typedef struct IPFTestSessionRec IPFTestSessionRec, *IPFTestSession;
struct IPFControlRec{
	/*
	 * Application configuration information.
	 */
	IPFContext		ctx;

	/*
	 * Hash for maintaining Policy state data.
	 */
	I2Table			table;

	/*
	 * Control connection state information.
	 */
	IPFBoolean		server;	/* this record represents server */
	int			state;	/* current state of connection */
	IPFSessionMode		mode;

				/*
				 * Very rough upper bound estimate of
				 * rtt.
				 * Used by clients to estimate a
				 * good "start" time for tests that
				 * is just beyond the amount of time
				 * it takes to request the test.
				 */
	IPFNum64		rtt_bound;
	/*
	 * This field is initialized to zero and used for comparisons
	 * to ensure AES is working.
	 */
	u_int8_t		zero[16];

				/* area for peer's messages		*/
				/* make u_int32_t to get wanted alignment */
				/* Usually cast to u_int8_t when used... */
	u_int32_t		msg[_IPF_MAX_MSG/sizeof(u_int32_t)];

	/*
	 * Address specification and "network" information.
	 * (Control socket addr information)
	 */
	IPFAddr			remote_addr;
	IPFAddr			local_addr;
	int			sockfd;

	/*
	 * Encryption fields
	 */
				/* null if not set - else userid_buffer */
	char			*userid;
	IPFUserID		userid_buffer;
	keyInstance             encrypt_key;
	keyInstance             decrypt_key;
	u_int8_t		session_key[16];
	u_int8_t		readIV[16];
	u_int8_t		writeIV[16];

	struct IPFControlRec	*next;
	IPFTestSession		tests;
};

typedef struct IPFEndpointRec{
#ifndef	NDEBUG
	IPFBoolean		childwait;
#endif
	IPFControl		cntrl;		/* To client		*/
	IPFTestSession		tsess;

	int			ssockfd;
	IPFControl		rcntrl;		/* To other endpoint	*/

	IPFAcceptType		acceptval;
	pid_t			child;
	int			wopts;
} IPFEndpointRec, *IPFEndpoint;

struct IPFTestSessionRec{
	IPFControl			cntrl;
	IPFSID				sid;
	IPFTimeStamp			localtime;
	IPFNum64			reserve_time;
	IPFNum64			fuzz;
	IPFNum64			latest_time;
	u_int16_t			recv_port;

	IPFBoolean			conf_sender;
	IPFBoolean			conf_receiver;
	IPFTestSpec			test_spec;

	FILE				*localfp;
	FILE				*remotefp;

	void				*closure; /* per/test app data */

	IPFEndpoint			endpoint;
};

/*
 * Private api.c prototypes
 */
extern IPFAddr
_IPFAddrAlloc(
	IPFContext	ctx
	);

extern IPFAddr
_IPFAddrCopy(
	IPFAddr		from
	);

extern IPFTestSession
_IPFTestSessionAlloc(
	IPFControl	cntrl,
	IPFBoolean	send,
	IPFAddr		sender,
	IPFAddr		receiver,
	u_int16_t	recv_port,
	IPFTestSpec	*test_spec
	);

extern IPFErrSeverity
_IPFTestSessionFree(
	IPFTestSession	tsession,
	IPFAcceptType	aval
	);

extern int
_IPFCreateSID(
	IPFTestSession	tsession
	);

#define	_IPF_SESSION_FIN_ERROR	0
#define	_IPF_SESSION_FIN_NORMAL	1
#define _IPF_SESSION_FIN_INCOMPLETE	2

extern int
_IPFWriteDataHeaderFinished(
		IPFContext	ctx,
		FILE		*fp,
		u_int32_t	finished
		);

extern int
_IPFReadDataHeaderInitial(
		IPFContext	ctx,
		FILE		*fp,
		u_int32_t	*ver,
		u_int32_t	*fin,	/* only set if (*ver >= 2) */
		off_t		*hdr_off,
		struct stat	*stat_buf
		);

/*
 * io.c prototypes
 */
extern int
_IPFSendBlocksIntr(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	int		*retn_on_intr
	      );

extern int
_IPFReceiveBlocksIntr(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	int		*retn_on_intr
		);

extern int
_IPFSendBlocks(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks
	      );

extern int
_IPFReceiveBlocks(
	IPFControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks
		);

extern int
_IPFEncryptBlocks(
	IPFControl	cntrl,
	u_int8_t	*in_buf,
	int		num_blocks,
	u_int8_t	*out_buf
		);

extern int
_IPFDecryptBlocks(
	IPFControl	cntrl,
	u_int8_t	*in_buf,
	int		num_blocks,
	u_int8_t	*out_buf
		);

extern void
_IPFMakeKey(
	IPFControl	cntrl,
	u_int8_t	*binKey
	);

extern int
IPFEncryptToken(
	u_int8_t	*binKey,
	u_int8_t	*token_in,
	u_int8_t	*token_out
	);

extern int
IPFDecryptToken(
	u_int8_t	*binKey,
	u_int8_t	*token_in,
	u_int8_t	*token_out
	);

/*
 * protocol.c
 */

extern IPFErrSeverity
_IPFWriteServerGreeting(
	IPFControl	cntrl,
	u_int32_t	avail_modes,
	u_int8_t	*challenge,	/* [16] */
	int		*retn_on_intr
	);

extern IPFErrSeverity
_IPFReadServerGreeting(
	IPFControl	cntrl,
	u_int32_t	*mode,		/* modes available - returned	*/
	u_int8_t	*challenge	/* [16] : challenge - returned	*/
);

extern IPFErrSeverity
_IPFWriteClientGreeting(
	IPFControl	cntrl,
	u_int8_t	*token	/* [32]	*/
	);

extern IPFErrSeverity
_IPFReadClientGreeting(
	IPFControl	cntrl,
	u_int32_t	*mode,
	u_int8_t	*token,		/* [32] - return	*/
	u_int8_t	*clientIV,	/* [16] - return	*/
	int		*retn_on_intr
	);

extern IPFErrSeverity
_IPFWriteServerOK(
	IPFControl	cntrl,
	IPFAcceptType	code,
	IPFNum64	uptime,
	int		*retn_on_intr
	);

extern IPFErrSeverity
_IPFReadServerOK(
	IPFControl	cntrl,
	IPFAcceptType	*acceptval	/* ret	*/
	);

extern IPFErrSeverity
_IPFReadServerUptime(
	IPFControl	cntrl,
	IPFNum64	*uptime_ret
	);

extern IPFErrSeverity
_IPFWriteTimeRequest(
	IPFControl	cntrl
	);

extern IPFErrSeverity
_IPFReadTimeRequest(
	IPFControl	cntrl,
	int		*retn_on_intr
	);

extern IPFErrSeverity
_IPFWriteTimeResponse(
	IPFControl	cntrl,
	IPFTimeStamp	*tstamp,
	int		*retn_on_intr
	);

extern IPFErrSeverity
_IPFReadTimeResponse(
	IPFControl	cntrl,
	IPFTimeStamp	*tstamp_ret
	);

extern IPFErrSeverity
_IPFWriteTestRequest(
	IPFControl	cntrl,
	IPFTestSession	tsession
);

/*
 * This function can be called from a server or client context. From the
 * server it is reading an actual new request. From the client it is part
 * of a FetchSession response. The server code MUST set the accept_ret
 * pointer to a valid IPFAcceptType record. This record will be filled
 * in with the appropriate AcceptType value for a response. The client
 * code MUST set this to NULL.
 */
extern IPFErrSeverity
_IPFReadTestRequest(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFTestSession	*test_session,
	IPFAcceptType	*accept_ret
	);

extern IPFErrSeverity
_IPFWriteTestAccept(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	acceptval,
	IPFTestSession	tsession
	);

extern IPFErrSeverity
_IPFReadTestAccept(
	IPFControl	cntrl,
	IPFAcceptType	*acceptval,
	IPFTestSession	tsession
	);

extern IPFErrSeverity
_IPFWriteStartSession(
	IPFControl	cntrl,
	u_int16_t	dataport
	);

extern IPFErrSeverity
_IPFReadStartSession(
	IPFControl	cntrl,
	u_int16_t	*dataport,
	int		*retn_on_intr
);

extern IPFErrSeverity
_IPFWriteStartAck(
	IPFControl	cntrl,
	int		*retn_on_intr,
	u_int16_t	dataport,
	IPFAcceptType	acceptval
	);

extern IPFErrSeverity
_IPFReadStartAck(
	IPFControl	cntrl,
	u_int16_t	*dataport,
	IPFAcceptType	*acceptval
	);

extern IPFErrSeverity
_IPFWriteStopSession(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	acceptval,
	FILE		*fp
	);

extern IPFErrSeverity
_IPFReadStopSession(
	IPFControl	cntrl,
	int		*retn_on_intr,
	IPFAcceptType	*acceptval,
	FILE		*fp
);

/*
 * context.c
 */

extern IPFControl
_IPFControlAlloc(
	IPFContext	ctx,
	IPFErrSeverity	*err_ret
	);

extern IPFBoolean
_IPFCallGetAESKey(
	IPFContext	ctx,		/* context record	*/
	const char	*userid,	/* identifies key	*/
	u_int8_t	*key_ret,	/* key - return		*/
	IPFErrSeverity	*err_ret	/* error - return	*/
);

extern IPFBoolean
_IPFCallCheckControlPolicy(
	IPFControl	cntrl,		/* control record		*/
	IPFSessionMode	mode,		/* requested mode       	*/
	const char	*userid,	/* key identity			*/
	struct sockaddr	*local_sa_addr,	/* local addr or NULL		*/
	struct sockaddr	*remote_sa_addr,/* remote addr			*/
	IPFErrSeverity	*err_ret	/* error - return		*/
);

extern IPFBoolean
_IPFCallCheckTestPolicy(
	IPFControl	cntrl,		/* control handle		*/
	IPFTestSession	tsession,	/* test session description	*/
	IPFErrSeverity	*err_ret	/* error - return		*/
);

extern void
_IPFCallTestComplete(
	IPFTestSession	tsession,
	IPFAcceptType	aval
	);

extern IPFErrSeverity
_IPFCallProcessResults(
	IPFTestSession	tsession
	);

/*
 * non-NULL closure indicates "receiver" - NULL indicates R/O Fetch.
 */
extern FILE *
_IPFCallOpenFile(
	IPFControl	cntrl,		/* control handle		*/
	void		*closure,	/* app data/per test		*/
	IPFSID		sid,		/* sid for datafile		*/
	char		fname_ret[PATH_MAX+1]
	);

extern void
_IPFCallCloseFile(
	IPFControl	cntrl,
	void		*closure,
	FILE		*fp,
	IPFAcceptType	aval
	);


/* endpoint.c */

/*
 * EndpointStart:
 * 1) Open tmpfile for results/ open /dev/null for stderr
 * 2)	If receiver - open serversock for endpoint2endpoint communication
 * 	If sender - connect to giving reciever control sock and send
 * 		timestamp packet and receive AOK.
 * 3) fork child
 * 	child:
 * 		dup stdout -> tmpfile
 * 		dup stdin -> /dev/null
 * 		dup stderr -> /dev/null
 * 		wait until start time to exec or signal to exit
 * 	parent: return AOK
 */
extern IPFBoolean
_IPFEndpointStart(
	IPFTestSession	tsession,
	u_int16_t	*dataport,
	IPFErrSeverity	*err_ret
	);

/*
 * EndpointStatus:
 * Is child still alive? What was "exit" code of test?
 */
extern IPFBoolean
_IPFEndpointStatus(
	IPFTestSession	tsession,
	IPFAcceptType	*aval,
	IPFErrSeverity	*err_ret
	);

extern IPFBoolean
_IPFEndpointStop(
	IPFTestSession	tsession,
	IPFAcceptType	aval,
	IPFErrSeverity	*err_ret
	);

/*
 * error.c
 */
extern IPFErrSeverity
_IPFFailControlSession(
	IPFControl	cntrl,
	int		err
	);

/*
 * time.c
 */

/*
 * En/DecodeTimeStamp functions do not assume any alignment requirements
 * for buf. (Most functions in protocol.c assume u_int32_t alignment.)
 */
extern void
_IPFEncodeTimeStamp(
	u_int8_t	buf[8],
	IPFTimeStamp	*tstamp
	);
extern IPFBoolean
_IPFEncodeTimeStampErrEstimate(
	u_int8_t	buf[2],
	IPFTimeStamp	*tstamp
	);
extern void
_IPFDecodeTimeStamp(
	IPFTimeStamp	*tstamp,
	u_int8_t	buf[8]
	);
extern IPFBoolean
_IPFDecodeTimeStampErrEstimate(
	IPFTimeStamp	*tstamp,
	u_int8_t	buf[2]
	);
extern int
_IPFInitNTP(
	IPFContext	ctx,
	I2Boolean	allowunsync
	);

extern struct timespec *
_IPFGetTimespec(
	IPFContext	ctx,
	struct timespec	*ts,
	u_int32_t	*esterr,
	int		*sync
	);

#endif	/* IPCNTRLP_H */
