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
**	File:		ipcntrl.h
**
**	Author:		Jeff W. Boote
**
**	Date:		Tue Sep  9 15:44:43 MDT 2003
**
**	Description:	
**	This header file describes the ipcntrl API. The ipcntrl API is intended
**	to provide a portable layer for implementing the ipcntrl protocol.
*/
#ifndef	IPCNTRL_H
#define	IPCNTRL_H

#include <I2util/util.h>

/*
 * Portablility sanity checkes.
 */
#if	HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <ipcntrl/config.h>

#if	!HAVE_ERRNO_H || !HAVE_NETDB_H || !HAVE_STDLIB_H || !HAVE_SYS_PARAM_H
#error	Missing Header!
#endif

#if	!HAVE_GETADDRINFO || !HAVE_SOCKET
#error	Missing needed networking capabilities! (getaddrinfo and socket)
#endif


#if	!HAVE_MALLOC || !HAVE_MEMSET
#error	Missing needed memory functions!
#endif
#endif	/* HAVE_CONFIG_H */

#ifndef	HAVE___ATTRIBUTE__
#define __attribute__(x)
#endif

#if	defined HAVE_DECL_FSEEKO && !HAVE_DECL_FSEEKO
#define fseeko(a,b,c) fseek(a,b,c)
#endif

#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#include <time.h>

#ifndef	False
#define	False	(0)
#endif
#ifndef	True
#define	True	(!False)
#endif

#ifndef MIN
#define MIN(a,b) ((a<b)?a:b)
#endif
#ifndef MAX
#define MAX(a,b) ((a>b)?a:b)
#endif

/*
 * Filename/path component macros used by various parts of ipcntrl.
 */
#ifndef IPF_PATH_SEPARATOR
#define	IPF_PATH_SEPARATOR	"/"
#endif
#ifndef	IPF_PATH_SEPARATOR_LEN
#define	IPF_PATH_SEPARATOR_LEN	1
#endif
#ifndef	IPF_FILE_EXT
#define	IPF_FILE_EXT	".ipf"
#endif

/*
 * The ascii decimal encoding of the 64 bit timestamps takes this many
 * chars. Log(2^64)
 *
 * fmt indicates 0 padding, 20 significant digits.
 */
#ifndef IPF_TSTAMPFMT 
#define IPF_TSTAMPFMT  "%020llu"
#endif

#ifndef IPF_TSTAMPCHARS
#define IPF_TSTAMPCHARS  20
#endif

/*
 * Char used between start_end.ipf files.
 */
#ifndef IPF_NAME_SEP
#define IPF_NAME_SEP    "_"
#endif


#include <ipcntrl/rijndael-api-fst.h>

/* Default mode offered by the server */
#define IPF_DEFAULT_OFFERED_MODE 	(IPF_MODE_OPEN|IPF_MODE_AUTHENTICATED|IPF_MODE_ENCRYPTED)

/*
 * TODO: 4822 should eventually be replaced by an IANA blessed service name.
 */
#define IPF_CONTROL_SERVICE_NAME	"4822"

/*
 * Default value to use for the listen backlog. We pick something large
 * and let the OS truncate it if it isn't willing to do that much.
 */
#define IPF_LISTEN_BACKLOG	(64)

/*
 * IPFNum64 is interpreted as 32bits of "seconds" and 32bits of
 * "fractional seconds".
 * The byte ordering is defined by the hardware for this value. 4 MSBytes are
 * seconds, 4 LSBytes are fractional. Each set of 4 Bytes is pulled out
 * via shifts/masks as a 32bit unsigned int when needed independently.
 *
 * sync/multiplier/scale are defined as in Section 5.1 of
 * draft-ietf-ippm-owdp-05.txt:
 * If sync is non-zero, then the party generating the timestamp claims to
 * have an external source of synchronization to UTC.
 * multiplier and scale are used to indicate the estimated error of
 * ipftime.
 * They are interpreted as follows:
 * multiplier*(2^(-32))*(2^Scale)
 *
 * (implementor note)
 * Effectively, this breaks down such that if Scale is 0, then the multiplier
 * is the error in the same scale as the fractional seconds of ipftime.
 * Therefore, for "real" errors greater than an 8 bit number at that scale
 * the value can just be right shifted until it fits into an 8 bit integer,
 * and the number of shifts would indicate the "Scale" value.
 */
typedef u_int64_t IPFNum64;

/*
 * Arithmetic/Conversion functions on IPFNum64 numbers.
 */

/*
 * These macros should be used instead of directly using
 * arithmetic on these types in the event that the underlying
 * type is changed from an u_int64_t to some kind of structure.
 *
 */
#define IPFNum64Diff(x,y)	((x>y) ? (x-y) : (y-x))
#define IPFNum64Add(x,y)	(x+y)
#define IPFNum64Sub(x,y)	(x-y)
#define IPFNum64Cmp(x,y)	((x<y) ? -1 : ((x>y) ? 1 : 0))
#define IPFNum64Min(x,y)	((x<y) ? x : y)
#define IPFNum64Max(x,y)	((x>y) ? x : y)

extern IPFNum64
IPFNum64Mult(
	IPFNum64	x,
	IPFNum64	y
	);

extern IPFNum64
IPFULongToNum64(
	u_int32_t	from);


extern void
IPFNum64ToTimeval(
	struct timeval	*to,
	IPFNum64	from
	);

extern void
IPFTimevalToNum64(
	IPFNum64	*to,
	struct timeval	*from
	);

extern void
IPFNum64ToTimespec(
	struct timespec	*to,
	IPFNum64	from
	);

extern void
IPFTimespecToNum64(
	IPFNum64	*to,
	struct timespec	*from
	);

extern double
IPFNum64ToDouble(
	IPFNum64	from
	);

extern IPFNum64
IPFDoubleToNum64(
	double		from
	);

extern IPFNum64
IPFUsecToNum64(u_int32_t usec);

/*
 * These structures are opaque to the API user.
 * They are used to maintain state internal to the library.
 */
typedef struct IPFContextRec	*IPFContext;
typedef struct IPFControlRec	*IPFControl;
typedef struct IPFAddrRec	*IPFAddr;

/*
 * Timestamp related types and structures needed throughout.
 */

typedef struct IPFTimeStampRec{
	IPFNum64		ipftime;
	u_int8_t		sync;
	u_int8_t		multiplier;
	u_int8_t		scale;
} IPFTimeStamp;


/* Codes for returning error severity and type. */
/* values are mapped to syslog "priorities" we want to use. */
typedef enum {
	IPFErrFATAL=3,
	IPFErrWARNING=4,
	IPFErrINFO=6,
	IPFErrDEBUG=7,
	IPFErrOK=8
} IPFErrSeverity;

typedef enum {
	IPFErrUNKNOWN=0,
	IPFErrPOLICY,
	IPFErrINVALID,
	IPFErrUNSUPPORTED
} IPFErrType;


/*
 * Valid values for "accept" - this will be added to for the purpose of
 * enumerating the reasons for rejecting a session, or early termination
 * of a test session.
 *
 * TODO:Get the additional "accept" values added to the spec.
 */
typedef enum{
	IPF_CNTRL_INVALID=-1,
	IPF_CNTRL_ACCEPT=0x0,
	IPF_CNTRL_REJECT=0x1,
	IPF_CNTRL_FAILURE=0x2,
	IPF_CNTRL_UNSUPPORTED=0x4
} IPFAcceptType;

typedef u_int32_t	IPFBoolean;
typedef u_int8_t	IPFSID[16];
typedef u_int8_t	IPFSequence[4];

/*
 * technically the username in the client greeting message can have u_int8_t
 * but this implementation limits it to a valid "char" type.
 */
#define	IPF_USERID_LEN	16
typedef char		IPFUserID[IPF_USERID_LEN+1];	/* add 1 for '\0' */
typedef u_int8_t	IPFKey[16];

#define	IPF_MODE_UNDEFINED		(0)
#define	IPF_MODE_OPEN			(01)
#define	IPF_MODE_AUTHENTICATED		(02)
#define	IPF_MODE_ENCRYPTED		(04)
#define	IPF_MODE_DOCIPHER	(IPF_MODE_AUTHENTICATED|IPF_MODE_ENCRYPTED)

typedef u_int32_t	IPFSessionMode;

typedef struct{
	IPFAddr		sender;
	IPFAddr		receiver;
	IPFTimeStamp	req_time;
	IPFNum64	latest_time;
	u_int32_t	duration;
	IPFBoolean	udp;
	u_int32_t	bandwidth;
	u_int32_t	window_size;
	u_int32_t	len_buffer;
	u_int16_t	report_interval;
} IPFTestSpec;

typedef u_int32_t IPFPacketSizeT;

/*
 * an IPFScheduleContextRec is used to maintain state for the schedule
 * generator. Multiple contexts can be allocated to maintain multiple
 * "streams" of schedules.
 */
typedef struct IPFScheduleContextRec	*IPFScheduleContext;

IPFScheduleContext
IPFScheduleContextCreate(
		IPFContext	ctx,
		IPFSID		sid,
		u_int32_t	mean
		);

void
IPFScheduleContextFree(
	IPFScheduleContext	sctx
		);

IPFErrSeverity
IPFScheduleContextReset(
	IPFScheduleContext	sctx,
		IPFSID		sid,
		u_int32_t	mean
		);

IPFNum64
IPFScheduleContextGenerateNextDelta(
	IPFScheduleContext	sctx
		);

/*
 * Error Reporting:
 *
 * Notice that this macro expands to multiple statements so it is
 * imperative that you enclose it's use in {} in single statement
 * context's such as:
 * 	if(test)
 * 		IPFError(...);	NO,NO,NO,NO!
 * Instead:
 * 	if(test){
 * 		IPFError(...);
 * 	}
 *
 *
 * (Sure would be nice if it were possible to do vararg macros...)
 */
#define IPFError	I2ErrLocation_(__FILE__,__DATE__,__LINE__);	\
			IPFError_

/*
 * Don't call this directly - use the IPFError macro.
 * 	Let me repeat.
 * Don't call this directly - use the IPFError macro.
 */
extern void
IPFError_(
	IPFContext	ctx,
	IPFErrSeverity	severity,
	IPFErrType	etype,
	const char	*fmt,
	...
	);

/*
 * The "context"  is used to basically initializes the library. There is no
 * "global" state - so you can create more than one "context" if you like.
 * (Well... SIGPIPE is disabled... I suppose that is global.)
 *
 * There are specific defaults that can be modified within the context by
 * calling the IPFContextConfigSet function with the following keys and
 * types. (The key is a string - the type indicates what type of data
 * will be stored/retrieved using that key.
 */

/*
 * This type is used to define the function that retrieves the shared
 * secret from whatever key-store is in use.
 * It should return True if it is able to fill in the key_ret variable that
 * is passed in from the caller. False if not. If the function returns false,
 * the caller should check the err_ret value. If OK, then the userid simply
 * didn't exist - otherwise it indicates an error in the key store mechanism.
 *
 * If an application doesn't set this, Encrypted and Authenticated
 * mode will be disabled.
 */	
#define	IPFGetAESKey		"IPFGetAESKey"
typedef IPFBoolean	(*IPFGetAESKeyFunc)(
	IPFContext	ctx,
	const IPFUserID	userid,
	u_int8_t	*key_ret,
	IPFErrSeverity	*err_ret
);

/*
 * This function will be called from IPFControlOpen and IPFServerAccept
 * to determine if the control connection should be accepted.
 * It is called after connecting, and after determining the userid.
 * On failure, value of *err_ret can be inspected: if > IPFErrWARNING,
 * this means rejection based on policy, otherwise there was an error
 * in the function itself.
 *
 * If an application doesn't set this, all connections will be allowed.
 */
#define IPFCheckControlPolicy	"IPFCheckControlPolicy"
typedef IPFBoolean (*IPFCheckControlPolicyFunc)(
	IPFControl	cntrl,
	IPFSessionMode	mode_req,
	const IPFUserID	userid,
	struct sockaddr	*local_sa_addr,
	struct sockaddr	*remote_sa_addr,
	IPFErrSeverity	*err_ret
);

/*
 * This function will be called by IPFRequestTestSession if
 * one of the endpoints of the test is on the localhost.
 * If err_ret returns IPFErrFATAL, IPFRequestTestSession/IPFProcessTestSession
 * will not continue, and return IPFErrFATAL as well.
 *
 * Only the IP address values will be set in the sockaddr structures -
 * i.e. port numbers will not be valid.
 *
 * If an application doesn't set this, all tests will be allowed.
 *
 * The application can use the "closure" pointer to store data that will
 * be passed onto the Open/Close and TestComplete functions. The intended
 * purpose of this pointer is to keep track of resources that are "reserved"
 * from this function - allowing the other functions to "free" or modify
 * those resource reservations.
 *
 * NOTE: Even if the application does not use the "closure" pointer to keep
 * track of resources - it should set the closure to a non-NULL value upon
 * return so the OpenFile function knows the file is being opened for
 * writing (a receiver context) and not being opened for reading (a fetch
 * context).
 */
#define IPFCheckTestPolicy	"IPFCheckTestPolicy"
typedef IPFBoolean (*IPFCheckTestPolicyFunc)(
	IPFControl	cntrl,
	IPFBoolean	local_sender,
	struct sockaddr	*local_sa_addr,
	struct sockaddr	*remote_sa_addr,
	socklen_t	sa_len,
	IPFTestSpec	*test_spec,
	void		**closure,
	IPFErrSeverity	*err_ret
);

/*
 * This function will be called when a test is "complete". It is used
 * to free resources that were allocated on behalf of the test including
 * memory associated with the "closure" pointer itself if necessary.
 */
#define IPFTestComplete		"IPFTestComplete"
typedef void (*IPFTestCompleteFunc)(
	IPFControl	cntrl,
	void		*closure,
	IPFAcceptType	aval
	);

/*
 * This function will be called by the test endpoint initialization
 * code to open a file for writing. It will also be called by the
 * fetch-session code to open an existing file to return the data
 * to an application. (fname_ret is PATH_MAX+1 to include a nul byte.)
 * (if 
 */
#define IPFOpenFile		"IPFOpenFile"
typedef FILE* (*IPFOpenFileFunc)(
	IPFControl	cntrl,
	void		*closure,
	IPFSID		sid,
	char		fname_ret[PATH_MAX+1]
	);

/*
 * This function will be called by the test endpoint "cleanup" code
 * to indicate that the given fp (from IPFOpenFile) is no longer needed.
 * This allows the implementation to do it's own cleanup based on policy.
 * For example, a delete-on-fetch functionality could be implemented here
 * to delete the given file now that is it no longer needed.
 */
#define IPFCloseFile		"IPFCloseFile"
typedef void (*IPFCloseFileFunc)(
	IPFControl	cntrl,
	void		*closure,
	FILE		*fp,
	IPFAcceptType	aval
	);

#ifndef	NDEBUG
/*
 * This integer type is used to aid in child-debugging. If IPFChildWait is
 * set and non-zero forked off endpoints will go into a busy-wait loop to
 * allow a debugger to attach to the process. (i.e. they will be hung until
 * attached and the loop variable modified with the debugger. This should
 * not strictly be needed, but the gdb on many of the test plateforms I
 * used did not implement the follow-fork-mode option.) This was a quick
 * fix. (This will not be used if ipcntrl is compiled with -DNDEBUG.)
 */
#define	IPFChildWait	"IPFChildWait"
#endif

extern IPFContext
IPFContextCreate(
	I2ErrHandle	eh
);

extern void
IPFContextFree(
	IPFContext	ctx
);

extern I2ErrHandle
IPFContextGetErrHandle(
	IPFContext	ctx
	);

extern IPFBoolean
IPFContextConfigSet(
	IPFContext	ctx,
	const char	*key,
	void		*value
	);

extern void*
IPFContextConfigGet(
	IPFContext	ctx,
	const char	*key
	);

extern IPFBoolean
IPFContextConfigDelete(
	IPFContext	ctx,
	const char	*key
	);

/*
 * The following functions are completely analogous to the Context versions
 * but are used to maintain state information about a particular control
 * connection.
 */
extern IPFBoolean
IPFControlConfigSet(
	IPFControl	cntrl,
	const char	*key,
	void		*value
	);

extern void*
IPFControlConfigGet(
	IPFControl	cntrl,
	const char	*key
	);

extern IPFBoolean
IPFControlConfigDelete(
	IPFControl	cntrl,
	const char	*key
	);

/*
 * The IPFAddrBy* functions are used to allow the IPF API to more
 * adequately manage the memory associated with the many different ways
 * of specifying an address - and to provide a uniform way to specify an
 * address to the main API functions.
 * These functions return NULL on failure. (They call the error handler
 * to specify the reason.)
 */
extern IPFAddr
IPFAddrByNode(
	IPFContext	ctx,
	const char	*node	/* dns or valid char representation of addr */
);

extern IPFAddr
IPFAddrByAddrInfo(
	IPFContext		ctx,
	const struct addrinfo	*ai	/* valid addrinfo linked list	*/
);

extern IPFAddr
IPFAddrBySockFD(
	IPFContext	ctx,
	int		fd	/* fd must be an already connected socket */
);

/*
 * Return the address for the local side of the control connection.
 * (getsockname)
 */
IPFAddr
IPFAddrByLocalControl(
	IPFControl cntrl
	);

void
IPFAddrNodeName(
	IPFAddr	addr,
	char	*buf,
	size_t	*len	/* in/out parameter for buf len */
	);

void
IPFAddrNodeService(
	IPFAddr	addr,
	char	*buf,
	size_t	*len	/* in/out parameter for buf len */
	);

/*
 * return FD for given IPFAddr or -1 if it doesn't refer to a socket yet.
 */
extern int
IPFAddrFD(
	IPFAddr	addr
	);

/*
 * return socket address length (for use in calling accept etc...)
 * or 0 if it doesn't refer to a socket yet.
 */
extern socklen_t
IPFAddrSockLen(
	IPFAddr	addr
	);

extern IPFErrSeverity
IPFAddrFree(
	IPFAddr	addr
);

/*
 * IPFControlOpen allocates an IPFclient structure, opens a connection to
 * the IPF server and goes through the initialization phase of the
 * connection. This includes AES/CBC negotiation. It returns after receiving
 * the ServerOK message.
 *
 * This is typically only used by an IPF client application (or a server
 * when acting as a client of another IPF server).
 *
 * err_ret values:
 * 	IPFErrOK	completely successful - highest level mode ok'd
 * 	IPFErrINFO	session connected with less than highest level mode
 * 	IPFErrWARNING	session connected but future problems possible
 * 	IPFErrFATAL	function will return NULL - connection is closed.
 * 		(Errors will have been reported through the IPFErrFunc
 * 		in all cases.)
 * function return values:
 * 	If successful - even marginally - a valid IPFclient handle
 * 	is returned. If unsuccessful, NULL is returned.
 *
 * local_addr can only be set using IPFAddrByNode or IPFAddrByAddrInfo
 * server_addr can use any of the IPFAddrBy* functions.
 *
 * Once an IPFAddr record is passed into this function - it is
 * automatically free'd and should not be referenced again in any way.
 *
 * Client
 */
extern IPFControl
IPFControlOpen(
	IPFContext	ctx,
	IPFAddr		local_addr,	/* src addr or NULL		*/
	IPFAddr		server_addr,	/* server addr or NULL		*/
	u_int32_t	mode_mask,	/* OR of IPFSessionMode vals	*/
	IPFUserID	userid,		/* null if unwanted		*/
	IPFNum64	*uptime_ret,	/* server uptime - ret or NULL	*/
	IPFErrSeverity	*err_ret
);

/*
 * The following function is used to query the time/errest from
 * the remote server. This is useful for determining if a control
 * connection is still valid and to fetch the current NTP errest
 * from that system since it could change. It also updates the
 * control connections idea of the IPFGetRTTBound
 *
 * Client
 */
extern IPFErrSeverity
IPFControlTimeCheck(
	IPFControl	cntrl,
	IPFTimeStamp	*remote_time
	);

/*
 * Client and Server
 */
extern IPFErrSeverity
IPFControlClose(
	IPFControl	cntrl
);

/*
 * Request a test session - if the function returns True, then avail_time_ret
 * holds the time of the reservation. The first time this function is called
 * to configure a 'receiver', the sid will be returned. If it is called to
 * configure a 'sender', then sid MUST be passed in. (This function
 * can be called with a req_time later than the latest_time to cancel
 * a session.) This function can be called repeatedly to change the reservation
 * time. All future calls MUST pass in the same sid until this session is
 * declared invalid. (For these modify calls - the only parameters that
 * are looked at in the test_spec are the req_time and the latest_time. All
 * other parameters are preserved from the previous call.)
 *
 * Exactly one of a receiver OR a sender may be configured with each call.
 *
 * If the function returns False - check err_ret. If err_ret is ErrOK, the
 * session was denied by the server, and the control connection is still
 * valid. In this case, if (avail_time_ret != 0), then the server was
 * acceptible to the parameters of the request, but simply did not have
 * the resources available.
 *
 * Reasons this function will return False:
 * 1. Server denied test: err_ret==ErrOK
 * 	If avail_time_ret == 0, than no reason can be determined.
 * 	If avail_time_ret != 0, the client should interpret this is "busy".
 * 2. Control connection failure: err_ret == ErrFATAL
 * 3. Local resource problem (malloc/fork/fdopen): err_ret == ErrFATAL
 * 4. Bad addresses: err_ret == ErrWARNING
 *
 * Once an IPFAddr record has been passed into this function, it
 * is automatically free'd. It should not be referenced again in any way.
 *
 * Conversely, the test_spec is completely copied, and the caller continues
 * to "own" all memory associated with it after this call.
 *
 * Client
 */
extern IPFBoolean
IPFSessionRequest(
	IPFControl	control_handle,
	IPFBoolean	sender,
	IPFTestSpec	*test_spec,
	IPFTimeStamp	*avail_time_ret,
	u_int16_t	*recv_port,
	IPFSID		sid_ret,
	IPFErrSeverity	*err_ret
);

/*
 * Start all test sessions - if successful, returns IPFErrOK.
 *
 * Client and Server
 */
extern IPFErrSeverity
IPFStartSession(
	IPFControl	control_handle,
	u_int16_t	*dataport
);

/*
 * Wait for test sessions to complete. This function will return the
 * following integer values:
 * 	<0	ErrorCondition
 * 	0	StopSession received, acted upon, and sent back.
 * 	1	wake_time reached
 *
 *	2	system event (signal)
 *
 * To effect a poll - specify a waketime in the past. 1 will be returned
 * if there is nothing to read.
 *
 * To use a signal interaction instead of the waketime interface, set the
 * retn_on_intr pointer. Install a signal handler that sets the value
 * to non-zero, and this function will return 2. (If wake_time is non-null,
 * retn_on_intr is not used.) This interface can be used without signal
 * handlers as well be simply passing in a pointer to a non-zero value.
 * This function will return for any interrupt. (The signal interface
 * allows you to set the value to non-zero only for signals you are
 * actually interested in.)
 *
 * To block indefinately, specify NULL for wake_time and NULL for
 * retn_on_intr. (StopSessionWait will poll the status of current tests
 * automatically whenever a system event takes place in this case, so
 * StopSessionWait will never return 1 or 2 in this case.)
 *
 * If wake_time or retn_on_intr is set, and this function returns 1 or 2, then
 * it is required to poll the status of each local endpoint using
 * IPFTestSessionStatus until all sessions complete.  (IPFSessionsActive is
 * a simple way to poll all of them - you know you are done when it returns 0.)
 * You can of course recall StopSessionWait in this case.
 *
 * Server Only
 */
extern int
IPFStopSessionWait(
	IPFControl	control_handle,
	IPFNum64	*wake_time,		/* abs time */
	int		*retn_on_intr,
	IPFAcceptType	*acceptval,		/* out */
	IPFErrSeverity	*err_ret
);

/*
 * Used to poll the status of a test endpoint.
 *
 * returns:
 * 		True if it could get the status,
 * 		False if it could not. (session with given sid wasn't found,
 * 		or "send" indicated a remote endpoint.)
 *
 * 		aval returns the following for status:
 * 	<0	Test is not yet complete.
 * 	>=0	Accept value of completed test. 0 indicates success
 * 		other values indicate type of error test encountered.
 *
 * Server Only
 */
extern IPFBoolean
IPFSessionStatus(
	IPFControl	cntrl,
	IPFSID		sid,	/* SID of test to poll	*/
	IPFAcceptType	*aval	/* out - return accept value	*/
	);

/*
 * Used to determine how many local endpoints are still active.
 * (effectively calls the IPFTestSessionStatus function on all endpoints
 * and determines if they are complete yet.)
 *
 * If acceptval is non-null it is set to the MAX acceptval of any
 * complete session.
 *
 * returns:
 * 	number of active endpoints.
 *
 * Server Only
 */
extern int
IPFSessionsActive(
		IPFControl	cntrl,
		IPFAcceptType	*acceptval	/* rtn */
		);

/*
 * Send the StopSession message, and wait for the response.
 *
 * Server Only
 */
extern IPFErrSeverity
IPFStopSession(
	IPFControl	control_handle,
	int		*retn_on_intr,
	IPFAcceptType	*acceptval	/* in/out */
);

/*
 * Signal the server to stop the session, and read the response.
 * The response should contain the test results, and they will
 * be printed to the fp passed in.
 *
 * Client Only
 */
extern IPFErrSeverity
IPFEndSession(
	IPFControl	cntrl,
	int		*retn_on_intr,
	FILE		*fp
	);

/*
 * Return the file descriptor being used for the control connection. An
 * application can use this to call select or otherwise poll to determine
 * if anything is ready to be read but they should not read or write to
 * the descriptor.
 * This can be used in conjunction with the IPFStopSessionWait
 * function so that the application can recieve user input, and only call
 * the IPFStopSessionWait function when there is something to read
 * from the connection. (A nul timestamp would be used in this case
 * so that IPFStopSessionWait does not block.)
 *
 * This is also useful in a policy context - getpeername can be called
 * on this descriptor.
 *
 * If the control_handle is no longer connected - the function will return
 * a negative value.
 *
 * Client and Server.
 */
extern int
IPFControlFD(
	IPFControl	control_handle
);

extern int
IPFErrorFD(
	IPFContext	ctx
	);

extern
IPFAddr
IPFServerSockCreate(
	IPFContext	ctx,
	IPFAddr		addr,
	IPFErrSeverity	*err_ret
	);


/*!
 * Function:	IPFControlAccept
 *
 * Description:	
 * 		This function is used to initialiize the communication
 * 		to the peer.
 *           
 * In Args:	
 * 		connfd,connsaddr, and connsaddrlen are all returned
 * 		from "accept".
 *
 * Returns:	Valid IPFControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *
 *              If *rtn_on_intr and an inturrupt happens during write/read
 *              err_ret will be set to IPFErrWARNING.
 *
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
extern IPFControl
IPFControlAccept(
	IPFContext	ctx,		/* library context		*/
	int		connfd,		/* conencted socket		*/
	struct sockaddr	*connsaddr,	/* connected socket addr	*/
	socklen_t	connsaddrlen,	/* connected socket addr len	*/
	u_int32_t	mode_offered,	/* advertised server mode	*/
	IPFNum64	uptime,		/* uptime report		*/
	int		*retn_on_intr,	/* return on i/o interrupt	*/
	IPFErrSeverity	*err_ret	/* err - return			*/
		 );

typedef enum IPFRequestType{
	IPFReqInvalid=-1,
	IPFReqSockClose=0,
	IPFReqTest=1,
	IPFReqStartSession=2,
	IPFReqStopSession=3,
	IPFReqTime=4
} IPFRequestType;

extern IPFRequestType
IPFReadRequestType(
		IPFControl	cntrl,
		int		*retn_on_intr
		);

extern IPFErrSeverity
IPFProcessTestRequest(
	IPFControl	cntrl,
	int		*retn_on_intr
	);

extern IPFErrSeverity
IPFProcessTimeRequest(
	IPFControl	cntrl,
	int		*retn_on_intr
	);

extern IPFErrSeverity
IPFProcessStartSession(
	IPFControl	cntrl,
	int		*retn_on_intr
	);

extern IPFErrSeverity
IPFProcessStopSession(
	IPFControl	cntrl
	);

extern IPFContext
IPFGetContext(
	IPFControl	cntrl
	);

extern IPFSessionMode
IPFGetMode(
	IPFControl	cntrl
	);


/*
 * Returns bytes/second: 0.0 on error.
 */
extern double
IPFTestPacketBandwidth(
		IPFContext	ctx,
		int		af,
		IPFSessionMode	mode,
		IPFTestSpec	*tspec
		);

/*
 * buff must be at least (nbytes*2) +1 long or memory will be over-run.
 */
/* IN:bytes - OUT:char's */
extern void
IPFHexEncode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	);

/* IN:chars - OUT: bytes (False if chars not hex) */
extern IPFBoolean
IPFHexDecode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	);

/*
 * time.c conversion functions.
 */

#define	IPFJAN_1970	(unsigned long)0x83aa7e80	/* diffs in epoch*/

#ifndef	tvalclear
#define	tvalclear(a)	(a)->tv_sec = (a)->tv_usec = 0
#endif
#ifndef	tvaladd
#define tvaladd(a,b)					\
	do{						\
		(a)->tv_sec += (b)->tv_sec;		\
		(a)->tv_usec += (b)->tv_usec;		\
		if((a)->tv_usec >= 1000000){		\
			(a)->tv_sec++;			\
			(a)->tv_usec -= 1000000;	\
		}					\
	} while (0)
#endif
#ifndef	tvalsub
#define tvalsub(a,b)					\
	do{						\
		(a)->tv_sec -= (b)->tv_sec;		\
		(a)->tv_usec -= (b)->tv_usec;		\
		if((a)->tv_usec < 0){			\
			(a)->tv_sec--;			\
			(a)->tv_usec += 1000000;	\
		}					\
	} while (0)
#endif

#ifndef	tvalcmp
#define	tvalcmp(tvp,uvp,cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?			\
	 	((tvp)->tv_usec cmp (uvp)->tv_usec) :		\
		((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

/* Operations on timespecs */
#ifndef	timespecclear
#define timespecclear(tvp)      ((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#endif

#ifndef	timespecisset
#define timespecisset(tvp)      ((tvp)->tv_sec || (tvp)->tv_nsec)
#endif

#ifndef	timespeccmp
#define timespeccmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
		((tvp)->tv_nsec cmp (uvp)->tv_nsec) :			\
		((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef	timespecadd
#define timespecadd(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec += (uvp)->tv_sec;				\
		(vvp)->tv_nsec += (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec >= 1000000000){			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_nsec -= 1000000000;			\
		}							\
	} while (0)
#endif

#ifndef timespecsub
#define timespecsub(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec -= (uvp)->tv_sec;				\
		(vvp)->tv_nsec -= (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_nsec += 1000000000;			\
		}							\
	} while (0)
#endif

#ifndef	timespecdiff
#define	timespecdiff(vvp,uvp)						\
	do {								\
		struct timespec	ts1_,ts2_;				\
		if(timespeccmp(vvp,uvp,>)){				\
			ts1_ = *vvp;					\
			ts2_ = *uvp;					\
		}else{							\
			ts1_ = *uvp;					\
			ts2_ = *vvp;					\
		}							\
		timespecsub(&ts1_,&ts2_);				\
		*vvp = ts1_;						\
	} while(0)
#endif

extern IPFNum64
IPFGetRTTBound(
	IPFControl	cntrl
	);

extern double
IPFGetTimeStampError(
	IPFTimeStamp	*tstamp
	);

extern IPFTimeStamp *
IPFGetTimestamp(
	IPFContext	ctx,
	IPFTimeStamp	*tstamp
);

extern IPFTimeStamp *
IPFTimevalToTimestamp(
	IPFTimeStamp	*tstamp,
	struct timeval	*tval
);

extern struct timeval *
IPFTimestampToTimeval(
	struct timeval	*tval,
	IPFTimeStamp	*tstamp
	);

extern IPFTimeStamp *
IPFTimespecToTimestamp(
	IPFTimeStamp	*tstamp,
	struct timespec	*tval,
	u_int32_t	*errest,	/* usec's */
	u_int32_t	*last_errest	/* usec's */
	);

extern struct timespec *
IPFTimestampToTimespec(
	struct timespec	*tval,
	IPFTimeStamp	*tstamp
	);

#endif	/* OWAMP_H */
