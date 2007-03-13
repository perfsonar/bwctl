/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabls-mode: nil -*-
 *      $Id$
 */
/************************************************************************
 *                                                                      *
 *                           Copyright (C)  2003                        *
 *                               Internet2                              *
 *                           All Rights Reserved                        *
 *                                                                      *
 ************************************************************************/
/*
 **    File:         bwlib.h
 **
 **    Author:       Jeff W. Boote
 **
 **    Date:         Tue Sep  9 15:44:43 MDT 2003
 **
 **    Description:    
 **    This header file describes the bwlib API. The bwlib API is intended
 **    to provide a portable layer for implementing the bwlib protocol.
 */
#ifndef    IPCNTRL_H
#define    IPCNTRL_H

#include <I2util/util.h>

/*
 * Portablility sanity checkes.
 */
#if    HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <bwlib/config.h>

#if    !HAVE_ERRNO_H || !HAVE_NETDB_H || !HAVE_STDLIB_H || !HAVE_SYS_PARAM_H
#error    Missing Header!
#endif

#if    !HAVE_GETADDRINFO || !HAVE_SOCKET
#error    Missing needed networking capabilities! (getaddrinfo and socket)
#endif


#if    !HAVE_MALLOC || !HAVE_MEMSET
#error    Missing needed memory functions!
#endif
#endif    /* HAVE_CONFIG_H */

#ifndef    HAVE___ATTRIBUTE__
#define __attribute__(x)
#endif

#if    defined HAVE_DECL_FSEEKO && !HAVE_DECL_FSEEKO
#define fseeko(a,b,c) fseek(a,b,c)
#endif

#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#include <time.h>

#ifndef    False
#define    False    (0)
#endif
#ifndef    True
#define    True    (!False)
#endif

#ifndef MIN
#define MIN(a,b) ((a<b)?a:b)
#endif
#ifndef MAX
#define MAX(a,b) ((a>b)?a:b)
#endif

/*
 * Filename/path component macros used by various parts of bwlib.
 */
#ifndef BWL_PATH_SEPARATOR
#define    BWL_PATH_SEPARATOR    "/"
#endif
#ifndef    BWL_PATH_SEPARATOR_LEN
#define    BWL_PATH_SEPARATOR_LEN    1
#endif
#ifndef    BWL_FILE_EXT
#define    BWL_FILE_EXT    ".bw"
#endif

/*
 * The ascii decimal encoding of the 64 bit timestamps takes this many
 * chars. Log(2^64)
 *
 * fmt indicates 0 padding, 20 significant digits.
 */
#ifndef BWL_TSTAMPFMT 
#define BWL_TSTAMPFMT  "%020llu"
#endif

#ifndef BWL_TSTAMPCHARS
#define BWL_TSTAMPCHARS  20
#endif

#include <bwlib/rijndael-api-fst.h>

/* Default mode offered by the server */
#define BWL_DEFAULT_OFFERED_MODE     (BWL_MODE_OPEN|BWL_MODE_AUTHENTICATED|BWL_MODE_ENCRYPTED)

/*
 * TODO: 4823 should eventually be replaced by an IANA blessed service name.
 */
#define BWL_CONTROL_SERVICE_NUMBER    4823
#define BWL_CONTROL_SERVICE_NAME    "4823"

/*
 * Default value to use for the listen backlog. We pick something large
 * and let the OS truncate it if it isn't willing to do that much.
 */
#define BWL_LISTEN_BACKLOG    (64)

/*
 * BWLNum64 is interpreted as 32bits of "seconds" and 32bits of
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
 * tstamp.
 * They are interpreted as follows:
 * multiplier*(2^(-32))*(2^Scale)
 *
 * (implementor note)
 * Effectively, this breaks down such that if Scale is 0, then the multiplier
 * is the error in the same scale as the fractional seconds of tstamp.
 * Therefore, for "real" errors greater than an 8 bit number at that scale
 * the value can just be right shifted until it fits into an 8 bit integer,
 * and the number of shifts would indicate the "Scale" value.
 */
typedef uint64_t BWLNum64;

/*
 * Arithmetic/Conversion functions on BWLNum64 numbers.
 */

/*
 * These macros should be used instead of directly using
 * arithmetic on these types in the event that the underlying
 * type is changed from an uint64_t to some kind of structure.
 *
 */
#define BWLNum64Diff(x,y)    ((x>y) ? (x-y) : (y-x))
#define BWLNum64Add(x,y)    (x+y)
#define BWLNum64Sub(x,y)    (x-y)
#define BWLNum64Cmp(x,y)    ((x<y) ? -1 : ((x>y) ? 1 : 0))
#define BWLNum64Min(x,y)    ((x<y) ? x : y)
#define BWLNum64Max(x,y)    ((x>y) ? x : y)

extern BWLNum64
BWLNum64Mult(
        BWLNum64    x,
        BWLNum64    y
        );

extern BWLNum64
BWLULongToNum64(
        uint32_t    from);


extern void
BWLNum64ToTimeval(
        struct timeval    *to,
        BWLNum64    from
        );

extern void
BWLTimevalToNum64(
        BWLNum64    *to,
        struct timeval    *from
        );

extern void
BWLNum64ToTimespec(
        struct timespec    *to,
        BWLNum64    from
        );

extern void
BWLTimespecToNum64(
        BWLNum64    *to,
        struct timespec    *from
        );

extern double
BWLNum64ToDouble(
        BWLNum64    from
        );

extern BWLNum64
BWLDoubleToNum64(
        double        from
        );

extern BWLNum64
BWLUsecToNum64(uint32_t usec);

/*
 * These structures are opaque to the API user.
 * They are used to maintain state internal to the library.
 */
typedef struct BWLContextRec    *BWLContext;
typedef struct BWLControlRec    *BWLControl;
typedef struct BWLAddrRec    *BWLAddr;

/*
 * TimeStamp related types and structures needed throughout.
 */

typedef struct BWLTimeStampRec{
    BWLNum64        tstamp;
    uint8_t        sync;
    uint8_t        multiplier;
    uint8_t        scale;
} BWLTimeStamp;


/* Codes for returning error severity and type. */
/* when possible, values are mapped to syslog "priorities" we want to use. */
typedef enum {
    BWLErrFATAL=LOG_ERR,
    BWLErrWARNING=LOG_WARNING,
    BWLErrINFO=LOG_INFO,
    BWLErrDEBUG=LOG_DEBUG,
    BWLErrOK=I2LOG_NONE
} BWLErrSeverity;

typedef enum {
    BWLErrUNKNOWN=0,
    BWLErrPOLICY,
    BWLErrINVALID,
    BWLErrUNSUPPORTED
} BWLErrType;


/*
 * Valid values for "accept" - this will be added to for the purpose of
 * enumerating the reasons for rejecting a session, or early termination
 * of a test session.
 *
 * TODO:Get the additional "accept" values added to the spec.
 */
typedef enum{
    BWL_CNTRL_INVALID=-1,
    BWL_CNTRL_ACCEPT=0x0,
    BWL_CNTRL_REJECT=0x1,
    BWL_CNTRL_FAILURE=0x2,
    BWL_CNTRL_UNSUPPORTED=0x4
} BWLAcceptType;

/* Supported testers. */
typedef enum{
    BWL_TESTER_THRULAY=0x1,
    BWL_TESTER_IPERF=0x2,
    BWL_TESTER_NUTTCP=0x4
} BWLTester;

typedef uint32_t   BWLBoolean;
typedef uint8_t    BWLSID[16];
typedef uint8_t    BWLSequence[4];
typedef uint32_t   BWLTesterAvailability;

/*
 * technically the username in the client greeting message can have uint8_t
 * but this implementation limits it to a valid "char" type.
 */
#define    BWL_USERID_LEN    16
typedef char        BWLUserID[BWL_USERID_LEN+1];    /* add 1 for '\0' */
typedef uint8_t    BWLKey[16];

#define BWL_MODE_TESTER_NEGOTIATION_VERSION   (0x01000000)
#define BWL_MODE_TESTER_NEGOTIATION_MASK      (0xff000000)
#define BWL_MODE_UNDEFINED          (0x0)
#define BWL_MODE_LEAST_RESTRICTIVE  (0x80)
#define BWL_MODE_OPEN               (0x1)
#define BWL_MODE_AUTHENTICATED      (0x2)
#define BWL_MODE_ENCRYPTED          (0x4)
#define BWL_MODE_DOCIPHER           (BWL_MODE_AUTHENTICATED|BWL_MODE_ENCRYPTED)
#define BWL_MODE_ALLMODES           (BWL_MODE_DOCIPHER|BWL_MODE_OPEN)

typedef uint32_t    BWLSessionMode;
typedef uint32_t    BWLTesterNegotiationVersion;

typedef struct{
    BWLTester       tester;
    BWLAddr         sender;
    BWLAddr         receiver;
    BWLTimeStamp    req_time;
    BWLNum64        latest_time;
    uint32_t       duration;
    BWLBoolean      udp;
    uint8_t        tos;
    uint32_t       bandwidth;
    uint32_t       window_size;
    uint32_t       len_buffer;
    uint16_t       report_interval;
    uint8_t        parallel_streams;
    BWLBoolean      dynamic_window_size;
} BWLTestSpec;

typedef uint32_t   BWLPacketSizeT;

BWLTesterAvailability
LookForTesters(BWLContext ctx);

/*
 * an BWLScheduleContextRec is used to maintain state for the schedule
 * generator. Multiple contexts can be allocated to maintain multiple
 * "streams" of schedules.
 */
typedef struct BWLScheduleContextRec    *BWLScheduleContext;

BWLScheduleContext
BWLScheduleContextCreate(
        BWLContext  ctx,
        uint8_t    seed[16],
        uint32_t   mean
        );

void
BWLScheduleContextFree(
        BWLScheduleContext  sctx
        );

BWLErrSeverity
BWLScheduleContextReset(
        BWLScheduleContext  sctx,
        uint8_t            seed[16],
        uint32_t           mean
        );

BWLNum64
BWLScheduleContextGenerateNextDelta(
        BWLScheduleContext  sctx
        );

/*
 * Error Reporting:
 *
 * Notice that this macro expands to multiple statements so it is
 * imperative that you enclose it's use in {} in single statement
 * context's such as:
 *     if(test)
 *         BWLError(...);    NO,NO,NO,NO!
 * Instead:
 *     if(test){
 *         BWLError(...);
 *     }
 *
 *
 * (Sure would be nice if it were possible to do vararg macros...)
 */
#define BWLError    I2ErrLocation_(__FILE__,__DATE__,__LINE__);    \
BWLError_

/*
 * Don't call this directly - use the BWLError macro.
 *     Let me repeat.
 * Don't call this directly - use the BWLError macro.
 */
extern void
BWLError_(
        BWLContext      ctx,
        BWLErrSeverity  severity,
        BWLErrType      etype,
        const char      *fmt,
        ...
        );

/*
 * The "context"  is used to basically initializes the library. There is no
 * "global" state - so you can create more than one "context" if you like.
 * (Well... SIGPIPE is disabled... I suppose that is global.)
 *
 * There are specific defaults that can be modified within the context by
 * calling the BWLContextConfigSet function with the following keys and
 * types. (The key is a string - the type indicates what type of data
 * will be stored/retrieved using that key.
 */

/*
 * This type is used to hold a pointer to an integer pointer. That pointer
 * points at a value that determines if the low/level i/o functions should
 * return on interrupt. If it is non-zero an interrupt will cause the i/o
 * routine to fail and return. If it is zero, the low level i/o routine will
 * ignore the interrupt and restart the i/o.
 * (this can be used to ignore some signals and return on others.)
 */
#define BWLInterruptIO        "BWLInterruptIO"

/*
 * This context variable is used to hold a pointer to a port-range record. This
 * record is used to indicate what port ranges should be used for peer
 * server connections. (The connection used to verify clocks and share
 * test results.)
 */
#define BWLPeerPortRange    "BWLPeerPortRange"
typedef struct BWLPortRangeRec{
    uint16_t   low;
    uint16_t   high;
} BWLPortRangeRec, *BWLPortRange;

/*
 * This types are used to hold the path to the iperf/thrulay executables.
 * (char *)
 */
#define    BWLIperfCmd           "BWLIperfCmd"
#define    BWLNuttcpCmd          "BWLNuttcpCmd"

/*
 * Which tester tool was selected ("iperf", "thrulay", etc.).
 * (char *)
 */
#define    BWLTester          "BWLTester"

/*
 * This type is used to hold a pointer to an unsigned-64 bit int that
 * holds a fallback value for the bottleneckcapacity. This is used with
 * a rtt estimate to dynamically size the send/recv window sizes.
 * (uint64_t)
 */
#define BWLBottleNeckCapacity    "BWLBottleNeckCapacity"

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
#define    BWLGetAESKey        "BWLGetAESKey"
typedef BWLBoolean  (*BWLGetAESKeyFunc)(
        BWLContext      ctx,
        const BWLUserID userid,
        uint8_t        *key_ret,
        BWLErrSeverity  *err_ret
        );

/*
 * This function will be called from BWLControlOpen and BWLServerAccept
 * to determine if the control connection should be accepted.
 * It is called after connecting, and after determining the userid.
 * On failure, value of *err_ret can be inspected: if > BWLErrWARNING,
 * this means rejection based on policy, otherwise there was an error
 * in the function itself.
 *
 * If an application doesn't set this, all connections will be allowed.
 */
#define BWLCheckControlPolicy    "BWLCheckControlPolicy"
typedef BWLBoolean (*BWLCheckControlPolicyFunc)(
        BWLControl    cntrl,
        BWLSessionMode    mode_req,
        const BWLUserID    userid,
        struct sockaddr    *local_sa_addr,
        struct sockaddr    *remote_sa_addr,
        BWLErrSeverity    *err_ret
        );

/*
 * This function will be called by BWLRequestTestSession if
 * one of the endpoints of the test is on the localhost.
 * If err_ret returns BWLErrFATAL, BWLRequestTestSession/BWLProcessTestSession
 * will not continue, and return BWLErrFATAL as well.
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
#define BWLCheckTestPolicy    "BWLCheckTestPolicy"
typedef BWLBoolean (*BWLCheckTestPolicyFunc)(
        BWLControl    cntrl,
        BWLSID        sid,
        BWLBoolean    local_sender,
        struct sockaddr    *local_sa_addr,
        struct sockaddr    *remote_sa_addr,
        socklen_t    sa_len,
        BWLTestSpec    *test_spec,
        BWLNum64    fuzz_time,
        BWLNum64    *reservation_ret,
        uint16_t    *port_ret,
        void        **closure,
        BWLErrSeverity    *err_ret
        );

/*
 * This function will be called when a test is "complete". It is used
 * to free resources that were allocated on behalf of the test including
 * memory associated with the "closure" pointer itself if necessary.
 */
#define BWLTestComplete        "BWLTestComplete"
typedef void (*BWLTestCompleteFunc)(
        BWLControl    cntrl,
        void        *closure,
        BWLAcceptType    aval
        );

/*
 * This function will be called when tests are complete and results
 * are available.
 * (The function should handle the case where the FILE*'s are null. This
 * simply means that test results are unavailable.)
 */
#define BWLProcessResults    "BWLProcessResults"
typedef BWLErrSeverity (*BWLProcessResultsFunc)(
        BWLControl    cntrl,
        BWLBoolean    local_sender,
        BWLTestSpec    *tspec,
        FILE        *sendfp,
        FILE        *recvfp
        );

/*
 * This value is used to increase the tolerance of bwctld to deal
 * with incorrectly configured ntpd processes. Specified as a (*double).
 */
#define BWLSyncFuzz    "BWLSyncFuzz"

/*
 * This value is used to indicate if NTP synchronization is required
 * for tests to happen. If this value is set, then the application
 * can attempt to continue without determining if the current clock
 * is really synchronized.
 */
#define BWLAllowUnsync  "BWLAllowUnsync"

#ifndef    NDEBUG
/*
 * This integer type is used to aid in child-debugging. If BWLChildWait is
 * set and non-zero forked off endpoints will go into a busy-wait loop to
 * allow a debugger to attach to the process. (i.e. they will be hung until
 * attached and the loop variable modified with the debugger. This should
 * not strictly be needed, but the gdb on many of the test plateforms I
 * used did not implement the follow-fork-mode option.) This was a quick
 * fix. (This will not be used if bwlib is compiled with -DNDEBUG.)
 */
#define    BWLChildWait    "BWLChildWait"
#endif

extern BWLContext
BWLContextCreate(
        I2ErrHandle    eh,
        ...
        );

extern void
BWLContextFree(
        BWLContext    ctx
        );

extern I2ErrHandle
BWLContextGetErrHandle(
        BWLContext  ctx
        );

extern void
BWLContextSetAccessLogPriority(
        BWLContext  ctx,
        int         prio
        );

extern BWLBoolean
BWLContextConfigSet(
        BWLContext  ctx,
        const char  *key,
        void        *value
        );

extern void*
BWLContextConfigGet(
        BWLContext    ctx,
        const char    *key
        );

extern BWLBoolean
BWLContextConfigDelete(
        BWLContext    ctx,
        const char    *key
        );

/*
 * The following functions are completely analogous to the Context versions
 * but are used to maintain state information about a particular control
 * connection.
 */
extern BWLBoolean
BWLControlConfigSet(
        BWLControl    cntrl,
        const char    *key,
        void        *value
        );

extern void*
BWLControlConfigGet(
        BWLControl    cntrl,
        const char    *key
        );

extern BWLBoolean
BWLControlConfigDelete(
        BWLControl    cntrl,
        const char    *key
        );

/*
 * The BWLAddrBy* functions are used to allow the BWL API to more
 * adequately manage the memory associated with the many different ways
 * of specifying an address - and to provide a uniform way to specify an
 * address to the main API functions.
 * These functions return NULL on failure. (They call the error handler
 * to specify the reason.)
 */
extern BWLAddr
BWLAddrByNode(
        BWLContext    ctx,
        const char    *node    /* dns or valid char representation of addr */
        );

extern BWLAddr
BWLAddrByWildcard(
        BWLContext  ctx,
        int         socktype
        );

extern BWLAddr
BWLAddrBySAddr(
        BWLContext      ctx,
        struct sockaddr *saddr,
        socklen_t       saddr_len,
        int             socktype
        );

/*
 * Return the address for the remote side of the given socket.
 * (wrapper for getpeername)
 */
extern BWLAddr
BWLAddrBySockFD(
        BWLContext    ctx,
        int        fd    /* fd must be an already connected socket */
        );

/*
 * Return the address for the remote side of the given socket.
 * (wrapper for getsockname)
 */
extern BWLAddr
BWLAddrByLocalSockFD(
        BWLContext    ctx,
        int        fd    /* fd must be an already connected socket */
        );

/*
 * Return the address for the remote side of the control connection.
 * (getpeername)
 */
BWLAddr
BWLAddrByControl(
        BWLControl    cntrl
        );

/*
 * Return the address for the local side of the control connection.
 * (getsockname)
 */
BWLAddr
BWLAddrByLocalControl(
        BWLControl    cntrl
        );

/*
 * Addr access functions.
 * The set functions are only valid *before* a real socket is associated
 * with the Addr. So, the internal fd cannot be set upon entrance.
 */
BWLBoolean
BWLAddrSetSAddr(
        BWLAddr         addr,
        struct sockaddr *saddr,
        socklen_t       saddr_len
        );

BWLBoolean
BWLAddrSetFD(
        BWLAddr addr,
        int     fd,
        int     close_on_free
        );

BWLBoolean
BWLAddrSetPort(
        BWLAddr     addr,
        uint16_t   port
        );

BWLBoolean
BWLAddrSetSocktype(
        BWLAddr addr,
        int     so_type
        );

BWLBoolean
BWLAddrSetPassive(
        BWLAddr     addr,
        BWLBoolean  passive
        );

struct addrinfo
*BWLAddrAddrInfo(
        BWLAddr     addr,
        char        *def_node,
        char        *def_serv
        );

BWLBoolean
BWLAddrNodeName(
        BWLAddr addr,
        char    *buf,
        size_t  *len    /* in/out parameter for buf len */
        );

BWLBoolean
BWLAddrNodeService(
        BWLAddr addr,
        char    *buf,
        size_t  *len    /* in/out parameter for buf len */
        );

/*
 * return FD for given BWLAddr or -1 if it doesn't refer to a socket yet.
 */
extern int
BWLAddrFD(
        BWLAddr    addr
        );

/*
 * return socket address length (for use in calling accept etc...)
 * or 0 if it doesn't refer to a socket yet.
 */
extern socklen_t
BWLAddrSockLen(
        BWLAddr    addr
        );

extern BWLErrSeverity
BWLAddrFree(
        BWLAddr    addr
        );

/*
 * BWLControlOpen allocates an BWLclient structure, opens a connection to
 * the BWL server and goes through the initialization phase of the
 * connection. This includes AES/CBC negotiation. It returns after receiving
 * the ServerOK message.
 *
 * This is typically only used by an BWL client application (or a server
 * when acting as a client of another BWL server).
 *
 * err_ret values:
 *     BWLErrOK         completely successful - highest level mode ok'd
 *     BWLErrINFO       session connected with less than highest level mode
 *     BWLErrWARNING    session connected but future problems possible
 *     BWLErrFATAL      function will return NULL - connection is closed.
 *         (Errors will have been reported through the BWLErrFunc
 *         in all cases.)
 * function return values:
 *     If successful - even marginally - a valid BWLclient handle
 *     is returned. If unsuccessful, NULL is returned.
 *
 * local_addr can only be set using BWLAddrByNode or BWLAddrByAddrInfo
 * server_addr can use any of the BWLAddrBy* functions.
 *
 * Once an BWLAddr record is passed into this function - it is
 * automatically free'd and should not be referenced again in any way.
 *
 * Client
 */
extern BWLControl
BWLControlOpen(
        BWLContext    ctx,
        BWLAddr        local_addr,    /* src addr or NULL        */
        BWLAddr        server_addr,    /* server addr or NULL        */
        uint32_t    mode_mask,    /* OR of BWLSessionMode vals    */
        BWLUserID    userid,        /* null if unwanted        */
        BWLNum64    *uptime_ret,    /* server uptime - ret or NULL    */
	BWLTesterAvailability	*avail_testers,	/* server supported testers */
        BWLErrSeverity    *err_ret
        );

/*
 * The following function is used to query the time/errest from
 * the remote server. This is useful for determining if a control
 * connection is still valid and to fetch the current NTP errest
 * from that system since it could change. It also updates the
 * control connections idea of the BWLGetRTTBound
 *
 * Client
 */
extern BWLErrSeverity
BWLControlTimeCheck(
        BWLControl    cntrl,
        BWLTimeStamp    *remote_time
        );

/*
 * Client and Server
 */
extern BWLErrSeverity
BWLControlClose(
        BWLControl    cntrl
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
 *     If avail_time_ret == 0, than no reason can be determined.
 *     If avail_time_ret != 0, the client should interpret this is "busy".
 * 2. Control connection failure: err_ret == ErrFATAL
 * 3. Local resource problem (malloc/fork/fdopen): err_ret == ErrFATAL
 * 4. Bad addresses: err_ret == ErrWARNING
 *
 * Once an BWLAddr record has been passed into this function, it
 * is automatically free'd. It should not be referenced again in any way.
 *
 * Conversely, the test_spec is completely copied, and the caller continues
 * to "own" all memory associated with it after this call.
 *
 * Client
 */
extern BWLBoolean
BWLSessionRequest(
        BWLControl    control_handle,
        BWLBoolean    sender,
        BWLTestSpec    *test_spec,
        BWLTimeStamp    *avail_time_ret,
        uint16_t    *recv_port,
        BWLSID        sid_ret,
        BWLErrSeverity    *err_ret
        );

/*
 * Start all test sessions - if successful, returns BWLErrOK.
 *
 * Client and Server
 */
extern BWLErrSeverity
BWLStartSession(
        BWLControl    control_handle,
        uint16_t    *dataport
        );

/*
 * Wait for test sessions to complete. This function will return the
 * following integer values:
 *     <0    ErrorCondition
 *     0    StopSession received, acted upon, and sent back.
 *     1    wake_time reached
 *
 *    2    system event (signal)
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
 * BWLTestSessionStatus until all sessions complete.  (BWLSessionsActive is
 * a simple way to poll all of them - you know you are done when it returns 0.)
 * You can of course recall StopSessionWait in this case.
 *
 * Server Only
 */
extern int
BWLStopSessionWait(
        BWLControl      control_handle,
        BWLNum64        *wake_time,        /* abs time */
        int             *retn_on_intr,
        BWLAcceptType   *acceptval,        /* out */
        BWLErrSeverity  *err_ret
        );

/*
 * Used to poll the status of a test endpoint.
 *
 * returns:
 *         True if it could get the status,
 *         False if it could not. (session with given sid wasn't found,
 *         or "send" indicated a remote endpoint.)
 *
 *         aval returns the following for status:
 *     <0    Test is not yet complete.
 *     >=0    Accept value of completed test. 0 indicates success
 *         other values indicate type of error test encountered.
 *
 * Server Only
 */
extern BWLBoolean
BWLSessionStatus(
        BWLControl    cntrl,
        BWLSID        sid,    /* SID of test to poll    */
        BWLAcceptType    *aval    /* out - return accept value    */
        );

/*
 * Used to determine how many local endpoints are still active.
 * (effectively calls the BWLTestSessionStatus function on all endpoints
 * and determines if they are complete yet.)
 *
 * If acceptval is non-null it is set to the MAX acceptval of any
 * complete session.
 *
 * returns:
 *     number of active endpoints.
 *
 * Server Only
 */
extern int
BWLSessionsActive(
        BWLControl    cntrl,
        BWLAcceptType    *acceptval    /* rtn */
        );

/*
 * Send the StopSession message, and wait for the response.
 *
 * Server Only
 */
extern BWLErrSeverity
BWLStopSession(
        BWLControl    control_handle,
        int        *retn_on_intr,
        BWLAcceptType    *acceptval    /* in/out */
        );

/*
 * Signal the server to stop the session, and read the response.
 * The response should contain the test results, and they will
 * be printed to the fp passed in.
 *
 * Client Only
 */
extern BWLErrSeverity
BWLEndSession(
        BWLControl    cntrl,
        int        *retn_on_intr,
        FILE        *fp
        );

/*
 * Return the file descriptor being used for the control connection. An
 * application can use this to call select or otherwise poll to determine
 * if anything is ready to be read but they should not read or write to
 * the descriptor.
 * This can be used in conjunction with the BWLStopSessionWait
 * function so that the application can recieve user input, and only call
 * the BWLStopSessionWait function when there is something to read
 * from the connection. (A nul timestamp would be used in this case
 * so that BWLStopSessionWait does not block.)
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
BWLControlFD(
        BWLControl    control_handle
        );

extern int
BWLErrorFD(
        BWLContext    ctx
        );

extern
BWLAddr
BWLServerSockCreate(
        BWLContext    ctx,
        BWLAddr        addr,
        BWLErrSeverity    *err_ret
        );


/*!
 * Function:    BWLControlAccept
 *
 * Description:    
 *         This function is used to initialiize the communication
 *         to the peer.
 *           
 * In Args:    
 *         connfd,connsaddr, and connsaddrlen are all returned
 *         from "accept".
 *
 * Returns:    Valid BWLControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *
 *              If *rtn_on_intr and an inturrupt happens during write/read
 *              err_ret will be set to BWLErrWARNING.
 *
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
extern BWLControl
BWLControlAccept(
        BWLContext    ctx,        /* library context        */
        int        connfd,        /* conencted socket        */
        struct sockaddr    *connsaddr,    /* connected socket addr    */
        socklen_t    connsaddrlen,    /* connected socket addr len    */
        uint32_t    mode_offered,    /* advertised server mode    */
        BWLNum64    uptime,        /* uptime report        */
	BWLTesterAvailability  avail_testers, /* server available testers */
        int        *retn_on_intr,    /* return on i/o interrupt    */
        BWLErrSeverity    *err_ret    /* err - return            */
        );

typedef enum BWLRequestType{
    BWLReqInvalid=-1,
    BWLReqSockClose=0,
    BWLReqTest=1,
    BWLReqStartSession=2,
    BWLReqStopSession=3,
    BWLReqTime=4
} BWLRequestType;

extern BWLRequestType
BWLReadRequestType(
        BWLControl    cntrl,
        int        *retn_on_intr
        );

extern BWLErrSeverity
BWLProcessTestRequest(
        BWLControl    cntrl,
	BWLTesterAvailability avail_testers,
        int        *retn_on_intr
        );

extern BWLErrSeverity
BWLProcessTimeRequest(
        BWLControl    cntrl,
        int        *retn_on_intr
        );

extern BWLErrSeverity
BWLProcessStartSession(
        BWLControl    cntrl,
        int        *retn_on_intr
        );

extern BWLErrSeverity
BWLProcessStopSession(
        BWLControl    cntrl
        );

extern BWLContext
BWLGetContext(
        BWLControl    cntrl
        );

extern BWLSessionMode
BWLGetMode(
        BWLControl    cntrl
        );


/*
 * Returns bytes/second: 0.0 on error.
 */
extern double
BWLTestPacketBandwidth(
        BWLContext    ctx,
        int        af,
        BWLSessionMode    mode,
        BWLTestSpec    *tspec
        );

/*
 * time.c conversion functions.
 */

#define    BWLJAN_1970    (unsigned long)0x83aa7e80    /* diffs in epoch*/

#ifndef    tvalclear
#define    tvalclear(a)    (a)->tv_sec = (a)->tv_usec = 0
#endif
#ifndef    tvaladd
#define tvaladd(a,b)                        \
do{                                         \
    (a)->tv_sec += (b)->tv_sec;             \
        (a)->tv_usec += (b)->tv_usec;       \
        if((a)->tv_usec >= 1000000){        \
            (a)->tv_sec++;                  \
                (a)->tv_usec -= 1000000;    \
        }                                   \
} while (0)
#endif
#ifndef    tvalsub
#define tvalsub(a,b)                        \
do{                                         \
    (a)->tv_sec -= (b)->tv_sec;             \
        (a)->tv_usec -= (b)->tv_usec;       \
        if((a)->tv_usec < 0){               \
            (a)->tv_sec--;                  \
                (a)->tv_usec += 1000000;    \
        }                                   \
} while (0)
#endif

#ifndef    tvalcmp
#define    tvalcmp(tvp,uvp,cmp)         \
(((tvp)->tv_sec == (uvp)->tv_sec) ?     \
 ((tvp)->tv_usec cmp (uvp)->tv_usec) :  \
 ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

    /* Operations on timespecs */
#ifndef    timespecclear
#define timespecclear(tvp)      ((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#endif

#ifndef    timespecisset
#define timespecisset(tvp)      ((tvp)->tv_sec || (tvp)->tv_nsec)
#endif

#ifndef    timespeccmp
#define timespeccmp(tvp, uvp, cmp)          \
    (((tvp)->tv_sec == (uvp)->tv_sec) ?     \
     ((tvp)->tv_nsec cmp (uvp)->tv_nsec) :  \
     ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef    timespecadd
#define timespecadd(vvp, uvp)                       \
    do {                                            \
        (vvp)->tv_sec += (uvp)->tv_sec;             \
            (vvp)->tv_nsec += (uvp)->tv_nsec;       \
            if ((vvp)->tv_nsec >= 1000000000){      \
                (vvp)->tv_sec++;                    \
                    (vvp)->tv_nsec -= 1000000000;   \
            }                                       \
    } while (0)
#endif

#ifndef timespecsub
#define timespecsub(vvp, uvp)                   \
do {                                            \
    (vvp)->tv_sec -= (uvp)->tv_sec;             \
        (vvp)->tv_nsec -= (uvp)->tv_nsec;       \
        if ((vvp)->tv_nsec < 0) {               \
            (vvp)->tv_sec--;                    \
                (vvp)->tv_nsec += 1000000000;   \
        }                                       \
} while (0)
#endif

#ifndef    timespecdiff
#define    timespecdiff(vvp,uvp)        \
do {                                    \
    struct timespec    ts1_,ts2_;       \
        if(timespeccmp(vvp,uvp,>)){     \
            ts1_ = *vvp;                \
                ts2_ = *uvp;            \
        }else{                          \
            ts1_ = *uvp;                \
                ts2_ = *vvp;            \
        }                               \
    timespecsub(&ts1_,&ts2_);           \
        *vvp = ts1_;                    \
} while(0)
#endif

extern BWLNum64
BWLGetRTTBound(
        BWLControl    cntrl
        );

extern void
BWLSetTimeStampError(
        BWLTimeStamp    *tstamp,
        BWLNum64    err
        );

extern BWLNum64
BWLGetTimeStampError(
        BWLTimeStamp    *tstamp
        );

extern BWLTimeStamp *
BWLGetTimeStamp(
        BWLContext    ctx,
        BWLTimeStamp    *tstamp
        );

extern BWLTimeStamp *
BWLTimevalToTimeStamp(
        BWLTimeStamp    *tstamp,
        struct timeval    *tval
        );

extern struct timeval *
BWLTimeStampToTimeval(
        struct timeval    *tval,
        BWLTimeStamp    *tstamp
        );

extern BWLTimeStamp *
BWLTimespecToTimeStamp(
        BWLTimeStamp    *tstamp,
        struct timespec    *tval,
        uint32_t    *errest,    /* usec's */
        uint32_t    *last_errest    /* usec's */
        );

extern struct timespec *
BWLTimeStampToTimespec(
        struct timespec    *tval,
        BWLTimeStamp    *tstamp
        );

/*
 * util.c functions. (Basically a useful place to put config functions
 * that are needed by the spawned daemon of bwctl as well as the real
 * bwctld daemon.
 */
I2Boolean
BWLParsePorts(
        char            *pspec,
        BWLPortRange    prange_mem,
        BWLPortRange    *prange_ret,
        I2ErrHandle     ehand,
        FILE            *fout
        );

#endif    /* OWAMP_H */
