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
 *    File:         bwlibP.h
 *
 *    Author:       Jeff Boote
 *                  Internet2
 *
 *    Date:         Thu Sep 18 13:26:19 MDT 2003
 *
 *    Description:    
 *    This header file describes the internal-private bwlib API.
 */
#ifndef    IPCNTRLP_H
#define    IPCNTRLP_H

#include <stdint.h>
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
#include <sys/wait.h>
#include <netinet/in.h>

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  64
#endif

#ifndef PATH_MAX
#define PATH_MAX    1024
#endif

#include <I2util/util.h>
#include <bwlib/bwlib.h>

/* 
 ** Lengths (in 16-byte blocks) of various Control messages. 
 */
#define _BWL_RIJNDAEL_BLOCK_SIZE    16
#define _BWL_TIME_REQUEST_BLK_LEN   2
#define _BWL_TEST_REQUEST_BLK_LEN   8                /* may be 7 or 8 */
#define _BWL_START_SESSIONS_BLK_LEN 2
#define _BWL_STOP_SESSIONS_BLK_LEN  2
#define _BWL_CONTROL_ACK_BLK_LEN    2
#define _BWL_MAX_MSG_BLK_LEN        _BWL_TEST_REQUEST_BLK_LEN

#define _BWL_MAX_MSG    (_BWL_MAX_MSG_BLK_LEN*_BWL_RIJNDAEL_BLOCK_SIZE)
#define _BWL_TEST_REQUEST_PREAMBLE_SIZE    (_BWL_TEST_REQUEST_BLK_LEN*_BWL_RIJNDAEL_BLOCK_SIZE)
#define _BWL_TESTREC_SIZE    24

/*
 * Control state constants.
 */
/* initial & invalid */
#define    _BWLStateInitial     (0x0000)
#define    _BWLStateInvalid     (0x0000)
/* during negotiation */
#define    _BWLStateSetup       (0x0001)
#define    _BWLStateUptime      (_BWLStateSetup << 1)
/* after negotiation ready for requests */
#define    _BWLStateRequest     (_BWLStateUptime << 1)
/* test sessions are active  */
#define    _BWLStateTest        (_BWLStateRequest << 1)
/*
 * The following states are for partially read messages on the server.
 */
#define _BWLStateTestRequest    (_BWLStateTest << 1)
#define _BWLStateStartSession   (_BWLStateTestRequest << 1)
#define _BWLStateStopSession    (_BWLStateStartSession << 1)
#define _BWLStateTestAccept     (_BWLStateStopSession << 1)
#define _BWLStateStartAck       (_BWLStateTestAccept << 1)
#define _BWLStateTimeRequest    (_BWLStateStartAck << 1)
#define _BWLStateTimeResponse   (_BWLStateTimeRequest << 1)

/* Reading indicates partial read request-ReadRequestType without remainder */
#define _BWLStateReading    (_BWLStateTestRequest|_BWLStateStartSession|_BWLStateStopSession|_BWLStateTimeRequest)

/*
 * "Pending" indicates waiting for server response to a request.
 */
#define    _BWLStatePending         (_BWLStateTestAccept|_BWLStateStartAck|_BWLStateStopSession|_BWLStateTimeResponse)

#define _BWLStateIsInitial(c)       (!(c)->state)
#define _BWLStateIsSetup(c)         (!(_BWLStateSetup ^ (c)->state))

#define _BWLStateIs(teststate,c)    ((teststate & (c)->state))

#define _BWLStateIsRequest(c)       _BWLStateIs(_BWLStateRequest,c)
#define _BWLStateIsReading(c)       _BWLStateIs((_BWLStateReading),c)
#define _BWLStateIsPending(c)       _BWLStateIs(_BWLStatePending,c)
#define _BWLStateIsTest(c)          _BWLStateIs(_BWLStateTest,c)

/*
 * other useful constants.
 */
#define _BWL_DEFAULT_ACCESSPRIO BWLErrINFO
#define _BWL_DEFAULT_ERRORMASK  BWLErrOK
#define _BWL_DEFAULT_TMPDIR "/tmp"
#define _BWL_DEV_NULL       "/dev/null"
#define _BWL_ERR_MAXSTRING  (1024)
#define _BWL_PATH_SEPARATOR "/"
#define _BWL_TMPFILEFMT     "bwctl-tmp.XXXXXX"
#define _BWL_MAX_TOOLARGS  (36)

typedef struct BWLTestSessionRec BWLTestSessionRec, *BWLTestSession;

/*
 * Tool Data structures. The ToolRec is used to keep track of the actual
 * tools compiled into the given binary. (An array of these is allocated
 * as part of the BWLContext.
 */
typedef struct BWLToolRec{
    BWLToolType         id; /* what bits define this tool in the protocol? */
    BWLToolDefinition   tool;
} BWLToolRec, *BWLTool;

/*
 * This function is used to parse config file options specific to the tool.
 * The 'context' hash is expected to hold the values from the config file.
 */
typedef int  (*BWLToolParseArgFunc)(
        BWLContext                  ctx,
        BWLToolDefinition           tool,
        const char                  *key,
        const char                  *val
        );

/*
 * This function is used to initialize a tool.
 *
 * Minimally, it should determine if the tool is available. If there
 * is any one-time initialization that should happen for all test instances
 * that tool might run, it can do those here as well.
 */
typedef BWLBoolean  (*BWLToolAvailableFunc)(
        BWLContext          ctx,
        BWLToolDefinition   tool
        );

/*
 * This function is used to initialize a test at the resource-broker
 * portion of the daemon. It is called once for each new 'test session' -
 * but it is called in the global portion of the daemon, not from the
 * child 'handlers' so it should not do 'real' resource allocations.
 * This is for simple sanity checking and for deciding what 'port'
 * should be used since that needs to be 'global' state.
 */
typedef BWLErrSeverity  (*BWLToolInitTestFunc)(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        uint16_t            *toolport
        );

/*
 * This function is used to do any test initialization needed before
 * running. This is done so the 'run' function can do as little as
 * possible when it is run. (Basically just the exec in the iperf
 * case.) Returns a 'closure' pointer that if NULL indicates failure.
 * If non-NULL, this 'closure' is passed on to the 'run' function.
 */
typedef void * (*BWLToolPreRunTestFunc)(
        BWLContext          ctx,
        BWLTestSession      tsess
        );

/*
 * This function is used to actually run the test. In the iperf case,
 * this is just the exec.
 */
typedef BWLBoolean  (*BWLToolRunTestFunc)(
        BWLContext          ctx,
        BWLTestSession      tsess,
        void                *closure
        );

/*
 * Structure to hold complete 'tool' description
 */

/*
 * This structure is used to actually define the 'Tool' abstraction
 */
struct BWLToolDefinitionRec{
    char                    name[BWL_MAX_TOOLNAME];
    char                    *def_cmd;
    char                    *def_server_cmd;
    uint16_t                def_port;
    BWLToolParseArgFunc     parse;
    BWLToolAvailableFunc    tool_avail;
    BWLToolInitTestFunc     init_test;
    BWLToolPreRunTestFunc   pre_run;
    BWLToolRunTestFunc      run;
};


typedef struct BWLContextRec BWLContextRec;
typedef struct BWLControlRec BWLControlRec;

#define _BWL_CONTEXT_TABLE_SIZE    64
#define _BWL_CONTEXT_MAX_KEYLEN    64

#define _BWL_CONTEXT_FLIST_SIZE 20

typedef struct BWLContextFreeList BWLContextFreeList;
struct BWLContextFreeList{
    uint32_t            len;
    void                *list[_BWL_CONTEXT_FLIST_SIZE];
    BWLContextFreeList  *next;
};

struct BWLContextRec{
    BWLBoolean          valid;
    BWLBoolean          lib_eh;
    I2ErrHandle         eh;
    uint32_t            errmaskprio;
    I2Table             table;
    I2RandomSource      rand_src;
    char                tmpdir[PATH_MAX+1];
    BWLControlRec       *cntrl_list;
    uint32_t            tool_list_size;
    BWLToolRec          *tool_list;
    BWLToolAvailability tool_avail;
    BWLContextFreeList  *flist;
};

struct BWLControlRec{
    /*
     * Application configuration information.
     */
    BWLContext              ctx;

    /*
     * Hash for maintaining Policy state data.
     */
    I2Table                 table;

    /*
     * Control connection state information.
     */
    BWLBoolean              server;    /* this record represents server */
    int                     state;    /* current state of connection */
    BWLSessionMode          mode;
    BWLProtocolVersion      protocol_version;

    /*
     * Very rough upper bound estimate of
     * rtt.
     * Used by clients to estimate a
     * good "start" time for tests that
     * is just beyond the amount of time
     * it takes to request the test.
     */
    BWLNum64                rtt_bound;
    /*
     * This field is initialized to zero and used for comparisons
     * to ensure AES is working.
     */
    uint8_t                zero[16];

    /* area for peer's messages        */
    /* make uint32_t to get wanted alignment */
    /* Usually cast to uint8_t when used... */
    uint32_t               msg[_BWL_MAX_MSG/sizeof(uint32_t)];

    /*
     * Address specification and "network" information.
     * (Control socket addr information)
     */
    I2Addr                 remote_addr;
    I2Addr                 local_addr;
    int                     sockfd;

    /*
     * Encryption fields
     */
    /* null if not set - else userid_buffer */
    char                    *userid;
    BWLUserID               userid_buffer;
    keyInstance             encrypt_key;
    keyInstance             decrypt_key;
    uint8_t                session_key[16];
    uint8_t                readIV[16];
    uint8_t                writeIV[16];
    int                     *retn_on_intr;

    struct BWLControlRec    *next;
    BWLTestSession          tests;
};

typedef struct BWLEndpointRec{
#ifndef    NDEBUG
    BWLBoolean      childwait;
#endif
    BWLControl      cntrl;        /* To client        */
    BWLTestSession  tsess;

    int             ssockfd;
    BWLControl      rcntrl;        /* To other endpoint    */

    BWLAcceptType   acceptval;
    pid_t           child;
    int             wopts;
    uint8_t         exit_status;
    BWLBoolean      dont_kill;
    BWLBoolean      killed;
} BWLEndpointRec, *BWLEndpoint;

struct BWLTestSessionRec{
    BWLControl          cntrl;
    BWLSID              sid;
    BWLTimeStamp        localtime;
    BWLNum64            reserve_time;
    BWLNum64            fuzz;
    BWLToolDefinition   tool;
    uint16_t            tool_port;

    BWLBoolean          conf_sender;
    BWLBoolean          conf_receiver;
    BWLTestSpec         test_spec;

    FILE                *localfp;
    FILE                *remotefp;

    void                *closure; /* per/test app data */

    BWLEndpoint         endpoint;
};

/*
 * Private api.c prototypes
 */
extern BWLAcceptType
_BWLGetAcceptType(
        BWLControl  cntrl,
        uint8_t     val
        );

extern BWLTestSession
_BWLTestSessionAlloc(
        BWLControl  cntrl,
        BWLBoolean  sender_local,
        I2Addr      sender,
        I2Addr      receiver,
        uint16_t    recv_port,
        BWLTestSpec *test_spec
        );

extern BWLErrSeverity
_BWLTestSessionFree(
        BWLTestSession  tsession,
        BWLAcceptType   aval
        );

extern int
_BWLCreateSID(
        BWLTestSession  tsession
        );

#define _BWL_SESSION_FIN_ERROR      0
#define _BWL_SESSION_FIN_NORMAL     1
#define _BWL_SESSION_FIN_INCOMPLETE 2

extern int
_BWLWriteDataHeaderFinished(
        BWLContext  ctx,
        FILE        *fp,
        uint32_t   finished
        );

extern int
_BWLReadDataHeaderInitial(
        BWLContext  ctx,
        FILE        *fp,
        uint32_t   *ver,
        uint32_t   *fin,    /* only set if (*ver >= 2) */
        off_t       *hdr_off,
        struct stat *stat_buf
        );

/*
 * io.c prototypes
 */
extern int
_BWLSendBlocksIntr(
        BWLControl  cntrl,
        uint8_t    *buf,
        int         num_blocks,
        int         *retn_on_intr
        );

extern int
_BWLReceiveBlocksIntr(
        BWLControl  cntrl,
        uint8_t    *buf,
        int         num_blocks,
        int         *retn_on_intr
        );

extern int
_BWLSendBlocks(
        BWLControl  cntrl,
        uint8_t    *buf,
        int         num_blocks
        );

extern int
_BWLReceiveBlocks(
        BWLControl  cntrl,
        uint8_t    *buf,
        int         num_blocks
        );

extern int
_BWLEncryptBlocks(
        BWLControl  cntrl,
        uint8_t    *in_buf,
        int         num_blocks,
        uint8_t    *out_buf
        );

extern int
_BWLDecryptBlocks(
        BWLControl  cntrl,
        uint8_t    *in_buf,
        int         num_blocks,
        uint8_t    *out_buf
        );

extern void
_BWLMakeKey(
        BWLControl  cntrl,
        uint8_t    *binKey
        );

extern int
_BWLEncryptToken(
        uint8_t    *binKey,
        uint8_t    *token_in,
        uint8_t    *token_out
        );

extern int
_BWLDecryptToken(
        uint8_t    *binKey,
        uint8_t    *token_in,
        uint8_t    *token_out
        );

/*
 * protocol.c
 */

extern BWLErrSeverity
_BWLWriteServerGreeting(
        BWLControl  cntrl,
        uint32_t   avail_modes,
        uint8_t    *challenge,    /* [16] */
        int         *retn_on_intr
        );

extern BWLErrSeverity
_BWLReadServerGreeting(
        BWLControl  cntrl,
        uint32_t   *mode,        /* modes available - returned    */
        uint8_t    *challenge    /* [16] : challenge - returned    */
        );

extern BWLErrSeverity
_BWLWriteClientGreeting(
        BWLControl  cntrl,
        uint8_t    *token    /* [32]    */
        );

extern BWLErrSeverity
_BWLReadClientGreeting(
        BWLControl  cntrl,
        uint32_t   *mode,
        uint8_t    *token,        /* [32] - return    */
        uint8_t    *clientIV,    /* [16] - return    */
        int         *retn_on_intr
        );

extern BWLErrSeverity
_BWLWriteServerOK(
	BWLControl      	cntrl,
	BWLAcceptType   	code,
	BWLNum64        	uptime,
	BWLToolAvailability	avail_tools,
	int		*retn_on_intr
        );

extern BWLErrSeverity
_BWLReadServerOK(
	BWLControl	        cntrl,
	BWLAcceptType	        *acceptval,	/* ret	*/
	BWLToolAvailability	*avail  	/* ret	*/
        );

extern BWLErrSeverity
_BWLReadServerUptime(
        BWLControl  cntrl,
        BWLNum64    *uptime_ret
        );

extern BWLErrSeverity
_BWLWriteTimeRequest(
        BWLControl  cntrl
        );

extern BWLErrSeverity
_BWLReadTimeRequest(
        BWLControl  cntrl,
        int         *retn_on_intr
        );

extern BWLErrSeverity
_BWLWriteTimeResponse(
        BWLControl      cntrl,
        BWLTimeStamp    *tstamp,
        int             *retn_on_intr
        );

extern BWLErrSeverity
_BWLReadTimeResponse(
        BWLControl      cntrl,
        BWLTimeStamp    *tstamp_ret
        );

#define _BWL_DYNAMIC_WINDOW_SIZE    (0x1)

extern BWLErrSeverity
_BWLWriteTestRequest(
        BWLControl      cntrl,
        BWLTestSession  tsession
        );

extern BWLErrSeverity
_BWLReadTestRequest(
        BWLControl      cntrl,
        int             *retn_on_intr,
        BWLTestSession  *test_session,
        BWLAcceptType   *accept_ret
        );

extern BWLErrSeverity
_BWLWriteTestAccept(
        BWLControl      cntrl,
        int             *retn_on_intr,
        BWLAcceptType   acceptval,
        BWLTestSession  tsession
        );

extern BWLErrSeverity
_BWLReadTestAccept(
        BWLControl      cntrl,
        BWLAcceptType   *acceptval,
        BWLTestSession  tsession
        );

extern BWLErrSeverity
_BWLWriteStartSession(
        BWLControl  cntrl,
        uint16_t   dataport
        );

extern BWLErrSeverity
_BWLReadStartSession(
        BWLControl  cntrl,
        uint16_t   *dataport,
        int         *retn_on_intr
        );

extern BWLErrSeverity
_BWLWriteStartAck(
        BWLControl      cntrl,
        int             *retn_on_intr,
        uint16_t       dataport,
        BWLAcceptType   acceptval
        );

extern BWLErrSeverity
_BWLReadStartAck(
        BWLControl      cntrl,
        uint16_t       *dataport,
        BWLAcceptType   *acceptval
        );

extern BWLErrSeverity
_BWLWriteStopSession(
        BWLControl      cntrl,
        int             *retn_on_intr,
        BWLAcceptType   acceptval,
        FILE            *fp
        );

extern BWLErrSeverity
_BWLReadStopSession(
        BWLControl      cntrl,
        int             *retn_on_intr,
        BWLAcceptType   *acceptval,
        FILE            *fp
        );

/*
 * context.c
 */

extern BWLControl
_BWLControlAlloc(
        BWLContext      ctx,
        BWLErrSeverity  *err_ret
        );

extern BWLBoolean
_BWLCallGetAESKey(
        BWLContext      ctx,        /* context record    */
        const char      *userid,    /* identifies key    */
        uint8_t        *key_ret,   /* key - return        */
        BWLErrSeverity  *err_ret    /* error - return    */
        );

extern BWLBoolean
_BWLCallCheckControlPolicy(
        BWLControl      cntrl,              /* control record       */
        BWLSessionMode  mode,               /* requested mode       */
        const char      *userid,            /* key identity         */
        struct sockaddr *local_sa_addr,     /* local addr or NULL   */
        struct sockaddr *remote_sa_addr,    /* remote addr          */
        BWLErrSeverity  *err_ret            /* error - return       */
        );

extern BWLBoolean
_BWLCallCheckTestPolicy(
        BWLControl      cntrl,      /* control handle           */
        BWLTestSession  tsession,   /* test session description */
        BWLErrSeverity  *err_ret    /* error - return           */
        );

extern void
_BWLCallTestComplete(
        BWLTestSession  tsession,
        BWLAcceptType   aval
        );

extern BWLErrSeverity
_BWLCallProcessResults(
        BWLTestSession  tsession
        );

/*
 * non-NULL closure indicates "receiver" - NULL indicates R/O Fetch.
 */
extern FILE *
_BWLCallOpenFile(
        BWLControl  cntrl,                  /* control handle       */
        void        *closure,               /* app data/per test    */
        BWLSID      sid,                    /* sid for datafile     */
        char        fname_ret[PATH_MAX+1]
        );

extern void
_BWLCallCloseFile(
        BWLControl      cntrl,
        void            *closure,
        FILE            *fp,
        BWLAcceptType   aval
        );

/* tools.c */

extern BWLBoolean
_BWLToolInitialize(
        BWLContext  ctx
        );

extern BWLBoolean
_BWLToolLookForTesters(
        BWLContext  ctx
        );

extern BWLToolDefinition
_BWLToolGetDefinition(
        BWLContext  ctx,
        BWLToolType id
        );

extern void *
_BWLToolPreRunTest(
        BWLContext      ctx,
        BWLTestSession  tsess
        );

extern void
_BWLToolRunTest(
        BWLContext      ctx,
        BWLTestSession  tsess,
        void            *closure
        );

extern int
_BWLToolGenericParse(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        const char          *key,
        const char          *val
        );

extern BWLErrSeverity
_BWLToolGenericInitTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        uint16_t            *toolport
        );


/* endpoint.c */

/*
 * EndpointStart:
 * 1) Open tmpfile for results/ open /dev/null for stderr
 * 2) If receiver - open serversock for endpoint2endpoint communication
 *    If sender - connect to giving reciever control sock and send
 *         timestamp packet and receive AOK.
 * 3) fork child
 *     child:
 *         dup stdout -> tmpfile
 *         dup stdin -> /dev/null
 *         dup stderr -> /dev/null
 *         wait until start time to exec or signal to exit
 *     parent: return AOK
 */
extern BWLBoolean
_BWLEndpointStart(
        BWLTestSession  tsession,
        uint16_t       *dataport,
        BWLErrSeverity  *err_ret
        );

/*
 * EndpointStatus:
 * Is child still alive? What was "exit" code of test?
 */
extern BWLBoolean
_BWLEndpointStatus(
        BWLTestSession  tsession,
        BWLAcceptType   *aval,
        BWLErrSeverity  *err_ret
        );

extern BWLBoolean
_BWLEndpointStop(
        BWLTestSession  tsession,
        BWLAcceptType   aval,
        BWLErrSeverity  *err_ret
        );

/*
 * error.c
 */
extern BWLErrSeverity
_BWLFailControlSession(
        BWLControl  cntrl,
        int         err
        );

/*
 * time.c
 */

/*
 * En/DecodeTimeStamp functions do not assume any alignment requirements
 * for buf. (Most functions in protocol.c assume uint32_t alignment.)
 */
extern void
_BWLEncodeTimeStamp(
        uint8_t        buf[8],
        BWLTimeStamp    *tstamp
        );
extern BWLBoolean
_BWLEncodeTimeStampErrEstimate(
        uint8_t        buf[2],
        BWLTimeStamp    *tstamp
        );
extern void
_BWLDecodeTimeStamp(
        BWLTimeStamp    *tstamp,
        uint8_t        buf[8]
        );
extern BWLBoolean
_BWLDecodeTimeStampErrEstimate(
        BWLTimeStamp    *tstamp,
        uint8_t        buf[2]
        );
extern int
_BWLInitNTP(
        BWLContext  ctx
        );

extern struct timespec *
_BWLGetTimespec(
        BWLContext      ctx,
        struct timespec *ts,
        uint32_t        *esterr,
        int             *synchronized
        );

#endif    /* IPCNTRLP_H */
