/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabls-mode: nil -*-
 *      $Id$
 */
/*
 *    File:         bwctl.c
 *
 *    Author:       Jeff Boote
 *                  Internet2
 *
 *    Date:         Mon Sep 15 10:54:30 MDT 2003
 *
 *    Description:    
 *
 *    License:
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <assert.h>
#include <syslog.h>
#include <math.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include <I2util/addr.h>
#include <bwlib/bwlib.h>


#if defined HAVE_DECL_OPTRESET && !HAVE_DECL_OPTRESET
int optreset;
#endif

#include "./bwctlP.h"

static BWLControl spawn_local_server(BWLContext lctx, ipsess_t sess, BWLToolAvailability *avail_tools);
static BWLBoolean close_local_server(BWLContext ctx, ipsess_t sess);
static BWLBoolean wait_for_next_test();
static BWLBoolean start_testing(ipsess_t server_sess, ipsess_t client_sess);
static BWLBoolean negotiate_individual_test(ipsess_t sess, BWLSID sid, BWLTimeStamp *req_time, uint16_t *recv_port);
static BWLBoolean negotiate_test(ipsess_t server_sess, ipsess_t client_sess, BWLTestSpec *test_options);
static BWLBoolean wait_for_results();
static BWLBoolean setup_results_storage(ipsess_t sess);
static BWLBoolean display_results(ipsess_t sess);
static BWLBoolean establish_connection(ipsess_t current_sess, ipsess_t other_sess);
static BWLBoolean getclientkey(BWLContext lctx, const BWLUserID userid, BWLKey key_ret, BWLErrSeverity  *err_ret);

// The ordering here is the odering it will show when the usage is printed
struct bwctl_option bwctl_options[] = {
   {
        BWL_TEST_ALL,
        { "receiver", required_argument, 0, 'c' },
        "The host that will act as the receiving side for a test",
        "address",
   },
   {
        BWL_TEST_ALL,
        { "sender", required_argument, 0, 's' },
        "The host that will act as the sending side for a test",
        "address",
   },
   {
        BWL_TEST_ALL,
        { "ipv4", no_argument, 0, '4' },
        "Use IPv4 only",
   },
   {
        BWL_TEST_ALL,
        { "ipv6", no_argument, 0, '6' },
        "Use IPv6 only",
   },
   {
        BWL_TEST_ALL,
        { "local_address", required_argument, 0, 'B' },
        "Use this as a local address for control connection and tests",
        "address",
   },
   {
        BWL_TEST_ALL,
        { "num_tests", required_argument, 0, 'n' },
        "Number of tests to perform (default: 1)",
        "num"
   },
   {
        BWL_TEST_ALL,
        { "test_interval", required_argument, 0, 'I' },
        "Time between repeated bwctl tests",
        "seconds",
   },
   {
        BWL_TEST_ALL,
        { "latest_time", required_argument, 0, 'L' },
        "Latest time into an interval to allow a test to run",
        "seconds"
   },
   {
        BWL_TEST_ALL,
        { "randomize", required_argument, 0, 'R' },
        "Randomize the start time within this percentage of the test's interval (Default: 10%)",
        "percent",
   },
   {
        BWL_TEST_ALL,
        { "tool", required_argument, 0, 'T' },
        "The tool to use for the test",
        "tool",
   },
   {
        BWL_TEST_ALL,
        { "flip", no_argument, 0, 'o' },
        "Have the receiver connect to the sender (default: False)"
   },
   {
        BWL_TEST_ALL,
        { "allow_ntp_unsync", required_argument, 0, 'a' },
        "Allow unsynchronized clock - claim good within offset",
        "seconds"
   },

   {
        BWL_TEST_ALL,
        { "units", required_argument, 0, 'f' },
        "Type of measurement units to return (Default: tool specific)",
        "unit"
   },
   {
        BWL_TEST_ALL,
        { "both", no_argument, 0, 'x' },
        "Output both sender and receiver results",
   },
   {
        BWL_TEST_ALL,
        { "format", no_argument, 0, 'y' },
        "Output format to use (Default: tool specific)",
   },

// Latency/Traceroute-specific options
   {
        BWL_TEST_LATENCY | BWL_TEST_TRACEROUTE,
        { "no_endpoint", no_argument, 0, 'E' },
        "Allow tests to occur when the receiver isn't running bwctl (Default: False)",
   },
   {
        BWL_TEST_LATENCY | BWL_TEST_TRACEROUTE,
        { "packet_length", required_argument, 0, 'l' },
        "Length of packets",
        "bytes",
   },

// Latency-specific options
   {
        BWL_TEST_LATENCY,
        { "num_packets", required_argument, 0, 'N' },
        "Number of packets to send (Default: 10)",
        "num",
   },
   {
        BWL_TEST_LATENCY,
        { "ttl", required_argument, 0, 't' },
        "TTL for the packets",
        "num",
   },
   {
        BWL_TEST_LATENCY,
        { "packet_interval", required_argument, 0, 'i' },
        "Delay between packets (Default: 1.0)",
        "seconds",
   },

// Traceroute-specific options
   {
        BWL_TEST_TRACEROUTE,
        { "first_ttl", required_argument, 0, 'F' },
        "minimum TTL for traceroute (Default: none)",
        "num",
   },
   {
        BWL_TEST_TRACEROUTE,
        { "max_ttl", required_argument, 0, 'M' },
        "maximum TTL for traceroute (Default: none)",
        "num",
   },
   {
        BWL_TEST_TRACEROUTE,
        { "test_duration", required_argument, 0, 't' },
        "Maximum time to wait for traceroute to finish (Default: 10)",
        "seconds",
   },

// Throughput-specific options
   {
        BWL_TEST_THROUGHPUT,
        { "bandwidth", required_argument, 0, 'b' },
        "Bandwidth to use for tests (bits/sec KM) (Default: 1Mb for UDP tests, unlimited for TCP tests)",
        "bandwidth",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "report_interval", required_argument, 0, 'i' },
        "Tool reporting interval",
        "seconds",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "buffer_length", required_argument, 0, 'l' },
        "Length of read/write buffers",
        "bytes",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "omit", required_argument, 0, 'O' },
        "Omit time (currently only for iperf3)",
        "seconds",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "parallel", required_argument, 0, 'P' },
        "Number of concurrent connections",
        "num",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "dscp", required_argument, 0, 'D' },
        "RFC 2474-style DSCP value for TOS byte",
        "dscp",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "tos", required_argument, 0, 'S' },
        "Type-Of-Service for outgoing packets",
        "tos",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "test_duration", required_argument, 0, 't' },
        "Duration for test (Default: 10)",
        "seconds",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "udp", no_argument, 0, 'u' },
        "Perform a UDP test",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "window", no_argument, 0, 'w' },
        "TCP window size (Default: system default)",
   },
   {
        BWL_TEST_THROUGHPUT,
        { "dynamic_window", no_argument, 0, 'W' },
        "Dynamic TCP window fallback size (Default: system default)",
   },


// Lesser-used or minor options
   {
        BWL_TEST_ALL,
        { "verbose", no_argument, 0, 'v' },
        "Display verbose output",
   },
   {
        BWL_TEST_ALL,
        { "print", no_argument, 0, 'p' },
        "Print results filenames to stdout (Default: False)",
   },
   {
        BWL_TEST_ALL,
        { "output_dir", required_argument, 0, 'd' },
        "Directory to save session files to (only if -p)",
        "directory"
   },
   {
        BWL_TEST_ALL,
        { "facility", required_argument, 0, 'e' },
        "Syslog facility to log to",
        "facility"
   },
   {
        BWL_TEST_ALL,
        { "quiet", no_argument, 0, 'q' },
        "Silent mode (Default: False)",
   },
   {
        BWL_TEST_ALL,
        { "syslog_to_stderr", no_argument, 0, 'r' },
        "Send syslog to stderr (Default: False)",
   },

   {
        BWL_TEST_ALL,
        { "version", no_argument, 0, 'V' },
        "Show version number",
   },
   {
        BWL_TEST_ALL,
        { "help", no_argument, 0, 'h' },
        "Display the help message\n",
   },
   {
        BWL_TEST_UNDEFINED,
   },
};

/*
 * The bwctl context
 */
static    ipapp_trec    app;
static    char          *progname;
static    BWLTestType   test_type;
static    I2ErrHandle   eh;
static    int           ip_intr = 0;
static    int           ip_chld = 0;
static    int           ip_reset = 0;
static    int           ip_exit = 0;
static    int           ip_error = SIGCONT;
static    BWLContext    ctx;
static    aeskey_auth   current_auth=NULL;
static    BWLNum64      zero64;
static    BWLNum64      fuzz64;
static    int           exit_val=0;
static    ipsess_trec   sessions[2];    /* server == 0, client == 1 */
static    I2RandomSource      rsrc;

static void
version(
        void
        )
{
    fprintf(stderr,"\nVersion: %s\n",PACKAGE_VERSION);

    return;
}

static void
usage(
        const char  *msg
        )
{
    int i;

    // Do a dummy load of ctx to make sure we can print out the list of
    // available tools...
    if (!ctx) {
        if( !(ctx = BWLContextCreate(NULL,
                        BWLInterruptIO, &ip_intr,
                        BWLGetAESKey,   getclientkey,
                        NULL))){
            fprintf(stderr, "Unable to initialize BWL library.\n");
            exit(1);
        }
    }

    if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
    fprintf(stderr,"usage: %s %s\n", progname, "[arguments]");

    for(i = 0; bwctl_options[i].test_types != BWL_TEST_UNDEFINED; i++) {
        char buf[50];

        if (!(bwctl_options[i].test_types & test_type))
            continue;

        if (bwctl_options[i].option.val) {
            snprintf(buf, sizeof(buf) - 1, "-%c|--%s", bwctl_options[i].option.val, bwctl_options[i].option.name);
        }
        else {
            snprintf(buf, sizeof(buf) - 1, "--%s", bwctl_options[i].option.name);
        }

        if (bwctl_options[i].option.has_arg == required_argument) {
            strncat(buf, " <", sizeof(buf) - 1);
            strncat(buf, bwctl_options[i].argument_description, sizeof(buf) - 1);
            strncat(buf, ">", sizeof(buf) - 1);
        }

        fprintf(stderr, "%-32.34s %s\n", buf, bwctl_options[i].description);

        // The -T option is a special case
        if (bwctl_options[i].option.name == "tool") {
            int j, n;
            fprintf(stderr, "%-34s Available Tools:\n", "");
            for(j=0,n = BWLToolGetNumTools(ctx);j<n;j++){
                if (BWLToolGetTestTypesByIndex(ctx, j) != test_type)
                    continue;
        
                fprintf(stderr, "%-34s    %s\n", "", BWLToolGetNameByIndex(ctx,j));
            }
        }
    }

    version();

    return;
}

static BWLBoolean
getclientkey(
        BWLContext      lctx,
        const BWLUserID userid,
        BWLKey          key_ret,
        BWLErrSeverity  *err_ret
        )
{
    if(!current_auth){
        /*
         * Function shouldn't be called if identity wasn't passed in...
         */
        BWLError(lctx,BWLErrFATAL,BWLErrUNKNOWN,
                "GetKey: auth method unknown");
        *err_ret = BWLErrFATAL;
        return False;
    }

    if(strncmp(current_auth->identity,userid,sizeof(BWLUserID))){
        /*
         * If identity doesn't match, there are auth problems...
         */
        BWLError(lctx,BWLErrFATAL,BWLErrUNKNOWN,
                "GetKey: auth identity mismatch");
        *err_ret = BWLErrFATAL;
        return False;
    }
    memcpy(key_ret,current_auth->aesbuff,sizeof(current_auth->aesbuff));

    return True;
}

/*
 * Function:    parse_auth_args
 *
 * Description:    
 *         parses authentication style args using argv,argc,optind.
 *
 * In Args:    
 *              I2ErrHandle    eh
 *
 * Out Args:    
 *              aeskey_auth    *auth_ret
 *              return a pointer to the structure that holds the
 *              authentication information.
 *
 * Scope:    
 * Returns:    0 on success
 * Side Effect:    
 *         updates optind so getopt is set to grab the next non-auth
 *         opt from the commandline.
 */
static int
parse_auth_args(
        I2ErrHandle leh,
        char        **argv,
        int         argc,
        char        *hostref,
        aeskey_auth *auth_ret
        )
{
    aeskey_auth auth;
    char        *s;
    uint32_t   auth_mode = 0;
    FILE        *fp;
    int         rc = 0;
    char        *lbuf=NULL;
    size_t      lbuf_max=0;


    *auth_ret = NULL;

    /*
     * If there are no options, then return success.
     */
    if(optind >= argc)
        return 0;

    /*
     * Verify/decode auth options.
     */
    s = argv[optind];
    while(*s != '\0'){
        switch (toupper(*s)){
            case 'O':
                auth_mode |= BWL_MODE_OPEN;
                break;
            case 'A':
                auth_mode |= BWL_MODE_AUTHENTICATED;
                break;
            case 'E':
                auth_mode |= BWL_MODE_ENCRYPTED;
                break;
            default:
                /*
                 * arg doesn't match a autmode string,
                 * return 0 and let getopt grab this arg.
                 */
                return 0;

        }
        s++;
    }

    /*
     * This was an auth_mode argument - move the optind past it.
     */
    optind++;

    if(!(auth = (aeskey_auth)calloc(1,sizeof(aeskey_auth_rec)))){
        I2ErrLog(leh,"malloc:%M");
        return 1;
    }
    *auth_ret = auth;
    auth->auth_mode = auth_mode;

    /*
     * If there are no more options, then return success.
     */
    if(optind >= argc)
        return 0;

    /*
     * See if the AESKEY authscheme is selected. In the future, will
     * need to check for multiple scheme's, and may even need to turn
     * the aeskey_auth_rec into a union or something like that, but for
     * now it is simple enough to just look for AESKEY. :)
     */
    if(strncasecmp(argv[optind],"aeskey",7)){
        /*
         * If strncasecmp != 0, then argv[optind] is not what
         * we are looking for.
         */
        return 0;
    }
    optind++;

    /*
     * The remainder of this function pulls AESKEY scheme options out.
     */
    if(optind >= argc){
        I2ErrLog(leh,"Invalid AESKEY schemeopts");
        return 1;
    }

    if(!(auth->identity = strdup(argv[optind]))){
        I2ErrLog(leh,"malloc: %m");
        return 1;
    }
    optind++;

    /* If there are no more args, or the next arg starts with '-'
     * it is assumed that the optional keyfile is not being specified.
     */
    if(optind < argc){
        s = argv[optind];
        if(s[0] != '-'){
            if(!(auth->keyfile = strdup(argv[optind]))){
                I2ErrLog(leh,"malloc: %m");
                return 1;
            }
            optind++;
        }
    }

    /*
     * keyfile specified, attempt to get key from there.
     */
    if(auth->keyfile){
        if(!(fp = fopen(auth->keyfile,"r"))){
            I2ErrLog(leh,"Unable to open %s: %M",auth->keyfile);
            return 1;
        }

        rc = I2ParseKeyFile(leh,fp,0,&lbuf,&lbuf_max,NULL,
                auth->identity,NULL,auth->aesbuff);
        if(lbuf){
            free(lbuf);
        }
        lbuf = NULL;
        lbuf_max = 0;
        fclose(fp);

        if(rc <= 0){
            I2ErrLog(leh,
                    "Unable to find key for id=\"%s\" from keyfile=\"%s\"",
                    auth->identity,auth->keyfile);
            return 1;
        }
    }else{
        /*
         * Do passphrase:
         *     open tty and get passphrase.
         *    (md5 the passphrase to create an aes key.)
         */
        char        *passphrase;
        char        ppbuf[MAX_PASSPHRASE];
        char        prompt[MAX_PASSPROMPT];
        I2MD5_CTX   mdc;
        size_t      pplen;

        if(snprintf(prompt,MAX_PASSPROMPT,
                    "Enter passphrase for host '%s', identity '%s': ",
                    hostref,auth->identity) >= MAX_PASSPROMPT){
            I2ErrLog(leh,"Invalid identity");
            return 1;
        }

        if(!(passphrase = I2ReadPassPhrase(prompt,ppbuf,
                        sizeof(ppbuf),I2RPP_ECHO_OFF))){
            I2ErrLog(leh,"I2ReadPassPhrase(): %M");
            return 1;
        }
        pplen = strlen(passphrase);

        I2MD5Init(&mdc);
        I2MD5Update(&mdc,(unsigned char *)passphrase,pplen);
        I2MD5Final(auth->aesbuff,&mdc);
    }
    auth->aeskey = auth->aesbuff;

    return 0;
}

static void
CloseSessions(
        void
        )
{
    /* TODO: Handle clearing other state. Canceling tests nicely? */

    if (app.client_sess->cntrl) {
        BWLControlClose(app.client_sess->cntrl);
        app.client_sess->cntrl = NULL;
        app.client_sess->sockfd = 0;
        app.client_sess->tspec.req_time.tstamp = zero64;

        close_local_server(ctx, app.client_sess);
    }

    if (app.server_sess->cntrl) {
        BWLControlClose(app.server_sess->cntrl);
        app.server_sess->cntrl = NULL;
        app.server_sess->sockfd = 0;
        app.server_sess->tspec.req_time.tstamp = zero64;

        close_local_server(ctx, app.server_sess);
    }

    return;
}

static void
sig_catch(
        int    signo
        )
{
    switch(signo){
        case SIGINT:
        case SIGTERM:
        case SIGALRM:
            ip_exit++;
            break;
        case SIGCHLD:
            ip_chld++;
            break;
        case SIGHUP:
            ip_reset++;
            break;
        default:
            ip_error = signo;
            break;
    }

    ip_intr++;

    return;
}

static int
sig_check(
        void
        )
{
    if(ip_error != SIGCONT){
        I2ErrLog(eh,"sig_catch(%d):UNEXPECTED SIGNAL NUMBER",ip_error);
        return 1;
    }

    if(ip_exit || ip_reset){
        return 1;
    }

    ip_intr = 0;

    if(ip_reset){
        ip_reset = 0;
        return 1;
    }

    return 0;
}

/*
 * Generate the next "interval" randomized by +-alpha
 */
static BWLNum64
next_start(
        I2RandomSource  rsrc,
        uint32_t       interval,
        uint32_t       alpha,
        BWLNum64        *base
        )
{
    uint32_t   r;
    double      a,b;
    BWLNum64    inc;

    if(alpha > 0){
        /*
         * compute normalized range for alpha
         */
        a = (double)interval * (double)alpha/100.0;

        /*
         * compute minimum start for interval
         * (random number will be added to this).
         */
        b = (double)interval - a;

        /*
         * get a random uint32_t
         */
        if(I2RandomBytes(rsrc,(uint8_t*)&r,4) != 0){
            exit(1);
        }

        /*
         * Use the random number to pick a random value in the range
         * of [0,2alpha]. Add that to b to get a value of
         * interval +- alpha
         */
        inc = BWLDoubleToNum64(b + ((double)r /0xffffffff) * 2.0 * a);
    }
    else{
        inc = BWLULongToNum64(interval);
    }

    /*
     * Add the relative offset to the base to get the next "wake" time.
     */
    inc = BWLNum64Add(*base,inc);

    /*
     * Now update base for the next time through the loop.
     */
    *base = BWLNum64Add(*base,BWLULongToNum64(interval));

    return inc;
}

/*
 * CheckTestPolicy for client faux-daemon. Always say yes, but do
 * scheduling and tool initialization check.
 */
static BWLBoolean
CheckTestPolicy(
        BWLControl      cntrl,
        BWLSID          lsid __attribute__((unused)),
        BWLBoolean      local_sender,
        struct sockaddr *local_sa_addr    __attribute__((unused)),
        struct sockaddr *remote_sa_addr __attribute__((unused)),
        socklen_t       sa_len    __attribute__((unused)),
        BWLTestSpec     *tspec,
        BWLNum64        fuzz_time,
        BWLNum64        *reservation_ret,
        uint16_t        *tool_port_ret,
        void            **closure,
        BWLErrSeverity  *err_ret
        )
{
    BWLContext      lctx = BWLGetContext(cntrl);
    BWLTimeStamp    currtime;
    BWLNum64        start;
    BWLNum64        minstart;
    uint16_t        tool_port_loc;

    *err_ret = BWLErrOK;

    if(!BWLGetTimeStamp(lctx,&currtime)){
        BWLError(lctx,BWLErrFATAL,BWLErrUNKNOWN,"BWLGetTimeStamp(): %M");
        *err_ret = BWLErrFATAL;
        return False;
    }

    /*
     * Start time as defined by request.
     */
    start = BWLNum64Sub(tspec->req_time.tstamp,fuzz_time);

    /*
     * Determine earliest time test can happen. (See comments in
     * bwctl/bwctld.c:ChldReservationDemand() )
     */
    minstart = BWLNum64Add(currtime.tstamp,BWLNum64Mult(
                BWLNum64Add(BWLGetRTTBound(cntrl),fuzz_time),
                BWLULongToNum64(2))
            );

    /*
     * If start is less than min start, then reset the start time to
     * one second past the min start. (Again see comments in bwctld.c)
     */
    if(BWLNum64Cmp(start,minstart) < 0){
        start = BWLNum64Add(minstart,BWLULongToNum64(1));
    }

    /*
     * reservation time is fuzz_time after start time.
     */
    *reservation_ret = BWLNum64Add(start,fuzz_time);

    /*
     * Initialize the tool if this is the first time CheckTest was called.
     * (closure is kept to maintain state between calls to CheckTest,
     * no information is needed so just set it to any non-NULL value
     * for this logic test.)
     */
    if(!*closure){
        if( BWLErrOK !=
                (*err_ret =
                 BWLToolInitTest(lctx,tspec->tool_id,&tool_port_loc))){
            BWLError(lctx,*err_ret,BWLErrINVALID,
                    "CheckTestPolicy(): Tool initialization failed");
            return False;
        }
        *closure = (void *)!NULL;

        /*
         * Only update the tool port if configuring the receiver
         */
        if(!local_sender){
            *tool_port_ret = tool_port_loc;
        }
    }

    return True;
}

static BWLBoolean
close_local_server(
        BWLContext   ctx,
        ipsess_t     sess
)
{
    BWLBoolean func_retval = True;

    if(sess->fake_daemon_pipe > -1){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,"close_local_server(): shutting down daemon pipe");
        while((close(sess->fake_daemon_pipe) < 0) &&
                (errno == EINTR));
        sess->fake_daemon_pipe = -1;
    }

    if(sess->fake_daemon_pid > 0){
        int     status = 0;
        int     killed=0;
        struct timeval tv;

        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,"close_local_server(): killing daemon process");

        tv.tv_sec = 2;
        tv.tv_usec = 0;

        while (1) {
            int retval = select(0, NULL, NULL, NULL, &tv);
            int select_errno = errno;

            pid_t rc = waitpid(sess->fake_daemon_pid,&status,WNOHANG);
            if (rc > 0) {
                if (app.opt.verbose) {
                    I2ErrLog(eh, "Local server has exited");
                }
                // child pid has exited 
                break;
            }

            if (rc < 0) {
                // No children are around...
                break;
            }

            if ((retval == -1 && select_errno == EINTR) ||
                (retval == 0 && killed)) {
                I2ErrLog(eh, "Problem killing local server");
                func_retval = False;
                break;
            }
            else if (retval == 0) {
                (void)kill(sess->fake_daemon_pid,SIGTERM);
                tv.tv_sec = 2;
                tv.tv_usec = 0;
                killed = 1;
            }
        }

        sess->fake_daemon_pid = -1;
    }

    return func_retval;
}

static BWLControl
spawn_local_server(
        BWLContext          lctx,
        ipsess_t            sess,
        BWLToolAvailability *avail_tools
        )
{
    int                 new_pipe[2];
    pid_t               pid;
    BWLErrSeverity      err = BWLErrOK;
    uint32_t            controltimeout = 7200;
    BWLTimeStamp        currtime;
    struct itimerval    itval;
    BWLControl          cntrl;
    BWLRequestType      msgtype;
    void                *childwait;

    /*
     * This socket is the 'control' connection to the mock-daemon
     */
    if(socketpair(AF_UNIX,SOCK_STREAM,0,new_pipe) < 0){
        I2ErrLog(eh,"socketpair(): %M");
    }

    /*
     * Now spawn the child process to be the mock-daemon
     */
    pid = fork();

    /* fork error */
    if(pid < 0){
        I2ErrLog(eh,"fork(): %M");
        return NULL;
    }

    /* parent */
    if(pid > 0){
        I2Addr      servaddr;

        while((close(new_pipe[1]) < 0) && (errno == EINTR));

        if(!(servaddr = I2AddrBySockFD(eh,new_pipe[0],True))){
            I2ErrLog(eh,"Failed to create local-server address: %M");
            return NULL;
        }

        cntrl = BWLControlOpen(lctx,NULL,servaddr,
                BWL_MODE_OPEN,NULL,NULL,avail_tools,&err);

        if(!cntrl){
            I2ErrLog(eh,"Failed to connect to local-server: %M");
            return NULL;
        }

        sess->fake_daemon_pipe = new_pipe[0];
        sess->fake_daemon_pid = pid;
        sess->fake_daemon = True;
        return cntrl;
    }

    /* Now implement child "server" */
    if(ip_exit){
        I2ErrLog(eh,"Child exiting from signal");
        _exit(0);
    }


    /* Close the write side of the pipe */
    while((close(new_pipe[0]) < 0) && (errno == EINTR));

    /*
     * Make access log stuff be quiet in child server if !verbose.
     */
    if(!app.opt.verbose){
        if(!BWLContextConfigSet(lctx,BWLAccessPriority,BWLErrOK)){
            I2ErrLog(eh,"BWLContextconfigSet(BWLAccessPriority,BWLErrOK): %M");
            _exit(1);
        }

        BWLContextSetErrMask(lctx,BWLErrWARNING);
    }

    /*
     * Wait for the debugger?
     */
    if( (childwait = BWLContextConfigGetV(lctx,BWLChildWait))){
        I2ErrLog(eh,"Waiting for Debugger(%d)",getpid());
        while(childwait);
        /*
         * Set childwait back to non-zero in debugger before
         * executing the next line to make sub children 'wait'
         * as well.
         */
        if( !BWLContextConfigSet(lctx,BWLChildWait,(void*)childwait)){
            I2ErrLog(eh,"BWLContextConfigSet(ChildWait): %M");
            _exit(1);
        }
    }

    if(!BWLContextConfigSet(lctx,BWLCheckTestPolicy,CheckTestPolicy)){
        I2ErrLog(eh,"BWLContextConfigSet(\"CheckTestPolicy\")");
        _exit(1);
    }

    if( !BWLContextFindTools(lctx)){
        I2ErrLog(eh,"BWLContextFindTools failed.");
        _exit(1);
    }

    /*
     * Initialize interval timer
     */
    memset(&itval,0,sizeof(itval));
    itval.it_value.tv_sec = controltimeout;
    if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
        I2ErrLog(eh,"setitimer(%d): %M",controltimeout);
        _exit(1);
    }

    /*
     * Get current time for server greeting.
     */
    if(!BWLGetTimeStamp(lctx,&currtime)){
        I2ErrLog(eh,"BWLGetTimeStamp: %M");
        _exit(1);
    }

    /*
     * Accept connection and send server greeting.
     */
    cntrl = BWLControlAccept(lctx,new_pipe[1],NULL,0,BWL_MODE_OPEN,
            currtime.tstamp,&ip_exit,&err);
    if(!cntrl){
        I2ErrLog(eh,"BWLControlAccept() failed");
        _exit((int)err);
    }

    /*
     * TODO?: Figure out a way to share the event-loop with bwctld
     *
     * Process all requests - return when complete.
     */
    while(1){
        BWLErrSeverity  rc;
        int             wstate;

        rc = BWLErrOK;

        if(ip_exit)
            goto done;

        /*
         * reset signal vars
         * TODO: If there is a pending reservation,
         * timer should be reduced to:
         *     MIN(time-util-start,reserve-timeout)
         */
        itval.it_value.tv_sec = controltimeout;
        if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
            I2ErrLog(eh,"setitimer(): %M");
            goto done;
        }

        msgtype = BWLReadRequestType(cntrl,&ip_exit);

        if(ip_exit)
            goto done;

        switch (msgtype){


            case BWLReqTest:
                rc = BWLProcessTestRequest(cntrl,&ip_exit);
                break;

            case BWLReqTime:
                rc = BWLProcessTimeRequest(cntrl,&ip_exit);
                break;

            case BWLReqStartSession:
                rc = BWLProcessStartSession(cntrl,&ip_exit);
                if(rc < BWLErrOK){
                    break;
                }
                /*
                 * Test session started - unset timer - wait
                 * until all sessions are complete, then
                 * reset the timer and wait for stopsessions
                 * to complete.
                 */
                itval.it_value.tv_sec = 0;
                if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
                    I2ErrLog(eh,"setitimer(): %M");
                    goto done;
                }
                if(ip_exit)
                    goto done;

                rc = BWLErrOK;
                wstate = BWLStopSessionWait(cntrl,NULL,
                        &ip_exit,NULL,&rc);
                if(ip_exit || (wstate != 0)){
                    goto done;
                }

                /*
                 * Sessions are complete, but StopSession
                 * message has not been exchanged - set the
                 * timer and trade StopSession messages
                 */
                itval.it_value.tv_sec = controltimeout;
                if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
                    I2ErrLog(eh,"setitimer(): %M");
                    goto done;
                }
                rc = BWLStopSession(cntrl,&ip_exit,NULL);

                break;

            case BWLReqSockClose:
            default:
                rc = BWLErrFATAL;
                break;
        }
        if(rc < BWLErrWARNING){
            break;
        }

    }

done:
    BWLControlClose(cntrl);

    if(ip_exit){
        _exit(0);
    }

    /*
     * Normal socket close
     */
    if(msgtype == BWLReqSockClose){
        _exit(0);
    }

    I2ErrLog(eh,"Control session terminated abnormally...");

    _exit(1);
}

#define BWCTL_DEFAULT_RCNAME    ".bwctlrc"

static BWLBoolean
LoadConfig(
        BWLContext  lctx
        )
{
    FILE    *conf;
    char    conf_filebuf[MAXPATHLEN+1];
    char    *conf_file;
    char    keybuf[MAXPATHLEN],valbuf[MAXPATHLEN];
    char    *key = keybuf;
    char    *val = valbuf;
    int     rc;
    int     dc;
    char    *lbuf=NULL;
    size_t  lbuf_max=0;

    if( !(conf_file = getenv("BWCTLRC"))){
        char    *home;

        if( !(home = getenv("HOME"))){
            struct passwd   *pw;

            if( !(pw = getpwuid(getuid()))){
                BWLError(lctx,BWLErrFATAL,errno,"LoadConfig: getpwuid(): %M");
                return False;
            }

            home = pw->pw_dir;
        }

        rc = strlen(home) + strlen(BWL_PATH_SEPARATOR) +
            strlen(BWCTL_DEFAULT_RCNAME);

        if(rc > MAXPATHLEN){
            BWLError(lctx,BWLErrFATAL,errno,"strlen(BWCTLRC) > MAXPATHLEN");
            return False;
        }

        conf_file = conf_filebuf;
        strcpy(conf_file,home);
        strcat(conf_file,BWL_PATH_SEPARATOR);
        strcat(conf_file,BWCTL_DEFAULT_RCNAME);
    }

    if( !(conf = fopen(conf_file, "r"))){
        /*
         * TODO?:
         * No local config - just go with the defaults
         * Set something in the ctx so this can be seen later?
         * Perhaps better to set something if it is opened - to indicate
         * what rc files is used...
         *
         */
        /* no conf file, success */
        return True;
    }

    /*
     * Now parse the file
     */
    rc=0;
    while((rc = I2ReadConfVar(conf,rc,key,val,MAXPATHLEN,&lbuf,&lbuf_max)) >0){

        /*
         * Add any client specific conf vars first
         * (none yet, but could provide defaults for command-line opts...)
         */

        /*
         * Now, daemon functionality
         */
        if( (dc = BWLDaemonParseArg(lctx,key,val))){
            if(dc < 0){
                rc = -rc;
                break;
            }
        }
        else{
            BWLError(lctx,BWLErrFATAL,BWLErrINVALID,"Unknown key=%s",key);
            rc = -rc;
            break;
        }
    }

    /*
     * Done with line buffer.
     */
    if(lbuf){
        free(lbuf);
    }
    lbuf = NULL;
    lbuf_max = 0;

    if(rc < 0){
        BWLError(lctx,BWLErrFATAL,BWLErrUNKNOWN,"%s:%d Problem parsing config file",conf_file,-rc);
        return False;
    }

    return True;
}

static BWLBoolean
parse_typeP(
        char        *tspec
        )
{
    char            *tstr,*endptr;
    unsigned long   tlng;
    uint8_t         tosbyte = 0;

    if(!tspec) return False;

    tstr = tspec;
    endptr = NULL;
    while(isspace((int)*tstr)) tstr++;
    tlng = strtoul(optarg,&endptr,0);

    /*
     * Try interpreting as hex DSCP value.
     * Verify user only sets
     * last 6 bits (DSCP must fit in 6 bits - RFC 2474.)
     */
    if((*endptr == '\0') && !(tlng & (unsigned)~0x3F)){
        /* save in tosbyte - uses high-order 6 bits instead of low */
        tosbyte = tlng << 2;
        tstr = endptr;
    }

    /*
     * It is useful to define some symbolic constants for the -D (DSCP)
     * value. RFC 4594 seemed a reasonable collection of these useful
     * constants.
     *
     * Table of constants from RFC 4594:
     *
     *
   *********************************************************************

    ------------------------------------------------------------------
   |   Service     |  DSCP   |    DSCP     |       Application        |
   |  Class Name   |  Name   |    Value    |        Examples          |
   |===============+=========+=============+==========================|
   |Network Control|  CS6    |   110000    | Network routing          |
   |---------------+---------+-------------+--------------------------|
   | Telephony     |   EF    |   101110    | IP Telephony bearer      |
   |---------------+---------+-------------+--------------------------|
   |  Signaling    |  CS5    |   101000    | IP Telephony signaling   |
   |---------------+---------+-------------+--------------------------|
   | Multimedia    |AF41,AF42|100010,100100|   H.323/V2 video         |
   | Conferencing  |  AF43   |   100110    |  conferencing (adaptive) |
   |---------------+---------+-------------+--------------------------|
   |  Real-Time    |  CS4    |   100000    | Video conferencing and   |
   |  Interactive  |         |             | Interactive gaming       |
   |---------------+---------+-------------+--------------------------|
   | Multimedia    |AF31,AF32|011010,011100| Streaming video and      |
   | Streaming     |  AF33   |   011110    |   audio on demand        |
   |---------------+---------+-------------+--------------------------|
   |Broadcast Video|  CS3    |   011000    |Broadcast TV & live events|
   |---------------+---------+-------------+--------------------------|
   | Low-Latency   |AF21,AF22|010010,010100|Client/server transactions|
   |   Data        |  AF23   |   010110    | Web-based ordering       |
   |---------------+---------+-------------+--------------------------|
   |     OAM       |  CS2    |   010000    |         OAM&P            |
   |---------------+---------+-------------+--------------------------|
   |High-Throughput|AF11,AF12|001010,001100|  Store and forward       |
   |    Data       |  AF13   |   001110    |     applications         |
   |---------------+---------+-------------+--------------------------|
   |    Standard   | DF (CS0)|   000000    | Undifferentiated         |
   |               |         |             | applications             |
   |---------------+---------+-------------+--------------------------|
   | Low-Priority  |  CS1    |   001000    | Any flow that has no BW  |
   |     Data      |         |             | assurance                |
    ------------------------------------------------------------------

                Figure 3. DSCP to Service Class Mapping
   *********************************************************************
     *
     * Mapping this to the full binary tos byte, and including CS? and
     * EF symbolic names...
     *
     *
     * Symbolic constants           6-bit DSCP
     *
     * none/default/CS0             000 000
     * CS1                          001 000
     * AF11                         001 010
     * AF12                         001 100
     * AF13                         001 110
     * CS2                          010 000
     * AF21                         010 010
     * AF22                         010 100
     * AF23                         010 110
     * CS3                          011 000
     * AF31                         011 010
     * AF32                         011 100
     * AF33                         011 110
     * CS4                          100 000
     * AF41                         100 010
     * AF42                         100 100
     * AF43                         100 110
     * CS5                          101 000
     * EF                           101 110
     * CS6                          110 000
     * CS7                          111 000
     */

    else if(!strncasecmp(tstr,"none",5)){
        /* standard */
        tstr += 4;
    }
    else if(!strncasecmp(tstr,"default",8)){
        /* standard */
        tstr += 7;
    }
    else if(!strncasecmp(tstr,"df",3)){
        /* standard */
        tstr += 2;
    }
    else if(!strncasecmp(tstr,"ef",3)){
        /* Expedited Forwarding */
        tosbyte = 0xB8;
        tstr += 2;
    }
    else if((toupper(tstr[0]) == 'C') && (toupper(tstr[1]) == 'S')){
        switch(tstr[2]){
            case '0':
                break;
            case '1':
                tosbyte = 0x20;
                break;
            case '2':
                tosbyte = 0x40;
                break;
            case '3':
                tosbyte = 0x60;
                break;
            case '4':
                tosbyte = 0x80;
                break;
            case '5':
                tosbyte = 0xA0;
                break;
            case '6':
                tosbyte = 0xC0;
                break;
            case '7':
                tosbyte = 0xE0;
                break;
            default:
                goto FAILED;
                break;
        }
        /* forward tstr to end of accepted pattern */
        tstr += 3;
    }
    else if(toupper(tstr[0] == 'A') && (toupper(tstr[1]) == 'F')){
        switch(tstr[2]){
            case '1':
                tosbyte = 0x20;
                break;
            case '2':
                tosbyte = 0x40;
                break;
            case '3':
                tosbyte = 0x60;
                break;
            case '4':
                tosbyte = 0x80;
                break;
            default:
                goto FAILED;
                break;
        }
        switch(tstr[3]){
            case '1':
                tosbyte |= 0x08;
                break;
            case '2':
                tosbyte |= 0x10;
                break;
            case '3':
                tosbyte |= 0x18;
                break;
            default:
                goto FAILED;
                break;
        }
        /* forward tstr to end of accepted pattern */
        tstr += 4;
    }

    /*
     * Forward past any whitespace and make sure arg is clean.
     */
    while(isspace((int)*tstr)) tstr++;
    if(*tstr != '\0'){
        goto FAILED;
    }

    app.opt.tos = tosbyte;

    return True;

FAILED:
    I2ErrLogP(eh,EINVAL,"Invalid DSCP value (-D): %M");
    return False;
}

static BWLBoolean
handle_conn_arg(const char arg, const char *long_name, const char *value, char **argv, int argc) {
    BWLBoolean handled = True;

    switch (arg) {
        case '4':
            app.opt.v4only = True;
            break;
        case '6':
            app.opt.v6only = True;
            break;
        case 'A':
            /* parse auth */
            if((parse_auth_args(eh,argv,argc,"BOTH",&app.def_auth) != 0) ||
                    !app.def_auth){
                usage("invalid default authentication");
                exit(1);
            }
            break;
        case 'B':
            if (!(app.opt.srcaddr = strdup(optarg))) {
                fprintf(stderr,"malloc failed\n");
                exit(1);
            }
            break;

        default:
            handled = False;
    }

    return handled;
}

static BWLBoolean
handle_output_arg(const char arg, const char *long_name, const char *value) {
    BWLBoolean handled = True;

    switch (arg) {
        case 'd':
            if (!(app.opt.savedir = strdup(optarg))) {
                fprintf(stderr,"malloc failed\n");
                exit(1);
            }
            break;
        case 'f':
            if(strlen(optarg) != 1){
                usage("Invalid value. (-f) Single character expected");
                exit(1);
            }
            app.opt.units = optarg[0];
            break;
        case 'p':
            app.opt.printfiles = True;
            break;
        case 'x':
            app.opt.bidirectional_results = True;
            break;
        default:
            handled = False;
    }

    return handled;
}

static BWLBoolean
handle_misc_arg(const char arg, const char *long_name, const char *value) {
    BWLBoolean handled = True;
    int fac;

    switch (arg) {
        case 'e':
            if((fac = I2ErrLogSyslogFacility(optarg)) == -1){
                fprintf(stderr, "Invalid -e: Unknown syslog facility");
                exit(1);
            }
            app.opt.log_facility = fac;
            break;
        case 'v':
            app.opt.verbose++;
            app.opt.log_to_stderr = True;
            break;
        case 'r':
            app.opt.log_to_stderr = True;
            break;
        case 'q':
            app.opt.quiet = True;
            break;
        case 'V':
            version();
            exit(0);
        case 'h':
        case '?':
            usage("");
            exit(0);
        default:
            handled = False;
    } 

    return handled;
}

static BWLBoolean
handle_scheduling_arg(const char arg, const char *long_name, const char *value) {
    BWLBoolean handled = True;
    char *tstr;

    switch (arg) {
        case 'a':
            app.opt.allowUnsync = strtod(optarg,&tstr);
            if((optarg == tstr) || (errno == ERANGE) ||
                    (app.opt.allowUnsync < 0.0)){
                usage("Invalid value \'-a\'. Positive float expected");
                exit(1);
            }
            break;
        case 'I':
            app.opt.seriesInterval =strtoul(optarg, &tstr, 10);
            if (*tstr != '\0') {
                usage("Invalid value. (-I) Positive integer expected");
                exit(1);
            }
            break;
        case 'R':
            app.opt.randomizeStart = strtoul(optarg,&tstr,10);
            if(*tstr != '\0'){
                usage("Invalid value. (-R) Positive integer expected");
                exit(1);
            }
            if(app.opt.randomizeStart > 50){
                usage("Invalid value. (-R) Value must be <= 50");
                exit(1);
            }
            break;
        case 'n':
            app.opt.nIntervals =strtoul(optarg, &tstr, 10);
            if (*tstr != '\0') {
                usage("Invalid value. Positive integer expected");
                exit(1);
            }
            break;
        case 'L':
            app.opt.seriesWindow = strtoul(optarg,&tstr,10);
            if(*tstr != '\0'){
                usage("Invalid value. Positive integer expected");
                exit(1);
            }
            break;
        default:
            handled = False;
    }

    return handled;
}

static BWLBoolean
handle_generic_test_arg(const char arg, const char *long_name, const char *value, char **argv, int argc) {
    BWLBoolean handled = True;

    switch (arg) {
        case 'c':
            if(app.receiver_sess->host){
                usage("-c flag can only be specified once");
                exit(1);
            }

            app.receiver_sess->host = optarg;

            if(parse_auth_args(eh,argv,argc,optarg,&app.receiver_sess->auth)
                    != 0){
                usage("invalid \'receiver\' authentication");
                exit(1);
            }
            break;
        case 's':
            if(app.sender_sess->host){
                usage("-s flag can only be specified once");
                exit(1);
            }

            app.sender_sess->host = optarg;

            if(parse_auth_args(eh,argv,argc,optarg,&app.sender_sess->auth)
                    != 0){
                usage("invalid \'sender\' authentication");
                exit(1);
            }
            break;

        case 'o':
            app.opt.flip_direction = True;
            break;

        case 'T':
            if (!(app.opt.tool = strdup(optarg))) {
                fprintf(stderr,"malloc failed\n");
                exit(1);
            }
            break;

        case 'y':
            if(strlen(optarg) != 1){
                usage("Invalid value. (-y) Single character expected");
                exit(1);
            }
            app.opt.outformat = optarg[0];
            break;

        default:
            handled = False;
    }

    return handled;
}

static BWLBoolean
handle_throughput_test_arg(const char arg, const char *long_name, const char *value) {
    BWLBoolean handled = True;
    char *tstr;

    switch (arg) {
        case 'b':
            if( !(tstr = strdup(optarg))){
                I2ErrLog(eh, "strdup(): %M");
                exit(1);
            }
            if(I2StrToNum(&app.opt.bandWidth,tstr) != 0){
                usage("Invalid value. (-b) Positive integer expected");
                exit(1);
            }
            free(tstr);
            tstr = NULL;
            break;
        case 'D':
            if(app.opt.tos){
                usage("Invalid option \'-D\'. TOS byte already specified");
                exit(1);
            }
            if(!parse_typeP(optarg)){
                exit(1);
            }
            break;
        case 'i':
            app.opt.reportInterval = strtod(optarg,&tstr) * 1000;
            if((optarg == tstr) || (errno == ERANGE) ||
                    (app.opt.reportInterval < 0.0)){
                usage("Invalid value. (-i) positive float expected");
                exit(1);
            }
            break;
        case 'l':
            if( !(tstr = strdup(optarg))){
                I2ErrLog(eh, "strdup(): %M");
                exit(1);
            }
            if(I2StrToByte(&app.opt.lenBuffer,tstr) != 0){
                usage("Invalid value. (-l) positive integer expected");
                exit(1);
            }
            free(tstr);
            tstr = NULL;
            break;
        case 'O':
            app.opt.timeOmit = strtoul(optarg,&tstr,10);
            if(*tstr != '\0'){
                usage("Invalid value. (-O) positive integer expected");
                exit(1);
            }
            if(app.opt.timeOmit > 60){
                usage("Invalid value. (-O) integer from 0 to 60 expected");
                exit(1);
            }
            break;
        case 'P':
            app.opt.parallel =strtoul(optarg, &tstr, 10);
            if (*tstr != '\0') {
                usage("Invalid value. Positive integer expected");
                exit(1);
            }
            break;
        case 'S':
            if(app.opt.tos){
                usage("Invalid option \'-S\'. TOS byte already specified");
                exit(1);
            }
            app.opt.tos = strtoul(optarg, &tstr, 0);
            if((*tstr != '\0') || (app.opt.tos > 0xff) ||
                    (app.opt.tos & 0x01)){
                usage("Invalid value for TOS. (-S)");
                exit(1);
            }
            break;
        case 't':
            app.opt.timeDuration = strtoul(optarg, &tstr, 10);
            if((*tstr != '\0') || (app.opt.timeDuration == 0)){
                usage("Invalid value \'-t\'. Positive integer expected");
                exit(1);
            }
            break;
        case 'u':
            app.opt.udpTest = True;
            break;
        case 'W':
            app.opt.dynamicWindowSize = True;
        case 'w':
            if(app.opt.winset){
                usage("Invalid args. Only one -w or -W may be set");
                exit(1);
            }
            app.opt.winset++;
            if( !(tstr = strdup(optarg))){
                I2ErrLog(eh, "strdup(): %M");
                exit(1);
            }
            if(I2StrToByte(&app.opt.windowSize,tstr) != 0){
                usage("Invalid value. (-w/-W) positive integer expected");
                exit(1);
            }
            free(tstr);
            tstr = NULL;
            break;
        default:
            handled = False;
    }
    return handled;
}

static BWLBoolean
handle_ping_test_arg(const char arg, const char *long_name, const char *value) {
    BWLBoolean handled = True;
    char *tstr;

    switch (arg) {
        case 'N':
            app.opt.ping_packet_count = strtoul(optarg,&tstr,10);
            if(*tstr != '\0') {
                usage("Invalid value. (-N) positive integer expected");
                exit(1);
            }
            break;
        case 'i':
            app.opt.ping_interpacket_time = strtod(optarg,&tstr) * 1000;
            if((optarg == tstr) || (errno == ERANGE) ||
                    (app.opt.ping_interpacket_time < 0.0)){
                usage("Invalid value. (-i) positive float expected");
                exit(1);
            }
            break;
        case 'l':
            app.opt.ping_packet_size = strtoul(optarg,&tstr,10);
            if(*tstr != '\0') {
                usage("Invalid value. (-l) positive integer expected");
                exit(1);
            }
            break;
        case 't':
            app.opt.ping_packet_ttl = strtoul(optarg,&tstr,10);
            if(*tstr != '\0') {
                usage("Invalid value. (-t) integer between 0 and 255 expected");
                exit(1);
            }
            break;
        case 'E':
            app.opt.allow_one_sided = True;
            break;
        case 'Q':
            app.opt.service_port = strtoul(optarg,&tstr,10);
            if(*tstr != '\0') {
                usage("Invalid value. (-t) positive integer expected");
                exit(1);
            }
            break;
        default:
            handled = False;
    }
    return handled;
}

static BWLBoolean
handle_traceroute_test_arg(const char arg, const char *long_name, const char *value) {
    BWLBoolean handled = True;
    char *tstr;

    switch (arg) {
        case 't':
            app.opt.timeDuration = strtoul(optarg,&tstr,10);
            if(*tstr != '\0' ||
               app.opt.timeDuration < 0) {
                usage("Invalid value. (-t) positive integer expected");
                exit(1);
            }
            break;
        case 'F':
            app.opt.traceroute_first_ttl = strtoul(optarg,&tstr,10);
            if(*tstr != '\0') {
                usage("Invalid value. (-F) integer between 0 and 255 expected");
                exit(1);
            }
            break;
        case 'l':
            app.opt.traceroute_packet_size = strtoul(optarg,&tstr,10);
            if(*tstr != '\0') {
                usage("Invalid value. (-l) positive integer expected");
                exit(1);
            }
            break;
        case 'E':
            app.opt.allow_one_sided = True;
            break;
        case 'M':
            app.opt.traceroute_last_ttl = strtoul(optarg,&tstr,10);
            if(*tstr != '\0') {
                usage("Invalid value. (-F) integer between 0 and 255 expected");
                exit(1);
            }
            break;
        default:
            handled = False;
    }
    return handled;
}

static void
build_arguments(char *buf, struct option *options) {
    int i, buf_i, opt_i;

    buf_i = 0;
    opt_i = 0;

    // build the option string/list
    for(i = 0; bwctl_options[i].test_types != BWL_TEST_UNDEFINED; i++) {
        if (!(bwctl_options[i].test_types & test_type))
            continue;

        // Add the long option
        options[opt_i] = bwctl_options[i].option;
        opt_i++;

        if (bwctl_options[i].option.val == 0)
            continue;

        // Add the short option
        buf[buf_i] = (char) bwctl_options[i].option.val;
        buf_i++;

        if (bwctl_options[i].option.has_arg == required_argument) {
            buf[buf_i] = ':';
            buf_i++;
        }
    }
    buf[buf_i] = '\0';
    options[opt_i].name =  NULL;
    options[opt_i].has_arg = 0;
    options[opt_i].flag    = 0;
    options[opt_i].val     = 0;

    return;
}

int
main(
        int    argc,
        char    **argv
    )
{
    int                 lockfd;
    char                lockpath[PATH_MAX];
    int                 rc;
    I2ErrLogSyslogAttr  syslogattr;

    int                 fname_len;
    int                 ch;
    int                 opt_index;
    char                opt_str[128];
    struct option       opt_list[128];
    static char         *conn_opts = "46a:AB:";
    static char         *misc_opts = "hV?";
    static char         *out_opts = "d:e:f:I:L:n:pqrR:vxy:";
    static char         *generic_test_opts = "c:s:T:o";
    static char         *throughput_test_opts = "b:D:i:l:O:P:S:t:uw:W:";
    static char         *ping_test_opts = "N:l:t:i:EQ:";
    static char         *traceroute_test_opts = "F:M:l:t:i:E";
    static char         *posixly_correct="POSIXLY_CORRECT=True";

    char                dirpath[PATH_MAX];
    struct flock        flk;
    struct sigaction    act;
    sigset_t            sigs;
    double              syncfuzz;
    BWLTestSpec         test_options;

    /*
     * Make sure the signal mask is UNBLOCKING TERM/HUP/INT
     */
    sigemptyset(&sigs);
    sigaddset(&sigs,SIGTERM);
    sigaddset(&sigs,SIGINT);
    sigaddset(&sigs,SIGHUP);
    sigaddset(&sigs,SIGALRM);
    sigaddset(&sigs,SIGCHLD);
    if(sigprocmask(SIG_UNBLOCK,&sigs,NULL) != 0){
        I2ErrLog(eh,"sigprocmask(): %M");
        exit(1);
    }

    if((progname = strrchr(argv[0], '/'))){
        progname++;
    }else{
        progname = *argv;
    }

    if (strcmp(progname, "bwping") == 0) {
        test_type = BWL_TEST_LATENCY;
    }
    else if (strcmp(progname, "bwtraceroute") == 0) {
        test_type = BWL_TEST_TRACEROUTE;
    }
    else {
        test_type = BWL_TEST_THROUGHPUT;
    }

    syslogattr.ident = progname;
    syslogattr.logopt = 0;
    syslogattr.facility = LOG_USER;
    syslogattr.priority = LOG_ERR;
    syslogattr.line_info = I2MSG;

    /* Set default options. */

    memset(&app,0,sizeof(app));
    app.opt.timeDuration = 10;
    app.opt.randomizeStart = 10;

    memset(&sessions[0],0,sizeof(sessions[0]));
    memset(&sessions[1],0,sizeof(sessions[1]));
    memset(&test_options,0,sizeof(test_options));

    app.receiver_sess = &(sessions[0]);
    app.sender_sess   = &(sessions[1]);

    /*
     * Fix getopt if the brain-dead GNU version is being used.
     */
    if(putenv(posixly_correct) != 0){
        fprintf(stderr,"Unable to set POSIXLY_CORRECT getopt mode");
        exit(1);
    }

    // build the option string/list
    build_arguments(opt_str, opt_list);

    opt_index = 0;
    while((ch = getopt_long(argc, argv, opt_str, opt_list, &opt_index)) != -1){
        const char *long_name = opt_list[opt_index].name;

        if (handle_conn_arg(ch, long_name, optarg, argv, argc))
            continue;

        if (handle_output_arg(ch, long_name, optarg))
            continue;

        if (handle_misc_arg(ch, long_name, optarg))
            continue;

        if (handle_scheduling_arg(ch, long_name, optarg))
            continue;

        if (handle_generic_test_arg(ch, long_name, optarg, argv, argc))
            continue;

        if (test_type == BWL_TEST_THROUGHPUT) {
            if (handle_throughput_test_arg(ch, long_name, optarg))
                continue;
        }
        else if (test_type == BWL_TEST_TRACEROUTE) {
            if (handle_traceroute_test_arg(ch, long_name, optarg))
                continue;
        }
        else if (test_type == BWL_TEST_LATENCY) {
            if (handle_ping_test_arg(ch, long_name, optarg))
                continue;
        }
        
        usage("");
        exit(0);
    }

    if(app.opt.verbose && app.opt.quiet){
        fprintf(stderr,"Ignoring -q (-v specified)\n");
        app.opt.quiet = False;
    }
    if(!app.opt.quiet){
        syslogattr.logopt |= LOG_PERROR;
    }
    if(app.opt.verbose > 1){
        syslogattr.logopt |= LOG_PID;
        syslogattr.line_info |= I2FILE | I2LINE;
    }

    /*
     * Start an error logging session for reporting errors to the
     * standard error
     */
    eh = I2ErrOpen(progname, I2ErrLogSyslog, &syslogattr, NULL, NULL);
    if(! eh) {
        fprintf(stderr, "%s : Couldn't init error module\n", progname);
        exit(1);
    }

    if(app.opt.verbose){
        fprintf(stderr,
                "Messages being sent to syslog(%s,%s)\n",
                I2ErrLogSyslogFacilityName(syslogattr.facility),
                I2ErrLogSyslogPriorityName(syslogattr.priority));
    }

    /*
     * Initialize library with configuration functions.
     */
    if( !(ctx = BWLContextCreate(eh,
                    BWLInterruptIO, &ip_intr,
                    BWLGetAESKey,   getclientkey,
                    NULL))){
        fprintf(stderr, "Unable to initialize BWL library.\n");
        exit(1);
    }

    /*
     * Currently mostly for daemon config options, but allowing this to
     * set defaults for the client could be nice.
     */
    if( !LoadConfig(ctx)){
        I2ErrLog(eh, "Unable to initialize configuration.");
        exit(1);
    }

    if(optind < argc) {
        usage("");
        exit(1);
    }

    if(!app.receiver_sess->host && !app.sender_sess->host){
        usage("At least one of -s or -c must be specified.");
        exit(1);
    }

    if(!app.receiver_sess->host) {
        if (!(app.receiver_sess->host = strdup("localhost"))){
            I2ErrLog(eh,"malloc:%M");
            exit(1);
        }

        app.receiver_sess->is_local = True;
    }

    if(!app.sender_sess->host) {
        if (!(app.sender_sess->host = strdup("localhost"))){
            I2ErrLog(eh,"malloc:%M");
            exit(1);
        }

        app.sender_sess->is_local = True;
    }

    app.sender_sess->is_receiver = False;
    app.receiver_sess->is_receiver = True;

    if (app.opt.flip_direction) {
        app.receiver_sess->is_client = True;
        app.client_sess = app.receiver_sess;
        app.server_sess = app.sender_sess;
    }
    else {
        app.sender_sess->is_client = True;
        app.client_sess = app.sender_sess;
        app.server_sess = app.receiver_sess;
    }

    if (app.opt.tool) {
        if( (app.opt.tool_id = BWLToolGetID(ctx,app.opt.tool)) ==
                BWL_TOOL_UNDEFINED){
            char    buf[BWL_MAX_TOOLNAME + 20];
            snprintf(buf,sizeof(buf)-1,"Invalid tool (-T): %s",app.opt.tool);
            usage(buf);
            exit(1);
        }

        if( test_type != BWLToolGetTestTypesByID(ctx,app.opt.tool_id) ) {
            char buf[1024];
            char *proper_cmd_name;
            if (BWLToolGetTestTypesByID(ctx,app.opt.tool_id) == BWL_TEST_TRACEROUTE) {
                proper_cmd_name = "bwtraceroute";
            }
            else if (BWLToolGetTestTypesByID(ctx,app.opt.tool_id) == BWL_TEST_LATENCY) {
                proper_cmd_name = "bwping";
            }
            else if (BWLToolGetTestTypesByID(ctx,app.opt.tool_id) == BWL_TEST_THROUGHPUT) {
                proper_cmd_name = "bwctl";
            }
            snprintf(buf,sizeof(buf)-1,"Invalid tool (-T): %s. Tool should be used with %s",app.opt.tool, proper_cmd_name);
            usage(buf);
            exit(1);
        }
    }


    if (app.opt.allow_one_sided &&
          app.opt.flip_direction) {
        I2ErrLog(eh,"-E and -o flags cannot be used together.");
        exit(1);
    }

    app.client_sess->require_endpoint = True;
    if (app.opt.allow_one_sided) {
        if (app.opt.verbose) {
            I2ErrLog(eh,"Server side does not require an endpoint");
        }
        app.server_sess->require_endpoint = False;
    }
    else {
        app.server_sess->require_endpoint = True;
    }

    if (!app.opt.allow_one_sided && app.opt.service_port) {
        I2ErrLog(eh,"-Q flag can only be used with -E flag");
        exit(1);
    }

    /*
     * -4/-6 sanity check
     */
    if(app.opt.v4only && app.opt.v6only){
        I2ErrLog(eh,"-4 and -6 flags cannot be used together.");
        exit(1);
    }

    if((app.opt.v4only) &&
            !BWLContextConfigSet(ctx,BWLIPv4Only,(void*)True)){
        I2ErrLog(eh,"BWLContextconfigSet(IPv4Only): %M");
        exit(1);
    }

    if((app.opt.v6only) &&
            !BWLContextConfigSet(ctx,BWLIPv6Only,(void*)True)){
        I2ErrLog(eh,"BWLContextconfigSet(IPv6Only): %M");
        exit(1);
    }

    /*
     * Useful constant
     */
    zero64 = BWLULongToNum64(0);

    /*
     * Check savedir option. Make sure it will not make fnames
     * exceed PATH_MAX even with the nul byte.
     * Also set file_offset and ext_offset to the lengths needed.
     */
    fname_len = BWL_TSTAMPCHARS + DIRECTION_EXT_LEN + strlen(BWL_FILE_EXT);
    assert((fname_len+1)<PATH_MAX);
    if(app.opt.savedir){
        if((strlen(app.opt.savedir) + strlen(BWL_PATH_SEPARATOR)+
                    fname_len + 1) > PATH_MAX){
            usage("-d: pathname too long.");
            exit(1);
        }
        strcpy(dirpath,app.opt.savedir);
        strcat(dirpath,BWL_PATH_SEPARATOR);
    }else{
        dirpath[0] = '\0';
    }

    /*
     * Possibly over-ride .bwctlrc allow_unsync and sync_fuzz options
     * with command-line.
     */
    syncfuzz = app.opt.allowUnsync;

    /*
     * Set configurable constants for library
     */
    if(app.opt.verbose){
        BWLContextSetErrMask(ctx,BWLErrOK);
    }
    else{
        BWLContextSetErrMask(ctx,BWLErrINFO);
    }

    if( !BWLContextConfigGetV(ctx,BWLAllowUnsync)){
        if( !BWLContextConfigSet(ctx,BWLAllowUnsync,(syncfuzz != 0.0))){
            I2ErrLog(eh,"BWLContextconfigSet(AllowUnsync): %M");
            exit(1);
        }
    }

    if((syncfuzz != 0.0) &&
                !BWLContextConfigSet(ctx,BWLSyncFuzz,syncfuzz)){
        I2ErrLog(eh,"BWLContextconfigSet(SyncFuzz): %M");
        exit(1);
    }

    if(getenv("BWCTL_DEBUG_CHILDWAIT")){
        if( !BWLContextConfigSet(ctx,BWLChildWait,(void*)!NULL)){
            I2ErrLog(eh,"BWLContextconfigSet(ChildWait): %M");
            exit(1);
        }
    }

    /*
     * Initialize logging and clock issues, now that configuration complete.
     */
    if( !BWLContextFinalize(ctx)){
        I2ErrLog(eh,"BWLContextFinalize failed.");
        exit(1);
    }

    /*
     * Set default test parameters if they're not already set.
     */
    if (test_type == BWL_TEST_TRACEROUTE) {
        if(!app.opt.timeDuration){
            app.opt.timeDuration = 10;
        }

    }
    else if (test_type == BWL_TEST_LATENCY) {
        if(!app.opt.ping_packet_count){
            app.opt.ping_packet_count = 10;
        }

        if(!app.opt.ping_interpacket_time){
            app.opt.ping_interpacket_time = 1000;
        }

        app.opt.timeDuration = app.opt.ping_packet_count * (app.opt.ping_interpacket_time / 1000.0) + 3;
    }
    else {
        if(!app.opt.timeDuration){
            app.opt.timeDuration = 10;
        }

        /*
         * UDP bandwidth checks.
         */
        if(app.opt.udpTest && !app.opt.bandWidth){
            app.opt.bandWidth = DEF_UDP_RATE;
        }
    }

    if( !(rsrc = I2RandomSourceInit(eh,I2RAND_DEV,NULL))){
        I2ErrLog(eh,"Failed to initialize Random Numbers");
        exit(1);
    }

    /*
     * If seriesInterval is in use, verify the args and pick a
     * resonable default for seriesWindow if needed.
     */
    if(app.opt.seriesInterval){
        if(app.opt.seriesInterval <
                (app.opt.timeDuration + SETUP_ESTIMATE)){
            usage("-I: interval too small relative to -t");
            exit(1);
        }

        /*
         * If nIntervals not set, continuous tests are requested.
         */
        if(!app.opt.nIntervals){
            app.opt.continuous = True;
        }
        /*
         * Make sure tests start before 50% of the 'interval' is
         * gone.
         */
        if(!app.opt.seriesWindow){
            app.opt.seriesWindow = (uint32_t)MIN(
                    app.opt.seriesInterval-app.opt.timeDuration,
                    app.opt.seriesInterval * 0.5);
        }
    }
    else{
        /*
         * Make sure tests start within 2 test durations. (But
         * no less than 5 minutes for the default.)
         */
        if(!app.opt.seriesWindow){
            app.opt.seriesWindow = MAX(app.opt.timeDuration * 2,600);
        }
        /*
         * If nIntervals not set, and seriesInterval not set
         * a single test is requested.
         */
        if(!app.opt.nIntervals){
            app.opt.nIntervals = 1;
        }
    }

    /*
     * Lock the directory for bwctl if it is in printfiles mode.
     */
    if(app.opt.printfiles){
        strcpy(lockpath,dirpath);
        strcat(lockpath,BWLOCK);
        lockfd = open(lockpath,O_RDWR|O_CREAT,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        if(lockfd < 0){
            I2ErrLog(eh,"open(%s): %M",lockpath);
            exit(1);
        }

        flk.l_start = 0;
        flk.l_len = 0;
        flk.l_type = F_WRLCK;
        flk.l_whence = SEEK_SET;
        while((rc = fcntl(lockfd,F_SETLK,&flk)) < 0 && errno == EINTR);
        if(rc < 0){
            I2ErrLog(eh,"Unable to lock file %s: %M",lockpath);
            if(I2Readn(lockfd,&ch,sizeof(ch)) == sizeof(ch)){
                I2ErrLog(eh,"Possibly locked by pid(%d)",ch);
            }
            exit(1);
        }

        ch = getpid();
        if(I2Writen(lockfd,&ch,sizeof(ch)) != sizeof(ch)){
            I2ErrLog(eh,"Unable to write to lockfile:%M");
            exit(1);
        }
    }

    /*
     * Initialize session records
     */
    /* skip req_time/latest_time - set per/test */
    if(app.opt.tool_id){
        test_options.tool_id = app.opt.tool_id;
    }
    else{
        test_options.tool_id = BWL_TOOL_UNDEFINED;
    }
    test_options.verbose = app.opt.verbose > 0 ? 1 : 0;

    test_options.duration = app.opt.timeDuration;

    test_options.outformat = app.opt.outformat;

    if (app.opt.flip_direction) {
        test_options.server_sends = True;
    }

    if (test_type == BWL_TEST_TRACEROUTE) {
        test_options.traceroute_udp = app.opt.traceroute_udp;
        test_options.traceroute_packet_size = app.opt.traceroute_packet_size;
        test_options.traceroute_first_ttl = app.opt.traceroute_first_ttl;
        test_options.traceroute_last_ttl = app.opt.traceroute_last_ttl;
    }
    else if (test_type == BWL_TEST_LATENCY) {
        test_options.ping_packet_count = app.opt.ping_packet_count;
        test_options.ping_packet_size = app.opt.ping_packet_size;
        test_options.ping_packet_ttl = app.opt.ping_packet_ttl;
        test_options.ping_interpacket_time = app.opt.ping_interpacket_time;
    }
    else {
        test_options.udp = app.opt.udpTest;
        test_options.tos = app.opt.tos;
        test_options.bandwidth = app.opt.bandWidth;
        test_options.window_size = (uint32_t)app.opt.windowSize;
        if(app.opt.windowSize != (I2numT)test_options.window_size){
            test_options.window_size = (uint32_t)~0;
            I2ErrLog(eh,"Requested -w/-W option (%llu) too large: max supported size: (%llu)",app.opt.windowSize,test_options.window_size);
            exit(1);
        }
        test_options.dynamic_window_size = app.opt.dynamicWindowSize;
        test_options.len_buffer = (uint32_t)app.opt.lenBuffer;
        if(app.opt.lenBuffer != (I2numT)test_options.len_buffer){
            test_options.len_buffer = (uint32_t)~0;
            I2ErrLog(eh,"Requested -l option (%llu) too large: max supported size: (%llu)",app.opt.lenBuffer,test_options.len_buffer);
            exit(1);
        }
        test_options.report_interval = app.opt.reportInterval;
        test_options.units = app.opt.units;
        test_options.omit = app.opt.timeOmit;
        test_options.parallel_streams = app.opt.parallel;
    }

    /*
     * setup sighandlers
     */
    ip_chld = ip_reset = ip_exit = 0;
    act.sa_handler = sig_catch;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NOCLDSTOP;
    if(        (sigaction(SIGCHLD,&act,NULL) != 0) ||
            (sigaction(SIGTERM,&act,NULL) != 0) ||
            (sigaction(SIGALRM,&act,NULL) != 0) ||
            (sigaction(SIGINT,&act,NULL) != 0) ||
            (sigaction(SIGHUP,&act,NULL) != 0)){
        I2ErrLog(eh,"sigaction(): %M");
        exit(1);
    }

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = SIG_IGN;
    if(    (sigaction(SIGPIPE,&act,NULL) != 0)){
        I2ErrLog(eh,"sigaction(): %M");
        exit(1);
    }

    while(app.opt.continuous || app.opt.nIntervals) {

        app.opt.nIntervals--;

        if(sig_check()){
            exit_val = 1;
            goto finish;
        }

        if (!wait_for_next_test()) {
            goto finish;
        }

        /*
         * Check if NTP is synchronized, and if not, verify that we're running
         * allow_unsync. If not, wait until the next test interval to see if
         * we're synchronized then.
         */
        if (BWLNTPIsSynchronized(ctx) == False) {
            if( !BWLContextConfigGetV(ctx,BWLAllowUnsync)){
                BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"NTP is unsynchronized. Skipping test. Use -a to run anyway.");
                goto next_test;
            }
        }

        if (!establish_connection(app.receiver_sess, app.sender_sess)) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

        if (!establish_connection(app.sender_sess, app.receiver_sess)) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

        if (!negotiate_test(app.server_sess, app.client_sess, &test_options)) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

        if (!setup_results_storage(app.server_sess)) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

        if (!setup_results_storage(app.client_sess)) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

        if (!start_testing(app.server_sess, app.client_sess)) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

        if (!wait_for_results()) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

        if (!display_results(app.server_sess)) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

        if (!display_results(app.client_sess)) {
            if (exit_val)
                goto finish;
            else
                goto next_test;
        }

next_test:
        if(sig_check()){
            exit_val = 1;
            goto finish;
        }

        // Close the session between runs
        CloseSessions();
    }

finish:
    CloseSessions();

    BWLContextFree(ctx);
    ctx = NULL;

    exit(exit_val);
}

static BWLBoolean
establish_connection(ipsess_t current_sess, ipsess_t other_sess)
{
    BWLErrSeverity err_ret = BWLErrOK;
    I2Addr local_address;
    char *host_address;
    char temp[1024];

    if (current_sess->cntrl) {
        return True;
    }

    if (current_sess->is_local) {
        current_sess->fake_daemon = False;
        host_address = BWLDiscoverSourceAddr(ctx, other_sess->host, temp, sizeof(temp));
        if (!host_address) {
            I2ErrLog(eh,
                    "Couldn't figure out address to use to connect to %s", other_sess->host);
            goto error_exit;
        }
    }
    else {
        host_address = current_sess->host;
    }

    current_auth = ((current_sess->auth)?current_sess->auth:app.def_auth);
    /*
     * If the session host is specified, a bwctld
     * process is required.
     */
    current_sess->cntrl = BWLControlOpen(ctx,
            app.opt.srcaddr,
            I2AddrByNode(eh,host_address),
            ((current_auth)?
             current_auth->auth_mode:
             BWL_MODE_OPEN),
            ((current_auth)?
             current_auth->identity:NULL),
            NULL,&current_sess->avail_tools,&err_ret);

    if(sig_check()){
        exit_val = 1;
        goto error_exit;
    }

    if(!current_sess->cntrl) {
        if(current_sess->is_local){
            /*
             * No local daemon - spawn something.
             */
            I2ErrLog(eh,
                    "Unable to contact a local bwctld: Spawning local tool controller");

            if( !(current_sess->cntrl =
                        spawn_local_server(ctx,current_sess,&current_sess->avail_tools))){
                I2ErrLog(eh,"Unable to spawn local tool controller");
            }
        }
        else if (current_sess->require_endpoint == False) {
            I2ErrLog(eh,"Spawning endpoint to handle remote side");
            if( !(current_sess->cntrl =
                        spawn_local_server(ctx,current_sess,&current_sess->avail_tools))){
                I2ErrLog(eh,"Unable to spawn local tool controller");
            }
        }
    }

    if(sig_check()){
        exit_val = 1;
        goto error_exit;
    }

    if(!current_sess->cntrl){
        I2ErrLog(eh,"Unable to connect to %s",host_address);
        goto error_exit;
    }

    /*
     * Get sockfd for later 'select' usage
     */
    current_sess->sockfd = BWLControlFD(current_sess->cntrl);

    /*
     * Query time error and update round-trip bound.
     */
    if(BWLControlTimeCheck(current_sess->cntrl,&current_sess->host_time) !=
            BWLErrOK){
        I2ErrLogP(eh,errno,"BWLControlTimeCheck: %M");
        goto error_exit;
    }

    if(sig_check()){
        exit_val = 1;
        goto error_exit;
    }

    current_sess->rttbound = BWLGetRTTBound(current_sess->cntrl);
    BWLSetTimeStampError(&current_sess->host_time,
                            BWLNum64Add(current_sess->rttbound,
                                  BWLGetTimeStampError(&current_sess->host_time)
                            )
                        );


    return True;

error_exit:
    return False;
}

static I2Addr
get_session_address(ipsess_t current_sess, ipsess_t other_sess) {
    I2Addr   address;
    char    *session_address;
    char    buf[1024];
    char    buflen;;


    if (current_sess->is_local) {
        session_address = BWLDiscoverSourceAddr(ctx, other_sess->host, buf, sizeof(buf));
    }
    else {
        session_address = current_sess->host;
    }

    if (!session_address) {
        I2ErrLog(eh,"Couldn't figure out address to use to connect to %s as %s.",
                    other_sess->host,
                    (current_sess->is_client?"client":"server"));
        return NULL;
    }

    address = I2AddrByNode(eh, session_address);

    if (app.opt.verbose) {
        I2ErrLog(eh,"Resolving %s", session_address);
    }

    if (BWLAddrIsLoopback(address)) {
        I2Addr new_addr = BWLAddrByLocalControl(other_sess->cntrl);

        session_address = BWLAddrNodeName(ctx, new_addr,buf,sizeof(buf), 0);

        if (I2AddrPort(address)) {
            char buf2[1024];

            snprintf(buf2, sizeof(buf2), "[%s]:%d", session_address, I2AddrPort(address));
            strncpy(buf, buf2, sizeof(buf));
        }

        I2AddrFree(address);

        I2ErrLog(eh,"Hostname '%s' resolves to a loopback address, using %s instead.", current_sess->host, session_address);

        address = I2AddrByNode(eh, session_address);
    }

    if (app.opt.verbose) {
        I2ErrLog(eh,"Current session is %s, using %s as the address for %s.",
                (current_sess->is_local?"local":"remote"),
                session_address,
                (current_sess->is_client?"client":"server"));
    }

    return address;
}

static BWLBoolean
negotiate_test(ipsess_t server_sess, ipsess_t client_sess, BWLTestSpec *test_options)
{
    BWLToolAvailability common_tools;
    BWLNum64            time_offset;
    BWLTimeStamp        req_time;
    BWLErrSeverity      err_ret = BWLErrOK;
    uint16_t            recv_port = 0;
    BWLSID              sid;

    test_options->client = get_session_address(client_sess, server_sess);
    test_options->server = get_session_address(server_sess, client_sess);

    if(!test_options->client){
        I2ErrLog(eh,"Unable to determine client address: %M");
        exit_val = 1;
        goto error_exit;
    }

    if(!test_options->server){
        I2ErrLog(eh,"Unable to determine server address: %M");
        exit_val = 1;
        goto error_exit;
    }

    /* Pick tool */

    /* Check if the requested tool is available at both servers. */
    common_tools = BWLToolGetCommonTools(ctx, client_sess->avail_tools,
                                         server_sess->avail_tools, test_type);
    if(!common_tools){
        I2ErrLog(eh,"No tools in common");
        goto error_exit;
    }

    I2ErrLog( eh, "Available in-common: %s", BWLToolGetToolNames( ctx, common_tools ) );

    if ( test_options->tool_id == BWL_TOOL_UNDEFINED ) {
        uint32_t tid;
        const char *req_name;

        /* Pick the first common tool to use. */
        tid = 1;
        for ( tid = 1; tid > 0; tid <<= 1 ) {
            if ( tid & common_tools )
                break;
        }
        test_options->tool_id = tid;
        req_name = BWLToolGetNameByID( ctx, test_options->tool_id );
        I2ErrLog( eh, "Using tool: %s", req_name );
    } else if ( ! ( test_options->tool_id & common_tools ) ) {
        char unknown[BWL_MAX_TOOLNAME];
        const char *req_name;

        req_name = BWLToolGetNameByID( ctx, test_options->tool_id );
        if ( ! req_name ) {
            sprintf( unknown, "unknown(id=%x)", test_options->tool_id );
            req_name = unknown;
        }
        I2ErrLog( eh, "Requested tool \"%s\" not supported by both servers. See the \'-T\' option", req_name );
        I2ErrLog( eh, "Available in-common: %s", BWLToolGetToolNames( ctx, common_tools ) );
        goto error_exit;
    }

    /*
     * Now caluculate how far into the future the test
     * request should be made for.
     *
     * The protocol messages that must happen are:
     * client -> first    request
     * client -> first    start
     * client -> second    request
     * client -> second    start
     * Then, there are 3 round trips between the server systems
     * for a peer connection setup. In the worst case, the
     * server two server rtt can be estimated as the sum of
     * the client->first and client->second rtts. So, we would
     * expect the amount of time required to setup a test to
     * be (rtt(c->first)+rtt(c->second))x7.
     *
     */
    /* initialize */
    time_offset = BWLNum64Mult(
            BWLNum64Add(client_sess->rttbound,server_sess->rttbound),
            BWLULongToNum64(7));
    /*
     * Add a small constant value to this... Will need to experiment
     * to find the right number. All the previous values were
     * basically estimates for how long it would take to make
     * the request. This is roughly the time into the future we
     * want to make the request for above and beyond the amount
     * of time it takes to actually make the request. It should
     * be short enough to not be annoying for interactive use, but
     * long enough to account for most random delays.
     * (The larger this value is, the more likely the two servers
     * will be able to accomidate the request initially - the
     * smaller, the more TestRequests will probably need to be made.
     * )
     * TODO: Come up with a *real* value here!
     * (Actually - make this an option?)
     */
    time_offset = BWLNum64Add(time_offset,BWLDoubleToNum64(.25));

    /*
     * Wait this long after a test should be complete before
     * poking the servers. It should be long enough to allow
     * the servers to declare the session complete before the
     * client does.
     * (Again 1 seconds is just a guess - I'm making a lot of
     * guesses due to time constrants. If these values cause
     * problems they can be revisited.)
     */
    fuzz64 = BWLNum64Add(BWLULongToNum64(1),
            BWLNum64Max(client_sess->rttbound,server_sess->rttbound));

    /*
     * req_time currently holds a reasonable relative amount of
     * time from 'now' that a test could be held. Get the current
     * time and add to make that an 'absolute' value.
     */
    if(!BWLGetTimeStamp(ctx,&req_time)){
        I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
        goto error_exit;
    }
    req_time.tstamp = BWLNum64Add(req_time.tstamp,
            time_offset);

    /*
     * Get a reservation:
     *     s[0] == server
     *     s[1] == client
     *     initialize req_time/latest_time
     *     keep querying each server in turn until satisfied,
     *     or denied.
     */
    test_options->latest_time = BWLNum64Add(req_time.tstamp, BWLULongToNum64(app.opt.seriesWindow));

    memset(sid,0,sizeof(sid));
    if(app.opt.verbose > 1){
        I2ErrLog(eh,"Requested Time: %lf",
                BWLNum64ToTimestampDouble(req_time.tstamp));
        I2ErrLog(eh,"Latest Acceptable Time: %lf",
                BWLNum64ToTimestampDouble(test_options->latest_time));
    }

    memcpy(&client_sess->tspec,test_options,sizeof(*test_options));
    memcpy(&server_sess->tspec,test_options,sizeof(*test_options));

    if (server_sess->fake_daemon && !server_sess->is_local) {
        client_sess->tspec.no_server_endpoint = True;
        server_sess->tspec.no_server_endpoint = True;
    }

    /*
     * Since we are doing a third party test, the "time" we're sending to each
     * host theoretically corresponds to the time from the other host, meaning
     * the timestamp error we send with each request should be the timestamp
     * error from the other host.
     */
    BWLSetTimeStampError(&client_sess->tspec.req_time, BWLGetTimeStampError(&server_sess->host_time));
    BWLSetTimeStampError(&server_sess->tspec.req_time, BWLGetTimeStampError(&client_sess->host_time));

    client_sess->session_requested = False;
    server_sess->session_requested = False;

    do {
        server_sess->tspec.req_time.tstamp = req_time.tstamp;

        if (!negotiate_individual_test(server_sess, sid, &req_time, &recv_port)) {
            goto error_exit;
        }

        if(sig_check()){
            exit_val = 1;
            goto error_exit;
        }

        if(app.opt.verbose){
          I2ErrLog(eh, "Server \'%s\' accepted test request at time %lf", server_sess->host, BWLNum64ToTimestampDouble(req_time.tstamp));
        }

        if (!client_sess->session_requested ||
            BWLNum64Cmp(client_sess->tspec.req_time.tstamp, server_sess->tspec.req_time.tstamp) != 0) {

            client_sess->tspec.req_time.tstamp = req_time.tstamp;

            // override the service port in the case we're doing a one-sided
            // test, and the -Q flag has been specified.
            if (client_sess->tspec.no_server_endpoint && app.opt.service_port) {
                recv_port = app.opt.service_port;
            }

            if (!negotiate_individual_test(client_sess, sid, &req_time, &recv_port)) {
                goto error_exit;
            }

            if(sig_check()){
                exit_val = 1;
                goto error_exit;
            }

            if(app.opt.verbose){
                I2ErrLog(eh, "Client \'%s\' accepted test request at time %lf", client_sess->host, BWLNum64ToTimestampDouble(req_time.tstamp));
            }
        }

        if (app.opt.verbose) {
            if (BWLNum64Cmp(client_sess->tspec.req_time.tstamp, server_sess->tspec.req_time.tstamp) != 0) {
                I2ErrLog(eh, "Tests accepted at different times re-requesting test with new time");
            }
        }
    }
    while (BWLNum64Cmp(client_sess->tspec.req_time.tstamp, server_sess->tspec.req_time.tstamp) != 0);

    return True;

error_exit:
    if (client_sess->session_requested) {
        I2ErrLog(eh, "Cancelling requested test for %s", client_sess->host);
        client_sess->tspec.req_time.tstamp = zero64;
        if(!BWLSessionRequest(
                            client_sess->cntrl,
                            client_sess->is_client,
                            &client_sess->tspec,
                            &req_time,
                            &recv_port,
                            sid,
                            &err_ret)){
                    I2ErrLog(eh,
                            "Problem cancelling requested test for \'%s\'",
                            client_sess->host);
        }
    }

    if (server_sess->session_requested) {
        I2ErrLog(eh, "Cancelling requested test for %s", server_sess->host);
        server_sess->tspec.req_time.tstamp = zero64;
        if(!BWLSessionRequest(
                            server_sess->cntrl,
                            server_sess->is_client,
                            &server_sess->tspec,
                            &req_time,
                            &recv_port,
                            sid,
                            &err_ret)){
                    I2ErrLog(eh,
                            "Problem cancelling requested test for \'%s\'",
                            server_sess->host);
        }
    }

    return False;
}

static BWLBoolean
negotiate_individual_test(ipsess_t sess, BWLSID sid, BWLTimeStamp *req_time, uint16_t *recv_port)
{
    BWLErrSeverity      err_ret = BWLErrOK;

    // presume that the request time is right

    /*
     * Make the request
     */
    if(!BWLSessionRequest(sess->cntrl,sess->is_client,
                &sess->tspec,req_time,recv_port,
                sid,&err_ret)){
        /*
         * Session was not accepted.
         */

        /*
         * If control connection is not ok...
         */
        if(err_ret != BWLErrOK){
            I2ErrLog(eh,
                        "SessionRequest Control connection failure for \'%s\'. Skipping...",
                        sess->host);
        }
        else if(req_time->tstamp != zero64){
            /*
             * Request is ok, but server
             * is too busy. Skip this test
             * and proceed to next session
             * interval.
             */
            I2ErrLog(eh,"SessionRequest: %s busy. (Try -L flag)",
                    sess->host);
        }
        else{
            /*
             * Don't know why it was
             * denied.
             */
            I2ErrLog(eh,"SessionRequest: Denied by %s",
                    sess->host);
        }

        goto error_exit;
    }

    if(sig_check()){
        exit_val = 1;
        goto error_exit;
    }

    sess->session_requested = True;

    if(app.opt.verbose > 1){
        I2ErrLog(eh,"Reservation(%s): %lf",sess->host,
                BWLNum64ToTimestampDouble(req_time->tstamp));
    }

    if(BWLNum64Cmp(req_time->tstamp,
                    sess->tspec.latest_time) > 0){
        I2ErrLog(eh,
                "SessionRequest: \'%s\' returned bad reservation time",
                sess->host);
        goto error_exit;
    }

    /* save new time for res */
    sess->tspec.req_time.tstamp = req_time->tstamp;

    return True;

error_exit:
    return False;
}

static BWLBoolean
wait_for_next_test()
{
    BWLTimeStamp currtime;
    BWLTimeStamp wake;
    static BWLBoolean is_first = True;

    /*
     * Initialize wake time to current time. If this is a single test,
     * this will indicate an immediate test. If seriesInterval is set,
     * this time will be adjusted to spread start times out.
     */
    if(!BWLGetTimeStamp(ctx,&wake)){
        I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
        goto error_exit;
    }

    if (is_first) {
        if(app.opt.seriesInterval && app.opt.randomizeStart){
            /*
             * sleep for rand([0,1])*sessionInterval
             * (spread out start time)
             * Use a random 32 bit integer and normalize.
             */
            uint32_t    r;

            if(I2RandomBytes(rsrc,(uint8_t*)&r,4) != 0){
                exit(1);
            }

            wake.tstamp = BWLNum64Add(wake.tstamp,
                    BWLDoubleToNum64((double)app.opt.seriesInterval*r/0xffffffff));
        }
    }
    else {
        BWLTimeStamp base = wake;

        if(app.opt.continuous || app.opt.nIntervals){
            wake.tstamp = next_start(rsrc,app.opt.seriesInterval,
                    app.opt.randomizeStart,&base.tstamp);
        }
    }

    /*
     * Check if the test should run yet...
     */
    if(!BWLGetTimeStamp(ctx,&currtime)){
        I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
        goto error_exit;
    }

    while (BWLNum64Cmp(wake.tstamp,currtime.tstamp) > 0){
        struct timespec     tspec;

        BWLNum64ToTimespec(&tspec,BWLNum64Sub(wake.tstamp,currtime.tstamp));

        /*
         * If the next period is more than 3 seconds from
         * now, say something.
         */
        if(!app.opt.quiet && (tspec.tv_sec > 3)){
            BWLError(ctx,BWLErrINFO,BWLErrUNKNOWN,
                    "%lu seconds until next testing period",
                    tspec.tv_sec);
        }

        if (nanosleep(&tspec,NULL) < 0 && errno != EINTR) {
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"nanosleep(): %M");
            goto error_exit;
        }

        if(sig_check()){
            exit_val = 1;
            goto error_exit;
        }

        if(!BWLGetTimeStamp(ctx,&currtime)){
            I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
            goto error_exit;
        }
    }

    is_first = False;

    return True;

error_exit:
    return False;
}

static BWLBoolean 
start_testing(ipsess_t server_sess, ipsess_t client_sess)
{
    uint16_t dataport;

    /* Start server */
    if(BWLStartSession(server_sess->cntrl,&dataport) < BWLErrINFO){
        I2ErrLog(eh,"BWLStartSessions: Failed");
        goto error_exit;
    }
    if(sig_check()){
        exit_val = 1;
        goto error_exit;
    }

    /* Start client */
    if(BWLStartSession(client_sess->cntrl,&dataport) < BWLErrINFO){
        I2ErrLog(eh,"BWLStartSessions: Failed");
        goto error_exit;
    }
    if(sig_check()){
        exit_val = 1;
        goto error_exit;
    }

    return True;

error_exit:
    return False;
}

static BWLBoolean 
wait_for_results()
{
    struct timeval      reltime;
    BWLNum64            endtime;
    BWLTimeStamp        currtime;
    BWLAcceptType       atype;
    BWLErrSeverity      err_ret;

    endtime = app.client_sess->tspec.req_time.tstamp;
    endtime = BWLNum64Add(endtime,
            BWLULongToNum64(app.client_sess->tspec.duration));
    endtime = BWLNum64Add(endtime,
            BWLULongToNum64(app.client_sess->tspec.omit));
    endtime = BWLNum64Add(endtime,fuzz64);

    /*
     *     WaitForStopSessions
     */
    if(!BWLGetTimeStamp(ctx,&currtime)){
        I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
        goto error_exit;
    }

    BWLNum64ToTimeval(&reltime,
            BWLNum64Sub(endtime,currtime.tstamp));
    if(!app.opt.quiet){
        BWLError(ctx,BWLErrINFO,BWLErrUNKNOWN,
                "%lu seconds until test results available",
                reltime.tv_sec);
    }

    while(1){
        int      rc;
        fd_set   readfds,exceptfds;

        FD_ZERO(&readfds);
        FD_SET(app.client_sess->sockfd,&readfds);
        FD_SET(app.server_sess->sockfd,&readfds);
        exceptfds = readfds;

        /*
         * Wait until endtime, or until one of the sockets
         * is readable.
         */
        rc = select(MAX(app.client_sess->sockfd,app.server_sess->sockfd)+1,
                &readfds,NULL,&exceptfds,&reltime);

        if(!BWLGetTimeStamp(ctx,&currtime)){
            I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
            goto error_exit;
        }

        BWLNum64ToTimeval(&reltime,
                BWLNum64Sub(endtime,currtime.tstamp));

        if(sig_check()){
            exit_val = 1;
            goto error_exit;
        }

        if(rc > 0 || BWLNum64Cmp(currtime.tstamp, endtime) >= 0){
            /*
             * Either One of the sockets is readable. (Any i/o on either of
             * these sockets indicates it is time to terminate the test.) Or
             * we've run out of time.
             */
            break;
        }
    }

    /*
     * Send TerminateSession
     */

    atype = BWL_CNTRL_ACCEPT;

    if( (err_ret =BWLEndSession(app.client_sess->cntrl,
                    &ip_intr,&atype,app.client_sess->results_fp))
            < BWLErrWARNING){
        goto error_exit;
    }

    if(atype != BWL_CNTRL_ACCEPT && app.client_sess->results_fp){
        fprintf(app.client_sess->results_fp,"bwctl: Session ended abnormally\n");
    }

    app.client_sess->session_requested = False;

    if(sig_check()){
        exit_val = 1;
        goto error_exit;
    }

    atype = BWL_CNTRL_ACCEPT;

    if( (err_ret =BWLEndSession(app.server_sess->cntrl,
                    &ip_intr,&atype,app.server_sess->results_fp))
            < BWLErrWARNING){
        goto error_exit;
    }

    if(atype != BWL_CNTRL_ACCEPT && app.server_sess->results_fp){
        fprintf(app.server_sess->results_fp,"bwctl: Session ended abnormally\n");
    }

    app.server_sess->session_requested = False;

    return True;

error_exit:
    return False;
}

static BWLBoolean 
setup_results_storage(ipsess_t sess)
{
    BWLTestSideData test_results_side = BWLToolGetResultsSideByID(ctx, sess->tspec.tool_id, &(sess->tspec));

    if (app.opt.bidirectional_results ||
        (test_results_side == BWL_DATA_ON_CLIENT && sess->is_client) ||
        (test_results_side == BWL_DATA_ON_SERVER && !sess->is_client)) {

       if(app.opt.printfiles){
            char dirpath[PATH_MAX];
            uint32_t file_offset,ext_offset;

            strcpy(dirpath,app.opt.savedir);
            strcat(dirpath,BWL_PATH_SEPARATOR);

            file_offset = strlen(dirpath);
            ext_offset = file_offset + BWL_TSTAMPCHARS;

            strcpy(sess->results_fname,dirpath);
            sprintf(&sess->results_fname[file_offset],BWL_TSTAMPFMT,
                    sess->tspec.req_time.tstamp);

            if(sess->is_receiver) {
                sprintf(&sess->results_fname[ext_offset],"%s%s",
                        RECV_EXT,BWL_FILE_EXT);
            }
            else {
                sprintf(&sess->results_fname[ext_offset],"%s%s",
                        SEND_EXT,BWL_FILE_EXT);
            }

            if(!(sess->results_fp = fopen(sess->results_fname,"w"))){
                I2ErrLog(eh,"Unable to write to %s %M",
                        sess->results_fname);
                goto error_exit;
            }
        }
        else {
            if(!(sess->results_fp = tmpfile())){
                I2ErrLog(eh,"Unable to create temporary file");
                goto error_exit;
            }
        }
    }

    return True;

error_exit:
    return False;
}

static BWLBoolean 
display_results(ipsess_t sess)
{
    if (sess->results_fp) {
        if(app.opt.printfiles){
            fflush(sess->results_fp);
            fclose(sess->results_fp);
            fprintf(stdout,"%s\n",sess->results_fname);
            fflush(stdout);
        }
        else {
            char tmpbuf[1024];
            int n;

            if (sess->is_receiver) {
                fprintf(stdout,"\nRECEIVER START\n");
            }
            else {
                fprintf(stdout,"\nSENDER START\n");
            }

            fseek(sess->results_fp, SEEK_SET, 0);
            while((n = fread(tmpbuf, 1, sizeof(tmpbuf), sess->results_fp)) > 0) {
                fwrite(tmpbuf, n, 1, stdout);
            }

            if (sess->is_receiver) {
                fprintf(stdout,"\nRECEIVER END\n");
            }
            else {
                fprintf(stdout,"\nSENDER END\n");
            }
        }

        sess->results_fp = NULL;
        sess->results_fname[0] = '\0';
    }

    return True;

error_exit:
    return False;
}
