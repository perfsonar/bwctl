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

/*
 * The bwctl context
 */
static    ipapp_trec    app;
static    char          *progname;
static    BWLTestType   test_type;
static    I2ErrHandle   eh;
static    uint32_t      file_offset,ext_offset;
static    int           ip_intr = 0;
static    int           ip_chld = 0;
static    int           ip_reset = 0;
static    int           ip_exit = 0;
static    int           ip_error = SIGCONT;
static    BWLContext    ctx;
static    int           first_set = False;
static    int           second_set = False;
static    ipsess_trec   first;
static    ipsess_trec   second;
static    aeskey_auth   current_auth=NULL;
static    BWLNum64      zero64;
static    BWLNum64      fuzz64;
static    BWLSID        sid;
static    uint16_t      recv_port;
static    ipsess_t      sess[2];    /* server == 0, client == 1 */
static    BWLBoolean    fake_daemon = False;
static    pid_t         fake_pid = -1;
static    int           fake_fd = -1;

static void
print_conn_args(
        void
        )
{
    fprintf(stderr,"              [Connection Args]\n\n"
            "  -4             Use IPv4 only\n"
            "  -6             Use IPv6 only\n"
            "  -A authmode [AUTHMETHOD [AUTHOPTS]]\n"
            "            authmodes:\n"
            "                 [A]uthenticated, [E]ncrypted, [O]pen\n"
            "            AUTHMETHODS:\n"
            "                 AESKEY userid [keyfile]\n"
            "  -B srcaddr     use this as a local address for control connection and tests\n"
            "  -k             deprecated\n"
            "  -U             deprecated\n"
           );
}

static void
print_test_args(
        )
{
    uint32_t    i,n;

    fprintf(stderr,
            "            [Test Args]\n\n");
    fprintf(stderr,
            "  -c recvhost [AUTHMETHOD [AUTHOPTS]]\n"
            "                 recvhost will run thrulay/nuttcp/iperf server \n"
            "            AUTHMETHODS: (See -A argument)\n"
            "\n",
            "  -s sendhost [AUTHMETHOD [AUTHOPTS]]\n"
            "                 sendhost will run thrulay/nuttcp/iperf client \n"
            "            AUTHMETHODS: (See -A argument)\n"
            "             [MUST SPECIFY AT LEAST ONE OF -c/-s]\n"
           );

    fprintf(stderr,
	        "  -T tool        tool one of:\n");
    for(i=0,n = BWLToolGetNumTools(ctx);i<n;i++){
        if (BWLToolGetTestTypesByIndex(ctx, i) != test_type)
            continue;

        fprintf(stderr,
                "                     %s\n",BWLToolGetNameByIndex(ctx,i));
    }

    fprintf(stderr,"\n"
            "  -o             Have the receiver connect to the sender (default: False)\n"
           );

    if (test_type == BWL_TEST_PING) {
    fprintf(stderr,"\n"
            "  -N count       number of packets to send (Default: 10)\n"
            "  -l len         length of the packets (bytes)\n"
            "  -t ttl         TTL for the packets\n"
           );
    }
    else if (test_type == BWL_TEST_TRACEROUTE) {
    fprintf(stderr,"\n"
            "  -F first_ttl   minimum TTL for traceroute\n"
            "  -M max_ttl     maximum TTL for traceroute\n"
            "  -l len         length of the packets (bytes)\n"
            "  -t time        maximum seconds for traceroute to finish (Default: 10)\n"
           );
    }
    else {
    fprintf(stderr,"\n"
            "  -a offset      allow unsync'd clock - claim good within offset (seconds)\n"
            "  -b bandwidth   bandwidth to use for UDP test (bits/sec KM) (Default: 1Mb)\n"
            "  -i interval    report interval (seconds)\n"
            "  -l len         length of read/write buffers (bytes)\n"
            "  -O interval    omit time (currently only for iperf3)\n"
            "  -P nThreads    number of concurrent connections\n"
            "  -D DSCP        RFC 2474 style DSCP value for TOS byte\n"
            "  -S TOS         type-of-service for outgoing packets\n"
            "  -t time        duration of test (seconds) (Default: 10)\n"
            "  -u             UDP test\n"
            "  -w window      TCP window size (bytes) 0 indicates system defaults\n"
            "  -W window      Dynamic TCP window size: value used as fallback (bytes)\n"
           );
    }
}

static void
print_output_args(
        void
        )
{
    fprintf(stderr,
            "              [Output Args]\n\n"
            "  -d dir         directory to save session files in (only if -p)\n"
            "  -e facility    syslog facility to log to\n"
            "  -f units       units type to use (Default: tool specific)\n"
            "  -h             print this message and exit\n"
           );
    fprintf(stderr,
            "  -I Interval    time between BWL test sessions(seconds)\n"
            "  -L LatestDelay latest time into an interval to run test(seconds)\n"
            "  -n nIntervals  number of tests to perform (default: continuous)\n"
            "  -p             print completed filenames to stdout - not session data\n"
           );
    fprintf(stderr,
            "  -q             silent mode\n"
            "  -r             send syslog to stderr\n"
            "  -R alpha       randomize the start time within this alpha(0-50%%)\n"
            "                  (Initial start randomized within the complete interval.)\n"
           );
    fprintf(stderr,
            "                  (default: 10 - start time randomization is 10%)\n"
            "  -v             verbose output to syslog - add 'v's to increase verbosity\n"
            "  -V             print version and exit\n"
            "  -x             output both sender and receiver session results\n"
            "  -y outfmt      output format to use (Default: tool specific)\n"
           );
}

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
    if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
    fprintf(stderr,"usage: %s %s\n", progname, "[arguments]");
    fprintf(stderr, "\n");
    print_conn_args();

    fprintf(stderr, "\n");
    print_test_args();

    fprintf(stderr, "\n");
    print_output_args();

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
    struct itimerval    itval;

    /* TODO: Handle clearing other state. Canceling tests nicely? */

    if(first.cntrl){
        BWLControlClose(first.cntrl);
        first.cntrl = NULL;
        first.sockfd = 0;
        first.tspec.req_time.tstamp = zero64;
    }

    if(second.cntrl){
        BWLControlClose(second.cntrl);
        second.cntrl = NULL;
        second.sockfd = 0;
        second.tspec.req_time.tstamp = zero64;
        if(fake_daemon){
            if(fake_fd > -1){
                while((close(fake_fd) < 0) &&
                        (errno == EINTR));
                fake_fd = -1;
            }
            if(fake_pid > 0){
                int     status = 0;
                pid_t   rc;
                int     killed=0;

                /*
                 * Attempt to let the spawned daemon complete on
                 * it's own by waiting 1 seconds before killing it.
                 */
time_wait:
                ip_intr=0;
                ip_chld=0;
                memset(&itval,0,sizeof(itval));
                itval.it_value.tv_sec = 1;
                if(setitimer(ITIMER_REAL,&itval,NULL) != 0){
                    I2ErrLog(eh,"setitimer(): %M");
                    exit(-1);
                }

again:
                rc = waitpid(fake_pid,&status,0);
                if(fake_pid != rc){
                    if(errno == EINTR){
                        /*
                         * If the timer went off, then kill the
                         * child process.
                         */
                        if(ip_intr && !killed){
                            (void)kill(fake_pid,SIGTERM);
                            killed=1;
                            goto time_wait;
                        }
                        goto again;
                    }
                    I2ErrLog(eh,"waitpid() returned %d: %M",
                            rc);
                    exit(-1);
                }
                fake_pid = -1;
            }
            fake_daemon = False;
        }
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
        exit(1);
    }

    if(ip_exit || ip_reset){
        CloseSessions();
    }

    if(ip_exit){
        I2ErrLog(eh,"SIGTERM/SIGINT: Exiting.");
        exit(0);
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

static BWLControl
SpawnLocalServer(
        BWLContext          lctx,
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

        fake_fd = new_pipe[0];
        fake_pid = pid;
        return cntrl;
    }

    /* Now implement child "server" */
    if(ip_exit){
        I2ErrLog(eh,"Child exiting from signal");
        _exit(0);
    }

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
handle_conn_arg(const char arg, const char *value, char **argv, int argc) {
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
                I2ErrLog(eh,"invalid default authentication");
                exit(1);
            }
            break;
        case 'B':
            if (!(app.opt.srcaddr = strdup(optarg))) {
                I2ErrLog(eh,"malloc:%M");
                exit(1);
            }
            break;

        default:
            handled = False;
    }

    return handled;
}

static BWLBoolean
handle_output_arg(const char arg, const char *value) {
    BWLBoolean handled = True;

    switch (arg) {
        case 'd':
            if (!(app.opt.savedir = strdup(optarg))) {
                I2ErrLog(eh,"malloc:%M");
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
handle_misc_arg(const char arg, const char *value) {
    BWLBoolean handled = True;

    switch (arg) {
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
handle_scheduling_arg(const char arg, const char *value) {
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
handle_generic_test_arg(const char arg, const char *value, char **argv, int argc) {
    BWLBoolean handled = True;

    switch (arg) {
        case 'c':
            if(app.receiver_sess){
                usage("-c flag can only be specified once");
                exit(1);
            }
            if(!first_set){
                first_set = True;
                app.receiver_sess = &first;
            }else{
                second_set = True;
                app.receiver_sess = &second;
            }
            app.receiver_sess->host = optarg;

            if(parse_auth_args(eh,argv,argc,optarg,&app.receiver_sess->auth)
                    != 0){
                I2ErrLog(eh,
                        "invalid \'receiver\' authentication");
                exit(1);
            }
            break;
        case 's':
            if(app.sender_sess){
                usage("-s flag can only be specified once");
                exit(1);
            }
            if(!first_set){
                first_set = True;
                app.sender_sess = &first;
            }else{
                second_set = True;
                app.sender_sess = &second;
            }
            app.sender_sess->host = optarg;

            if(parse_auth_args(eh,argv,argc,optarg,&app.sender_sess->auth)
                    != 0){
                I2ErrLog(eh,
                        "invalid \'sender\' authentication");
                exit(1);
            }
            break;

        case 'o':
            app.opt.flip_direction = True;
            break;

        case 'T':
            if( (app.opt.tool_id = BWLToolGetID(ctx,optarg)) ==
                    BWL_TOOL_UNDEFINED){
                char    buf[BWL_MAX_TOOLNAME + 20];
                snprintf(buf,sizeof(buf)-1,"Invalid tool (-T): %s",optarg);
                usage(buf);
                exit(1);
            }
            break;

        default:
            handled = False;
    }

    return handled;
}

static BWLBoolean
handle_throughput_test_arg(const char arg, const char *value) {
    BWLBoolean handled = True;
    char *tstr;

    switch (arg) {
        case 'y':
            if(strlen(optarg) != 1){
                usage("Invalid value. (-y) Single character expected");
                exit(1);
            }
            app.opt.outformat = optarg[0];
            break;

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
handle_ping_test_arg(const char arg, const char *value) {
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
        default:
            handled = False;
    }
    return handled;
}

static BWLBoolean
handle_traceroute_test_arg(const char arg, const char *value) {
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

int
main(
        int    argc,
        char    **argv
    )
{
    int                 lockfd;
    char                lockpath[PATH_MAX];
    int                 rc;
    BWLErrSeverity      err_ret = BWLErrOK;
    I2ErrLogSyslogAttr  syslogattr;

    int                 fname_len;
    int                 ch;
    char                *tstr = NULL;
    char                optstring[128];
    static char         *conn_opts = "46a:AB:";
    static char         *misc_opts = "hV?";
    static char         *out_opts = "d:e:f:I:L:n:pqrR:vxy:";
    static char         *generic_test_opts = "c:s:T:o";
    static char         *throughput_test_opts = "b:D:i:l:O:P:S:t:uw:W:";
    static char         *ping_test_opts = "N:l:t:";
    static char         *traceroute_test_opts = "F:M:l:t:";
    static char         *posixly_correct="POSIXLY_CORRECT=True";

    char                dirpath[PATH_MAX];
    struct flock        flk;
    BWLNum64            latest64;
    uint32_t           p,q;
    I2RandomSource      rsrc;
    BWLTimeStamp        wake;
    BWLTimeStamp        base;
    struct sigaction    act;
    sigset_t            sigs;
    int                 exit_val=0;
    double              syncfuzz;
    BWLTestSideData     test_results_side;

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
        test_type = BWL_TEST_PING;
    }
    else if (strcmp(progname, "bwtraceroute") == 0) {
        test_type = BWL_TEST_TRACEROUTE;
    }
    else {
        test_type = BWL_TEST_THROUGHPUT;
    }

    /* Create options strings for this program. */
    strcpy(optstring, conn_opts);
    strcat(optstring, generic_test_opts);
    if (test_type == BWL_TEST_THROUGHPUT) {
        strcat(optstring, throughput_test_opts);
    }
    else if (test_type == BWL_TEST_TRACEROUTE) {
        strcat(optstring, traceroute_test_opts);
    }
    else if (test_type == BWL_TEST_PING) {
        strcat(optstring, ping_test_opts);
    }
    strcat(optstring, out_opts);
    strcat(optstring, misc_opts);


    syslogattr.ident = progname;
    syslogattr.logopt = 0;
    syslogattr.facility = LOG_USER;
    syslogattr.priority = LOG_ERR;
    syslogattr.line_info = I2MSG;

    /* Set default options. */
    memset(&app,0,sizeof(app));
    app.opt.timeDuration = 10;
    app.opt.randomizeStart = 10;

    memset(&first,0,sizeof(first));
    memset(&second,0,sizeof(second));

    /*
     * Fix getopt if the brain-dead GNU version is being used.
     */
    if(putenv(posixly_correct) != 0){
        fprintf(stderr,"Unable to set POSIXLY_CORRECT getopt mode");
        exit(1);
    }

    opterr = 0;
    while((ch = getopt(argc, argv, optstring)) != -1){
        int fac;
        switch (ch) {
            case 'e':
                if((fac = I2ErrLogSyslogFacility(optarg)) == -1){
                    fprintf(stderr,
                            "Invalid -e: Syslog facility \"%s\" unknown\n",
                            optarg);
                    exit(1);
                }
                syslogattr.facility = fac;
                break;
            case 'v':
                app.opt.verbose++;
                /* fallthrough */
            case 'r':
                syslogattr.logopt |= LOG_PERROR;
                break;
            case 'q':
                app.opt.quiet = True;
                break;
            default:
                break;
        }
    }
    opterr = optreset = optind = 1;

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
     * Start an error logging session for reporing errors to the
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
        I2ErrLog(eh, "Unable to initialize BWL library.");
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

    while ((ch = getopt(argc, argv, optstring)) != -1){
        if (handle_conn_arg(ch, optarg, argv, argc))
            continue;

        if (handle_output_arg(ch, optarg))
            continue;

        if (handle_misc_arg(ch, optarg))
            continue;

        if (handle_scheduling_arg(ch, optarg))
            continue;

        if (handle_generic_test_arg(ch, optarg, argv, argc))
            continue;

        if (test_type == BWL_TEST_THROUGHPUT) {
            if (handle_throughput_test_arg(ch, optarg))
                continue;
        }
        else if (test_type == BWL_TEST_TRACEROUTE) {
            if (handle_traceroute_test_arg(ch, optarg))
                continue;
        }
        else if (test_type == BWL_TEST_PING) {
            if (handle_ping_test_arg(ch, optarg))
                continue;
        }
        
        /* handled in prior getopt call... */
        if (ch == 'e' || ch == 'r' || ch == 'v' || ch == 'q')
            continue;

        usage("");
        exit(0);
    }
    argc -= optind;
    argv += optind;

    if(argc != 0){
        usage("");
        exit(1);
    }

    if(!app.receiver_sess && !app.sender_sess){
        usage("At least one of -s or -c must be specified.");
        exit(1);
    }
    if(!app.receiver_sess){
        app.receiver_sess = (app.sender_sess == &first)?&second:&first;
    }
    if(!app.sender_sess){
        app.sender_sess = (app.receiver_sess == &first)?&second:&first;
    }
    if (app.opt.flip_direction) {
        app.receiver_sess->is_client = True;
    }
    else {
        app.sender_sess->is_client = True;
    }

    if(!second_set && !(second.host = strdup("localhost"))){
        I2ErrLog(eh,"malloc:%M");
        exit(1);
    }

    /*
     * -4/-6 sanity check
     */
    if(app.opt.v4only && app.opt.v6only){
        I2ErrLog(eh,"-4 and -6 flags cannot be set together.");
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
    file_offset = strlen(dirpath);
    ext_offset = file_offset + BWL_TSTAMPCHARS;

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
    else if (test_type == BWL_TEST_PING) {
        if(!app.opt.ping_packet_count){
            app.opt.ping_packet_count = 10;
        }

        if(!app.opt.ping_interpacket_time){
            app.opt.ping_interpacket_time = 1000;
        }

        app.opt.timeDuration = app.opt.ping_packet_count * (app.opt.ping_interpacket_time / 1000.0) + 1;
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

        if(app.opt.bandWidth && !app.opt.udpTest){
            usage("-b: only valid with -u");
            exit(1);
        }
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

        if( !(rsrc = I2RandomSourceInit(eh,I2RAND_DEV,NULL))){
            I2ErrLog(eh,"Failed to initialize Random Numbers");
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
    latest64 = BWLULongToNum64(app.opt.seriesWindow);

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
        first.tspec.tool_id = second.tspec.tool_id = app.opt.tool_id;
    }
    else{
        first.tspec.tool_id = second.tspec.tool_id = BWL_TOOL_UNDEFINED;
    }
    first.tspec.verbose = app.opt.verbose > 0 ? 1 : 0;

    first.tspec.duration = app.opt.timeDuration;

    if (app.opt.flip_direction) {
        first.tspec.server_sends = True;
    }

    if (test_type == BWL_TEST_TRACEROUTE) {
        first.tspec.traceroute_udp = app.opt.traceroute_udp;
        first.tspec.traceroute_packet_size = app.opt.traceroute_packet_size;
        first.tspec.traceroute_first_ttl = app.opt.traceroute_first_ttl;
        first.tspec.traceroute_last_ttl = app.opt.traceroute_last_ttl;
    }
    else if (test_type == BWL_TEST_PING) {
        first.tspec.ping_packet_count = app.opt.ping_packet_count;
        first.tspec.ping_packet_size = app.opt.ping_packet_size;
        first.tspec.ping_packet_ttl = app.opt.ping_packet_ttl;
        first.tspec.ping_interpacket_time = app.opt.ping_interpacket_time;
    }
    else {
        first.tspec.udp = app.opt.udpTest;
        first.tspec.tos = app.opt.tos;
        if(first.tspec.udp){
            first.tspec.bandwidth = app.opt.bandWidth;
        }
        first.tspec.window_size = (uint32_t)app.opt.windowSize;
        if(app.opt.windowSize != (I2numT)first.tspec.window_size){
            first.tspec.window_size = (uint32_t)~0;
            I2ErrLog(eh,"Requested -w/-W option (%llu) too large: max supported size: (%llu)",app.opt.windowSize,first.tspec.window_size);
            exit(1);
        }
        first.tspec.dynamic_window_size = app.opt.dynamicWindowSize;
        first.tspec.len_buffer = (uint32_t)app.opt.lenBuffer;
        if(app.opt.lenBuffer != (I2numT)first.tspec.len_buffer){
            first.tspec.len_buffer = (uint32_t)~0;
            I2ErrLog(eh,"Requested -l option (%llu) too large: max supported size: (%llu)",app.opt.lenBuffer,first.tspec.len_buffer);
            exit(1);
        }
        first.tspec.report_interval = app.opt.reportInterval;
        first.tspec.units = app.opt.units;
        first.tspec.outformat = app.opt.outformat;
        first.tspec.omit = app.opt.timeOmit;
        first.tspec.parallel_streams = app.opt.parallel;
    }

     /*
     * copy first tspec to second record.
     */
    memcpy(&second.tspec,&first.tspec,sizeof(first.tspec));

    /* sess[0] == server, sess[1] == client */
    if (app.opt.flip_direction) {
        sess[0] = app.sender_sess;
        sess[1] = app.receiver_sess;
    }
    else {
        sess[0] = app.receiver_sess;
        sess[1] = app.sender_sess;
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

    /*
     * Initialize wake time to current time. If this is a single test,
     * this will indicate an immediate test. If seriesInterval is set,
     * this time will be adjusted to spread start times out.
     */
    if(!BWLGetTimeStamp(ctx,&wake)){
        I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
        exit(1);
    }

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
    base = wake;

    do{
        BWLTimeStamp        req_time;
        BWLTimeStamp        currtime;
        BWLNum64            endtime;
        BWLNum64            rel;
        uint16_t            dataport;
        BWLBoolean          stop;
        char                recvfname[PATH_MAX];
        char                sendfname[PATH_MAX];
        FILE                *servfp = NULL;
        FILE                *clientfp = NULL;
        struct timespec     tspec;
	    BWLToolAvailability common_tools;

AGAIN:
        if(sig_check()){
            exit_val = 1;
            goto finish;
        }

        /*
         * Get current time.
         */
        if(!BWLGetTimeStamp(ctx,&currtime)){
            I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
            exit_val = 1;
            goto finish;
        }

        /*
         * Check if the test should run yet...
         */
        if(BWLNum64Cmp(wake.tstamp,currtime.tstamp) > 0){

            rel = BWLNum64Sub(wake.tstamp,currtime.tstamp);
            BWLNum64ToTimespec(&tspec,rel);

            /*
             * If the next period is more than 3 seconds from
             * now, say something.
             */
            if(!app.opt.quiet && (tspec.tv_sec > 3)){
                BWLError(ctx,BWLErrINFO,BWLErrUNKNOWN,
                        "%lu seconds until next testing period",
                        tspec.tv_sec);
            }

            if((nanosleep(&tspec,NULL) == 0) || (errno == EINTR)){
                goto AGAIN;
            }

            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"nanosleep(): %M");
            exit_val = 1;
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

        /* Open first (definitely remote) connection */
        if(!first.cntrl){
            /*
             * pick auth to use
             */
            current_auth = ((first.auth)?first.auth:app.def_auth);
            first.cntrl = BWLControlOpen(ctx,
                    I2AddrByNode(eh,app.opt.srcaddr),
                    I2AddrByNode(eh,first.host),
                    ((current_auth)?
                     current_auth->auth_mode:BWL_MODE_OPEN),
                    ((current_auth)?
                     current_auth->identity:NULL),
                    NULL,&first.avail_tools,&err_ret);
            if(sig_check()){
                exit_val = 1;
                goto finish;
            }

            /* TODO: deal with temporary failures? */
            if(!first.cntrl){
                I2ErrLog(eh,"Unable to connect to %s",first.host);
                goto next_test;
            }

            /*
             * Get sockfd for later 'select' usage
             */
            first.sockfd = BWLControlFD(first.cntrl);

            if (second_set){
                /*
                 * When doing a third-party connection, the hostname needs to
                 * be passed to the underlying functions, not the IP address.
                 */
                if(first.is_client){
                    first.tspec.client = second.tspec.client =
                        I2AddrByNode(eh, first.host);
                }
                else{
                    first.tspec.server = second.tspec.server =
                        I2AddrByNode(eh, first.host);
                }
            }
            else {
                /*
                 * Need to get a clean I2Addr that is basically a copy of
                 * the control connection (but unconnected).
                 */
                if(first.is_client){
                    first.tspec.client = second.tspec.client =
                        BWLAddrByControl(first.cntrl);
                }
                else{
                    first.tspec.server = second.tspec.server =
                        BWLAddrByControl(first.cntrl);
                }
            }
        }

        /* Open second connection */
        if(!second.cntrl){
            /*
             * If second host specified, contact it.
             *
             * If second host not specified, attempt to
             * contact localhost server. If can, then
             * use it. If not, and if "client_test"
             * option is set, then fork of a client tool.
             */
            current_auth = ((second.auth)?second.auth:app.def_auth);
            fake_daemon = False;
            if(second_set){
                /*
                 * If second host is specified, a bwctld
                 * process is required.
                 */
                second.cntrl = BWLControlOpen(ctx,
                        I2AddrByNode(eh,app.opt.srcaddr),
                        I2AddrByNode(eh,second.host),
                        ((current_auth)?
                         current_auth->auth_mode:
                         BWL_MODE_OPEN),
                        ((current_auth)?
                         current_auth->identity:NULL),
                        NULL,&second.avail_tools,&err_ret);
            }else{
                /*
                 * Try "localhost" server.
                 */
                I2Addr laddr = BWLAddrByLocalControl(first.cntrl);
                if(!I2AddrSetPort(laddr,(uint16_t)BWL_CONTROL_SERVICE_NUMBER)){
                    if(laddr) I2AddrFree(laddr);
                    I2ErrLog(eh,"Unable to determine address for local server");
                    exit_val = 1;
                    goto finish;
                }

                second.cntrl = BWLControlOpen(ctx,NULL,laddr,
                        ((current_auth)?current_auth->auth_mode:BWL_MODE_OPEN),
                        ((current_auth)?current_auth->identity:NULL),
                        NULL,&second.avail_tools,&err_ret);
                if(!second.cntrl && (errno==ECONNREFUSED)){
                    /*
                     * No local daemon - spawn something.
                     */
                    I2ErrLog(eh,
                            "Unable to contact a local bwctld: Spawning local tool controller");

                    if( !(second.cntrl =
                                SpawnLocalServer(ctx,&second.avail_tools))){
                        I2ErrLog(eh,"Unable to spawn local tool controller");
                    }
                    fake_daemon = True;
                }
            }

            /* TODO: deal with temporary failures */
            if(sig_check()){
                exit_val = 1;
                goto finish;
            }
            if(!second.cntrl){
                I2ErrLog(eh,"Unable to connect to %s",second.host);
                goto next_test;
            }

            /*
             * Get sockfd for later 'select' usage
             */
            second.sockfd = BWLControlFD(second.cntrl);

            if(fake_daemon){
                if(second.is_client){
                    first.tspec.client = second.tspec.client =
                        BWLAddrByLocalControl(first.cntrl);
                }
                else{
                    first.tspec.server = second.tspec.server =
                        BWLAddrByLocalControl(first.cntrl);
                }
            }
            else if (second_set){
                if(second.is_client){
                    first.tspec.client = second.tspec.client =
                        I2AddrByNode(eh, second.host);
                }
                else{
                    first.tspec.server = second.tspec.server =
                        I2AddrByNode(eh, second.host);
                }
            }
            else {
                if(second.is_client){
                    first.tspec.client = second.tspec.client =
                        BWLAddrByControl(second.cntrl);
                }
                else{
                    first.tspec.server = second.tspec.server =
                        BWLAddrByControl(second.cntrl);
                }
            }
        }

        if (!fake_daemon) {
            if (I2AddrIsLoopback(BWLControlRemoteAddr(first.cntrl)) && !I2AddrIsLoopback(BWLControlRemoteAddr(second.cntrl))) {
                char        buf[NI_MAXHOST+1];
                size_t      buflen = sizeof(buf);
                I2Addr new_addr = BWLAddrByLocalControl(second.cntrl);

                if (first.is_client) {
                    I2AddrFree(first.tspec.client);
                    first.tspec.client = second.tspec.client = new_addr;
                }
                else{
                    I2AddrFree(first.tspec.server);
                    first.tspec.server = second.tspec.server = new_addr;
                }

                I2ErrLog(eh,"Hostname '%s' resolves to a loopback address, using %s.", first.host, I2AddrNodeName(new_addr,buf,&buflen));
            }
            else if (!I2AddrIsLoopback(BWLControlRemoteAddr(first.cntrl)) && I2AddrIsLoopback(BWLControlRemoteAddr(second.cntrl))) {
                char        buf[NI_MAXHOST+1];
                size_t      buflen = sizeof(buf);
                I2Addr new_addr = BWLAddrByLocalControl(first.cntrl);

                if (second.is_client) {
                    I2AddrFree(first.tspec.client);
                     first.tspec.client = second.tspec.client = new_addr;
                }
                else{
                    I2AddrFree(first.tspec.server);
                    first.tspec.server = second.tspec.server = new_addr;
                }

                I2ErrLog(eh,"Hostname '%s' resolves to a loopback address, using %s.", second.host, I2AddrNodeName(new_addr,buf,&buflen));
            }
        }

        if(!first.tspec.client){
            I2ErrLog(eh,"Unable to determine client address: %M");
            exit_val = 1;
            goto finish;
        }
        if(!first.tspec.server){
            I2ErrLog(eh,"Unable to determine recv address: %M");
            exit_val = 1;
            goto finish;
        }

        /* Pick tool */

        /* Check if the requested tool is available at both servers. */
        common_tools = first.avail_tools & second.avail_tools;
        if(!common_tools){
            I2ErrLog(eh,"No tools in common");
            exit_val = 1;
            goto finish;
        }

        if ( first.tspec.tool_id == BWL_TOOL_UNDEFINED ) {
            uint32_t tid;
            const char *req_name;

            /* Pick the first common tool to use. */
            tid = 1;
            for ( tid = 1; ; tid <<= 1 ) {
                if (BWLToolGetTestTypesByID(ctx, tid) != test_type)
                    continue;

                if ( tid & common_tools )
                    break;
            }
            first.tspec.tool_id = tid;
            second.tspec.tool_id = tid;
            req_name = BWLToolGetNameByID( ctx, first.tspec.tool_id );
            I2ErrLog( eh, "Using tool: %s", req_name );
        } else if ( ! ( first.tspec.tool_id & common_tools ) ) {
            char unknown[BWL_MAX_TOOLNAME];
            const char *req_name;

            req_name = BWLToolGetNameByID( ctx, first.tspec.tool_id );
            if ( ! req_name ) {
                sprintf( unknown, "unknown(id=%x)", first.tspec.tool_id );
                req_name = unknown;
            }
            I2ErrLog( eh, "Requested tool \"%s\" not supported by both servers. See the \'-T\' option", req_name );
            I2ErrLog( eh, "Available in-common: %s", BWLToolGetToolNames( ctx, common_tools ) );
            exit_val = 1;
            goto finish;
        }

        /*
         * Query first time error and update round-trip bound.
         * The time will be over-written later, we really only
         * care about the errest portion of the timestamp. The
         * error estimate is used to hold the "fuzz" time around
         * when the test can start. This "fuzz" includes the NTP
         * error as well as the rtt to the "other" server.
         *
         * Using the "second" tspec to hold the error of "first"
         * because I need to pass the error estimate for the
         * "opposite" end of the test on in the request.
         */
        if(BWLControlTimeCheck(first.cntrl,&second.tspec.req_time) !=
                BWLErrOK){
            I2ErrLogP(eh,errno,"BWLControlTimeCheck: %M");
            CloseSessions();
            goto next_test;
        }
        if(sig_check()){
            exit_val = 1;
            goto finish;
        }
        first.rttbound = BWLGetRTTBound(first.cntrl);
        rel = BWLNum64Add(first.rttbound,
                BWLGetTimeStampError(&second.tspec.req_time));
        BWLSetTimeStampError(&second.tspec.req_time,rel);

        /*
         * Query second time error and update round-trip bound.
         * The time will be over-written later, we really only
         * care about the errest portion of the timestamp. The
         * error estimate is used to hold the "fuzz" time around
         * when the test can start. This "fuzz" includes the NTP
         * error as well as the rtt to the "other" server.
         *
         * Using the "first" tspec to hold the error of "second"
         * because I need to pass the error estimate for the
         * "opposite" end of the test on in the request.
         */
        if(BWLControlTimeCheck(second.cntrl,&first.tspec.req_time) !=
                BWLErrOK){
            I2ErrLogP(eh,errno,"BWLControlTimeCheck: %M");
            CloseSessions();
            goto next_test;
        }
        if(sig_check()){
            exit_val = 1;
            goto finish;
        }
        second.rttbound = BWLGetRTTBound(second.cntrl);
        rel = BWLNum64Add(second.rttbound,
                BWLGetTimeStampError(&first.tspec.req_time));
        BWLSetTimeStampError(&first.tspec.req_time,rel);

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
        req_time.tstamp = BWLNum64Mult(
                BWLNum64Add(first.rttbound,second.rttbound),
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
        req_time.tstamp = BWLNum64Add(req_time.tstamp,BWLDoubleToNum64(.25));

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
                BWLNum64Max(first.rttbound,second.rttbound));

        /*
         * req_time currently holds a reasonable relative amount of
         * time from 'now' that a test could be held. Get the current
         * time and add to make that an 'absolute' value.
         */
        if(!BWLGetTimeStamp(ctx,&currtime)){
            I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
            exit_val = 1;
            goto finish;
        }
        req_time.tstamp = BWLNum64Add(req_time.tstamp,
                currtime.tstamp);

        /*
         * Get a reservation:
         *     s[0] == server
         *     s[1] == client
         *     initialize req_time/latest_time
         *     keep querying each server in turn until satisfied,
         *     or denied.
         */
        sess[0]->tspec.latest_time = sess[1]->tspec.latest_time =
            BWLNum64Add(req_time.tstamp, latest64);
        sess[1]->tspec.req_time.tstamp = zero64;
        memset(sid,0,sizeof(sid));
        recv_port = 0;
        if(app.opt.verbose > 1){
            I2ErrLog(eh,"CurrTime: %24.10f",
                    BWLNum64ToDouble(currtime.tstamp));
            I2ErrLog(eh,"ReqInitial: %24.10f",
                    BWLNum64ToDouble(req_time.tstamp));
            I2ErrLog(eh,"LastTime: %24.10f",
                    BWLNum64ToDouble(sess[0]->tspec.latest_time));
        }

        p=0;q=0;
        while(1){

            /*
             * p is the current connection we are talking to,
             * q is the "other" one.
             * (Logic is started so the first time through this loop
             * we are talking to the "server". That is required
             * to initialize the sid and recv_port.)
             */
            p = q++;
            q %= 2;

            sess[p]->tspec.req_time.tstamp = req_time.tstamp;

            /*
             * Make the request
             */
            if(!BWLSessionRequest(sess[p]->cntrl,sess[p]->is_client,
                        &sess[p]->tspec,&req_time,&recv_port,
                        sid,&err_ret)){
                /*
                 * Session was not accepted.
                 */

                /*
                 * If control connection is still ok...
                 */
                if(err_ret == BWLErrOK){

                    /*
                     * If server is busy, req_time will
                     * be non-zero.
                     */
                    if(req_time.tstamp != zero64){
                        /*
                         * Request is ok, but server
                         * is too busy. Skip this test
                         * and proceed to next session
                         * interval.
                         */
                        I2ErrLog(eh,"SessionRequest: %s busy. (Try -L flag)",
                                sess[p]->host);
                    }
                    else{
                        /*
                         * Don't know why it was
                         * denied.
                         */
                        I2ErrLog(eh,"SessionRequest: Denied by %s",
                                sess[p]->host);
                    }

                    /*
                     * Reset other servers reservation if
                     * needed.
                     */
                    if(sess[q]->tspec.req_time.tstamp !=
                            zero64){
                        /*
                         * zero request time is a
                         * reservation cancellation.
                         */
                        sess[q]->tspec.req_time.tstamp =
                            zero64;
                        if(!BWLSessionRequest(
                                    sess[q]->cntrl,
                                    sess[q]->is_client,
                                    &sess[q]->tspec,
                                    &req_time,
                                    &recv_port,
                                    sid,
                                    &err_ret)){
                            goto sess_req_err;
                            CloseSessions();
                            I2ErrLog(eh,
                                    "SessionRequest Control connection failure for \'%s\'. Skipping.",
                                    sess[q]->host);
                        }
                    }
                }
                else{
sess_req_err:
                    /*
                     * Control connection failed, close
                     * it down.
                     */
                    CloseSessions();
                    I2ErrLog(eh,
                            "SessionRequest Control connection failure for \'%s\'. Skipping...",
                            sess[p]->host);
                }
                goto next_test;
            }
            if(sig_check()){
                exit_val = 1;
                goto finish;
            }
            if(app.opt.verbose > 1){
                I2ErrLog(eh,"Res(%s): %24.10f",sess[p]->host,
                        BWLNum64ToDouble(req_time.tstamp));
            }

            if(BWLNum64Cmp(req_time.tstamp,
                        sess[p]->tspec.latest_time) > 0){
                I2ErrLog(eh,
                        "SessionRequest: \'%s\' returned bad reservation time!",
                        sess[p]->host);
                CloseSessions();
                goto next_test;
            }

            /* save new time for res */
            sess[p]->tspec.req_time.tstamp = req_time.tstamp;

            /*
             * Do we have a meeting?
             */
            if(BWLNum64Cmp(sess[p]->tspec.req_time.tstamp,
                        sess[q]->tspec.req_time.tstamp) == 0){
                break;
            }
        }

        /* Start server */
        if(BWLStartSession(sess[0]->cntrl,&dataport) < BWLErrINFO){
            I2ErrLog(eh,"BWLStartSessions: Failed");
            CloseSessions();
            goto next_test;
        }
        if(sig_check()){
            exit_val = 1;
            goto finish;
        }

        /* Start client */
        if(BWLStartSession(sess[1]->cntrl,&dataport) < BWLErrINFO){
            I2ErrLog(eh,"BWLStartSessions: Failed");
            CloseSessions();
            goto next_test;
        }
        if(sig_check()){
            exit_val = 1;
            goto finish;
        }

        endtime = first.tspec.req_time.tstamp;
        endtime = BWLNum64Add(endtime,
                BWLULongToNum64(first.tspec.duration));
        endtime = BWLNum64Add(endtime,
                BWLULongToNum64(first.tspec.omit));
        endtime = BWLNum64Add(endtime,fuzz64);
        stop = False;

        test_results_side = BWLToolGetResultsSideByID(ctx, sess[0]->tspec.tool_id, &(sess[0]->tspec));

        /*
         * Setup files for the results.
         */
        if(app.opt.printfiles){
            strcpy(recvfname,dirpath);
            sprintf(&recvfname[file_offset],BWL_TSTAMPFMT,
                    first.tspec.req_time.tstamp);
            strcpy(sendfname,recvfname);

            if(test_results_side == BWL_DATA_ON_SERVER ||
               app.opt.bidirectional_results){
                sprintf(&recvfname[ext_offset],"%s%s",
                        RECV_EXT,BWL_FILE_EXT);
                if(!(servfp = fopen(recvfname,"w"))){
                    I2ErrLog(eh,"Unable to write to %s %M",
                            recvfname);
                    exit_val = 1;
                    goto finish;
                }
            }

            if(test_results_side == BWL_DATA_ON_CLIENT ||
               app.opt.bidirectional_results){
                sprintf(&sendfname[ext_offset],"%s%s",
                        SEND_EXT,BWL_FILE_EXT);
                if(!(clientfp = fopen(sendfname,"w"))){
                    I2ErrLog(eh,"Unable to write to %s %M",
                            sendfname);
                    exit_val = 1;
                    goto finish;
                }
            }
        }
        else{
            if(test_results_side == BWL_DATA_ON_SERVER ||
                app.opt.bidirectional_results){
                servfp = stdout;
            }
            if(test_results_side == BWL_DATA_ON_CLIENT ||
                app.opt.bidirectional_results){
                clientfp = stdout;
            }
        }

        /*
         *     WaitForStopSessions
         */
        if(!BWLGetTimeStamp(ctx,&currtime)){
            I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
            exit_val = 1;
            goto finish;
        }
        rel = BWLNum64Sub(endtime,currtime.tstamp);
        BWLNum64ToTimespec(&tspec,rel);
        if(!app.opt.quiet){
            BWLError(ctx,BWLErrINFO,BWLErrUNKNOWN,
                    "%lu seconds until test results available",
                    tspec.tv_sec);
        }
        while(1){
            struct timeval  reltime;
            fd_set          readfds,exceptfds;

            if(!BWLGetTimeStamp(ctx,&currtime)){
                I2ErrLogP(eh,errno,"BWLGetTimeOfDay: %M");
                exit_val = 1;
                goto finish;
            }
            if(stop || (BWLNum64Cmp(currtime.tstamp,endtime) > 0)){
                BWLAcceptType   atype;

                /*
                 * Send TerminateSession
                 */
                if(servfp == stdout){
                    if (app.opt.flip_direction) {
                        fprintf(stdout,"\nSENDER START\n");
                    }
                    else {
                        fprintf(stdout,"\nRECEIVER START\n");
                    }
                }
                atype = BWL_CNTRL_ACCEPT;
                if( (err_ret =BWLEndSession(sess[0]->cntrl,
                                &ip_intr,&atype,servfp))
                        < BWLErrWARNING){
                    CloseSessions();
                    goto next_test;
                }
                if(servfp && (atype != BWL_CNTRL_ACCEPT)){
                    fprintf(servfp,"bwctl: Session ended abnormally\n");
                }
                if(servfp == stdout){
                    if (app.opt.flip_direction) {
                        fprintf(stdout,"\nSENDER END\n");
                    }
                    else {
                        fprintf(stdout,"\nRECEIVER END\n");
                    }
                }
                else if (servfp) {
                    fclose(servfp);
                    servfp = NULL;
                    fprintf(stdout,"%s\n",recvfname);
                }
                fflush(stdout);

                if(sig_check()){
                    exit_val = 1;
                    goto finish;
                }

                /* client session */
                if(clientfp == stdout){
                    if (app.opt.flip_direction) {
                        fprintf(stdout,"\nRECEIVER START\n");
                    }
                    else {
                        fprintf(stdout,"\nSENDER START\n");
                    }
                }
                atype = BWL_CNTRL_ACCEPT;
                if( (err_ret = BWLEndSession(sess[1]->cntrl,
                                &ip_intr,&atype,clientfp))
                        < BWLErrWARNING){
                    CloseSessions();
                    goto next_test;
                }
                if(clientfp && (atype != BWL_CNTRL_ACCEPT)){
                    fprintf(clientfp,"bwctl: Session ended abnormally\n");
                }
                if(clientfp == stdout){
                    if (app.opt.flip_direction) {
                        fprintf(stdout,"\nRECEIVER END\n");
                    }
                    else {
                        fprintf(stdout,"\nSENDER END\n");
                    }
                }
                else if(clientfp){
                    fclose(clientfp);
                    clientfp = NULL;
                    fprintf(stdout,"%s\n",sendfname);
                }
                fflush(stdout);

                if(sig_check()){
                    exit_val = 1;
                    goto finish;
                }

                break;
            }

            BWLNum64ToTimeval(&reltime,
                    BWLNum64Sub(endtime,currtime.tstamp));
            FD_ZERO(&readfds);
            FD_SET(first.sockfd,&readfds);
            FD_SET(second.sockfd,&readfds);
            exceptfds = readfds;

            /*
             * Wait until endtime, or until one of the sockets
             * is readable.
             */
            rc = select(MAX(first.sockfd,second.sockfd)+1,
                    &readfds,NULL,&exceptfds,&reltime);

            if(rc > 0){
                /*
                 * One of the sockets is readable. Don't
                 * really care which one. Set stop so
                 * EndSessions happens above.
                 * (Basically, any i/o on either of these
                 * sockets indicates it is time to terminate
                 * the test.)
                 */
                stop = True;
                if(app.opt.verbose > 1){
                    if(FD_ISSET(first.sockfd,&readfds)){
                        I2ErrLogP(eh,0,
                                "Local readable!");
                    }
                    if(FD_ISSET(second.sockfd,&readfds)){
                        I2ErrLogP(eh,0,
                                "Remote readable!");
                    }
                }
            }
            if(sig_check()){
                exit_val = 1;
                goto finish;
            }
        }

        /*
         * Skip to here on failure for now. Will perhaps add
         * intermediate retries until some threshold of the
         * current period.
         */
next_test:
        if(app.opt.continuous || --app.opt.nIntervals){
            wake.tstamp = next_start(rsrc,app.opt.seriesInterval,
                    app.opt.randomizeStart,&base.tstamp);
        }

        if(sig_check()){
            exit_val = 1;
            goto finish;
        }

    }while(app.opt.continuous || app.opt.nIntervals);

finish:
    CloseSessions();

    BWLContextFree(ctx);
    ctx = NULL;

    exit(exit_val);
}
