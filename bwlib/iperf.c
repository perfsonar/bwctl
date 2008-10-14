/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id$
 */
/*
 *    File:         iperf.c
 *
 *    Author:       Jeff W. Boote
 *                  Internet2
 *
 *    Date:         Mon Sep 03 12:42:26 MDT 2007
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run an
 *    iperf throughput tool in bwctl.
 *
 *    License:
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the following copyright notice,
 *       this list of conditions and the disclaimer below.
 * 
 *        Copyright (c) 2003-2008, Internet2
 * 
 *                              All rights reserved.
 * 
 *     * Redistribution in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 *    *  Neither the name of Internet2 nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       explicit prior written permission.
 * 
 * You are under no obligation whatsoever to provide any enhancements to Internet2,
 * or its contributors.  If you choose to provide your enhancements, or if you
 * choose to otherwise publish or distribute your enhancement, in source code form
 * without contemporaneously requiring end users to enter into a separate written
 * license agreement for such enhancements, then you thereby grant Internet2, its
 * contributors, and its members a non-exclusive, royalty-free, perpetual license
 * to copy, display, install, use, modify, prepare derivative works, incorporate
 * into the software or other computer software, distribute, and sublicense your
 * enhancements or derivative works thereof, in binary and source code form.
 * 
 * DISCLAIMER - THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * “AS IS” AND WITH ALL FAULTS.  THE UNIVERSITY OF DELAWARE, INTERNET2, ITS CONTRI-
 * BUTORS, AND ITS MEMBERS DO NOT IN ANY WAY WARRANT, GUARANTEE, OR ASSUME ANY RES-
 * PONSIBILITY, LIABILITY OR OTHER UNDERTAKING WITH RESPECT TO THE SOFTWARE. ANY E-
 * XPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRAN-
 * TIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT
 * ARE HEREBY DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH THE USER THEREOF.  IN NO EVENT SHALL THE COPYRIGHT
 * OWNER, CONTRIBUTORS, OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELO-
 * PMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTIT-
 * UTE GOODS OR SERVICES; REMOVAL OR REINSTALLATION LOSS OF USE, DATA, SAVINGS OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILIT-
 * Y, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHE-
 * RWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRUBUTION OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */
#include <bwlib/bwlibP.h>

/*
 * Function:    IperfAvailable
 * 
 * Description:
 *
 * In Args:
 * Out Args:
 * Scope:
 *
 * Returns:
 *
 * Side Effect:
 *
 */
static BWLBoolean
IperfAvailable(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    char            confkey[BWL_MAX_TOOLNAME + 10];
    int             len;
    char            *cmd;
    int             fdpipe[2];
    pid_t           pid;
    int             status;
    int             rc;
                    /* We expect 'iperf -v' to print to stderr something like
                    'iperf version 2.0.2 (03 May 2005) pthreads' */
    char            *pattern = "iperf version "; /* Expected begin of stderr */
    char            buf[PATH_MAX];
    const uint32_t  buf_size = I2Number(buf);

    /*
     * Build conf-key name that is used to store the tool cmd
     */
    strcpy(confkey,"V.");
    strncat(confkey,tool->name,sizeof(confkey));
    len = strlen(confkey);
    strncpy(&confkey[len],"_cmd",sizeof(confkey)-len);

    /*
     * Fetch 'tool' name
     */
    if( !(cmd = (char *)BWLContextConfigGetV(ctx,confkey))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "IperfAvailable(): %s unset, using \"%s\"",
                "iperf_cmd",tool->def_cmd);
        cmd = tool->def_cmd;
    }

    /*
     * iperf is quite weird regarding exit codes and output.
     *
     * 'iperf -v' and 'iperf -h exit 1!
     * Also, the output of 'iperf -v' and 'iperf -h' go to stderr, not stdout
     *
     */
    if(socketpair(AF_UNIX,SOCK_STREAM,0,fdpipe) < 0){
        BWLError(ctx,BWLErrFATAL,errno,"IperfAvailable():socketpair(): %M");
        return False;
    }

    pid = fork();

    /* fork error */
    if(pid < 0){
        BWLError(ctx,BWLErrFATAL,errno,"IperfAvailable():fork(): %M");
        return False;
    }

    /*
     * child:
     *
     * Redirect stderr to pipe - then exec iperf -v, which should send
     * an identifying version string into the pipe.
     */
    if(0 == pid){
        /* Redirect stderr from iperf into fdpipe[1]*/
        dup2(fdpipe[1],STDERR_FILENO);
        close(fdpipe[0]);
        close(fdpipe[1]);

        execlp(cmd,cmd,"-v",NULL);
        buf[buf_size-1] = '\0';
        snprintf(buf,buf_size-1,"IperfAvailable(): exec(%s)",cmd);
        perror(buf);
        exit(1);
    }

    /*
     * parent:
     *
     * Wait for child to exit, then read the output from the
     * child.
     *
     * XXX: This solution depends on the pipe buffer being large enough
     * to hold the complete output of the iperf -v command. (Otherwise
     * iperf will block...) This has not been a problem in practice, but
     * a more thourough solution would make sure SIGCHLD will be sent,
     * and wait for either that signal or I/O using select(2).
     *
     * May need to do this eventually anyway, if iperf ever starts
     * sending the messages via stdout - then this solution will need
     * to watch for data on both stdout and stderr.
     */

    close(fdpipe[1]);
    while(((rc = waitpid(pid,&status,0)) == -1) && errno == EINTR);
    if(rc < 0){
        BWLError(ctx,BWLErrFATAL,errno,
                "IperfAvailable(): waitpid(), rc = %d: %M",rc);
        return False;
    }

    /*
     * If iperf did not even exit...
     */
    if(!WIFEXITED(status)){
        if(WIFSIGNALED(status)){
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "IperfAvailable(): iperf exited due to signal=%d",
                    WTERMSIG(status));
        }
        BWLError(ctx,BWLErrWARNING,errno,"IperfAvailable(): iperf unusable");
        return False;
    }

    /*
     * Read any output from the child
     */
    buf[0] = '\0';
    if( (rc = read(fdpipe[0],buf,buf_size-1)) > 0){
        /* unsure the string is nul terminated */
        for(len=buf_size;len>rc;len--){
            buf[len-1] = '\0';
        }
    }
    close(fdpipe[0]);

    /*
     * Hopefully future versions of iperf will exit with 0 for -v...
     */
    if((WEXITSTATUS(status) == 0) || (WEXITSTATUS(status) == 1)){
        if(0 == strncmp(buf,pattern,strlen(pattern))){
            /* iperf found! */
            return True;
        }

        /* This is what we exit with if the exec fails so it likely means the tool isn't installed. */
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "IperfAvailable(): We were unable to verify that iperf is working. Likely you do not have it installed. exit status: 1: output: %s", buf);
    } else {
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "IperfAvailable(): iperf invalid: exit status %d: output:\n%s",
            WEXITSTATUS(status),buf);
    }

    return False;
}

/*
 * Function:    IperfPreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running an iperf test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the IperfRunTest.
 *
 *              (closure pointer is just the arg list for the exec)
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
/* This IperfArgs can be a static because it is only used from within a
 * forked process. If bwctl ever goes to threads, this will need to be
 * made thread-local memory.
 */
static char *IperfArgs[_BWL_MAX_TOOLARGS*2];
static void *
IperfPreRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess
        )
{
    char            confkey[BWL_MAX_TOOLNAME + 10];
    int             len;
    char            *cmd;
    int             a = 0;
    char            recvhost[MAXHOSTNAMELEN];
    char            sendhost[MAXHOSTNAMELEN];
    size_t          hlen;
    struct sockaddr *rsaddr;
    socklen_t       rsaddrlen;

    if( !(rsaddr = I2AddrSAddr(tsess->test_spec.receiver,&rsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "IperfPreRunTest(): Invalid receiver I2Addr");
        return NULL;
    }

    hlen = sizeof(recvhost);
    I2AddrNodeName(tsess->test_spec.receiver,recvhost,&hlen);
    if(!hlen){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "IperfPreRunTest(): Invalid receiver I2Addr");
        return NULL;
    }

    hlen = sizeof(sendhost);
    I2AddrNodeName(tsess->test_spec.sender,sendhost,&hlen);
    if(!hlen){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "IperfPreRunTest(): Invalid sender I2Addr");
        return NULL;
    }

    /*
     * Build conf-key name that is used to store the tool cmd
     */
    strcpy(confkey,"V.");
    strncat(confkey,tsess->tool->name,sizeof(confkey));
    len = strlen(confkey);
    strncpy(&confkey[len],"_cmd",sizeof(confkey)-len);

    /* Run iperf */
    cmd = (char*)BWLContextConfigGetV(ctx,confkey);
    if(!cmd) cmd = tsess->tool->def_cmd;

    /*
     * First figure out the args for iperf
     */
    IperfArgs[a++] = cmd;

    if(tsess->conf_receiver){
        IperfArgs[a++] = "-B";
        if( !(IperfArgs[a++] = strdup(recvhost))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"IperfPreRunTest():strdup(): %M");
            return NULL;
        }

        IperfArgs[a++] = "-s";
    }
    else{
        IperfArgs[a++] = "-c";
        if( !(IperfArgs[a++] = strdup(recvhost))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"IperfPreRunTest():strdup(): %M");
            return NULL;
        }
        IperfArgs[a++] = "-B";
        if( !(IperfArgs[a++] = strdup(sendhost))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"IperfPreRunTest():strdup(): %M");
            return NULL;
        }
        if(tsess->test_spec.tos){
            IperfArgs[a++] = "-S";
            if( !(IperfArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.tos))){
                return NULL;
            }
        }
    }

    /*
     * XXX: Perhaps these should be validated earlier, in the CheckTest
     * function chain?
     */
    if(!tsess->test_spec.units){
        IperfArgs[a++] = "-f";
        IperfArgs[a++] = "b";
    }
    else{
        char    temp[2];

        switch((char)tsess->test_spec.units){
            case 'b':
            case 'B':
            case 'k':
            case 'K':
            case 'm':
            case 'M':
            case 'g':
            case 'G':
            case 'a':
            case 'A':
                IperfArgs[a++] = "-f";
                temp[0] = (char)tsess->test_spec.units;
                temp[1] = '\0';
                if( !(IperfArgs[a++] = strdup(temp))){
                    BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                            "IperfPreRunTest():strdup(): %M");
                    return NULL;
                }
                break;

            default:
                fprintf(tsess->localfp,
                        "bwctl: tool(iperf): Invalid units (-f) specification %c",
                        (char)tsess->test_spec.units);
                return NULL;
                break;

        }
    }

    if(tsess->test_spec.outformat){
        switch((char)tsess->test_spec.outformat){
            case 'c':
                IperfArgs[a++] = "-y";
                IperfArgs[a++] = "c";
                break;
            default:
                fprintf(tsess->localfp,
                        "bwctl: tool(iperf): Invalid out format (-y) specification %c",
                        (char)tsess->test_spec.outformat);
                return NULL;
                break;

        }
    }

    if(tsess->test_spec.parallel_streams > 0){
        IperfArgs[a++] = "-P";
        if( !(IperfArgs[a++] =
                    BWLUInt32Dup(ctx,tsess->test_spec.parallel_streams))){
            return NULL;
        }
    }

    if(tsess->test_spec.len_buffer){
        IperfArgs[a++] = "-l";
        if( !(IperfArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.len_buffer))){
            return NULL;
        }
    }

    IperfArgs[a++] = "-m";

    IperfArgs[a++] = "-p";
    if( !(IperfArgs[a++] = BWLUInt32Dup(ctx,tsess->tool_port))){
        return NULL;
    }

    if(tsess->test_spec.udp){
        IperfArgs[a++] = "-u";
        if((!tsess->conf_receiver) && (tsess->test_spec.bandwidth)){
            IperfArgs[a++] = "-b";
            if( !(IperfArgs[a++] =
                        BWLUInt64Dup(ctx,tsess->test_spec.bandwidth))){
                return NULL;
            }
        }
    }

    if(tsess->test_spec.window_size){
        IperfArgs[a++] = "-w";
        if( !(IperfArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.window_size))){
            return NULL;
        }
    }

    IperfArgs[a++] = "-t";
    if( !(IperfArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.duration))){
        return NULL;
    }

    if(tsess->test_spec.report_interval){
        IperfArgs[a++] = "-i";
        if( !(IperfArgs[a++] =
                    BWLUInt32Dup(ctx,tsess->test_spec.report_interval))){
            return NULL;
        }
    }

    switch(rsaddr->sa_family){
#ifdef    AF_INET6
        case AF_INET6:
            IperfArgs[a++] = "-V";
            break;
#endif
        case AF_INET:
        default:
            break;
    }

    IperfArgs[a++] = NULL;

    /*
     * Report what will be run in the output file
     */
    fprintf(tsess->localfp,"bwctl: exec_line:");
    for(len=0;IperfArgs[len];len++){
        fprintf(tsess->localfp," %s",IperfArgs[len]);
    }
    fprintf(tsess->localfp,"\n");

    return (void *)IperfArgs;
}

/*
 * Function:    IperfRunTest
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
static BWLBoolean
IperfRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess __attribute__((unused)),
        void                *closure
        )
{
    char    **ipargs = (char **)closure;

    /*
     * Now run iperf!
     */
    execvp(ipargs[0],ipargs);

    BWLError(ctx,BWLErrFATAL,errno,"execvp(%s): %M",ipargs[0]);
    exit(BWL_CNTRL_FAILURE);
}

BWLToolDefinitionRec    BWLToolIperf = {
    "iperf",                /* name             */
    "iperf",                /* def_cmd          */
    NULL,                   /* def_server_cmd   */
    5001,                   /* def_port         */
    _BWLToolGenericParse,    /* parse            */
    IperfAvailable,         /* tool_avail       */
    _BWLToolGenericInitTest, /* init_test        */
    IperfPreRunTest,        /* pre_run          */
    IperfRunTest            /* run              */
};
