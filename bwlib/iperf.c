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
    int             len;
    char            *cmd;
    char            *pattern = "iperf version "; /* Expected begin of stderr */
                    /* We expect 'iperf -v' to print to stderr something like
                    'iperf version 2.0.2 (03 May 2005) pthreads' */
    char            buf[1024];
    int             n;

    /*
     * Fetch 'tool' name
     */
    if( !(cmd = (char *)BWLContextConfigGetV(ctx,"V.iperf_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "IperfAvailable(): %s unset, using \"%s\"",
                "iperf_cmd",tool->def_cmd);
        cmd = tool->def_cmd;
    }

    n = ExecCommand(ctx, buf, sizeof(buf), cmd, "-v", NULL);
    if(n == 0 || n == 1) {
        if(0 == strncmp(buf,pattern,strlen(pattern))){
            /* iperf found! */
            return True;
        }
   }

   /* This is what we exit with if the exec fails so it likely means the tool isn't installed. */
   BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
        "IperfAvailable(): Unable to verify that iperf is working. It may not be installed. exit status: %d: output: %s", n, buf);

   return False;
}

static BWLBoolean
IperfValidateTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        BWLTestSpec         test_spec
        )
{
    // validate the units
    if(test_spec.units){
        switch((char)test_spec.units){
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
                break;
            default:
                BWLError(ctx,BWLErrFATAL,EINVAL,
                    "IperfValidateTest: Invalid units specification: %c",
                    (char)test_spec.units);
                return False;
                break;
        }
    }

    if(test_spec.outformat){
        switch((char)test_spec.outformat){
            case 'c':
                break;
            default:
                BWLError(ctx,BWLErrFATAL,EINVAL,
                        "IperfValidateTest: Invalid output format specification %c",
                        (char)test_spec.outformat);
                return False;
                break;

        }
    }

    return _BWLToolGenericValidateTest(ctx, tool, test_spec);
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
    int             len;
    char            *cmd;
    int             a = 0;
    char            recvhost[MAXHOSTNAMELEN];
    char            sendhost[MAXHOSTNAMELEN];
    size_t          hlen;
    struct sockaddr *rsaddr;
    socklen_t       rsaddrlen;

    if( !(rsaddr = I2AddrSAddr(tsess->test_spec.server,&rsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "IperfPreRunTest(): Invalid server I2Addr");
        return NULL;
    }

    hlen = sizeof(recvhost);
    I2AddrNodeName(tsess->test_spec.server,recvhost,&hlen);
    if(!hlen){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "IperfPreRunTest(): Invalid server I2Addr");
        return NULL;
    }

    hlen = sizeof(sendhost);
    I2AddrNodeName(tsess->test_spec.client,sendhost,&hlen);
    if(!hlen){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "IperfPreRunTest(): Invalid client I2Addr");
        return NULL;
    }

    /* Run iperf */
    cmd = (char*)BWLContextConfigGetV(ctx,"V.iperf_cmd");
    if(!cmd) cmd = tsess->tool->def_cmd;

    /*
     * First figure out the args for iperf
     */
    IperfArgs[a++] = cmd;

    if(tsess->conf_server){
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

    if(!tsess->test_spec.udp && tsess->test_spec.bandwidth){
        fprintf(tsess->localfp, "bwctl: iperf does not support setting TCP bandwidth");
        return NULL;
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
        if((!tsess->conf_server) && (tsess->test_spec.bandwidth)){
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
                    BWLDoubleDup(ctx,tsess->test_spec.report_interval / 1000.0))){
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
    BWLGenericParseThroughputParameters,    /* parse_request */
    BWLGenericUnparseThroughputParameters,  /* unparse_request */
    IperfAvailable,         /* tool_avail       */
    IperfValidateTest,      /* validate_test    */
    _BWLToolGenericInitTest, /* init_test        */
    IperfPreRunTest,        /* pre_run          */
    IperfRunTest,           /* run              */
    BWL_TEST_THROUGHPUT,     /* test_types       */
    BWLToolServerSideData,      /* results_side     */
    False,                   /* supports_server_sends */
    True,                    /* supports_endpointless */
    5001,                    /* The server port to use in endpointless tests */
};
