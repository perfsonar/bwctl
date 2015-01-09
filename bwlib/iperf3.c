/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id$
 */
/*
 *    File:         iperf3.c
 *
 *    Author:       Aaron Brown
 *                  Internet2
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run an
 *    iperf3 throughput tool in bwctl.
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
 * Function:    Iperf3Available
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
Iperf3Available(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    int             len;
    char            *cmd;
    char            *patterns[] = { "iperf 3.0.11", "iperf 3.1" }; /* Expected begin of stdout */
                    /* We expect 'iperf3 -v' to print to stderr something like
                    'iperf 3.0.11' or 'iperf 3.1*' */
    char            buf[1024];
    int             n;

    /*
     * Fetch 'tool' name
     */
    if( !(cmd = (char *)BWLContextConfigGetV(ctx,"V.iperf3_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "Iperf3Available(): %s unset, using \"%s\"",
                "iperf3_cmd",tool->def_cmd);
        cmd = tool->def_cmd;
    }

    n = ExecCommand(ctx, buf, sizeof(buf), cmd, "-v", NULL);
    if(n == 0 || n == 1) {
        int i;
        for(i = 0; i < strlen(buf); i++) {
            int j;
            for(j = 0; j < sizeof(patterns)/sizeof(char *); j++) {
                if(0 == strncmp(buf + i,patterns[j],strlen(patterns[j]))){
                    /* iperf3 found! */
                    return True;
                }
            }
        }
   }

   /* This is what we exit with if the exec fails so it likely means the tool isn't installed. */
   BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
        "Iperf3Available(): An appropriate version of iperf3 is not available (>= 3.0.11). It may not be installed. exit status: %d: output: %s", n, buf);

   return False;
}

static BWLBoolean
Iperf3ValidateTest(
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
                    "Iperf3ValidateTest: Invalid units specification: %c",
                    (char)test_spec.units);
                return False;
                break;
        }
    }

    if(test_spec.outformat){
        switch((char)test_spec.outformat){
            case 'c':
            case 'J':
                break;
            default:
                BWLError(ctx,BWLErrFATAL,EINVAL,
                        "Iperf3ValidateTest: Invalid output format specification %c",
                        (char)test_spec.outformat);
                return False;
                break;

        }
    }

    return _BWLToolGenericValidateTest(ctx, tool, test_spec);
}

/*
 * Function:    Iperf3PreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running an iperf3 test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the Iperf3RunTest.
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
/* This Iperf3Args can be a static because it is only used from within a
 * forked process. If bwctl ever goes to threads, this will need to be
 * made thread-local memory.
 */
static char *Iperf3Args[_BWL_MAX_TOOLARGS*2];
static void *
Iperf3PreRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess
        )
{
    int             len;
    char            *cmd;
    int             a = 0;
    char            recvhost[MAXHOSTNAMELEN];
    char            sendhost[MAXHOSTNAMELEN];

    if(BWLAddrNodeName(ctx, tsess->test_spec.server, recvhost, sizeof(recvhost), NI_NUMERICHOST) == NULL) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "Iperf3PreRunTest(): Invalid server I2Addr");
        return NULL;
    }

    if(BWLAddrNodeName(ctx, tsess->test_spec.client, sendhost, sizeof(sendhost), NI_NUMERICHOST) == NULL) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "Iperf3PreRunTest(): Invalid client I2Addr");
        return NULL;
    }

    /* Fill in any taskset options */
    a = BWLToolGenericFillCPUAffinityCommand(ctx, tsess->tool, Iperf3Args);

    /* Run iperf3 */
    cmd = (char*)BWLContextConfigGetV(ctx,"V.iperf3_cmd");
    if(!cmd) cmd = tsess->tool->def_cmd;

    /*
     * First figure out the args for iperf
     */
    Iperf3Args[a++] = cmd;

    /*
     * Set the address information
     */
    if(tsess->conf_server){
        Iperf3Args[a++] = "-s";
        Iperf3Args[a++] = "-1"; // Make it a one-shot server

        Iperf3Args[a++] = "-B";
        if( !(Iperf3Args[a++] = strdup(recvhost))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"Iperf3PreRunTest():strdup(): %M");
            return NULL;
        }
    }
    else{
        Iperf3Args[a++] = "-c";
        if( !(Iperf3Args[a++] = strdup(recvhost))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"Iperf3PreRunTest():strdup(): %M");
            return NULL;
        }
        Iperf3Args[a++] = "-B";
        if( !(Iperf3Args[a++] = strdup(sendhost))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"Iperf3PreRunTest():strdup(): %M");
            return NULL;
        }
    }

    /*
     * Set some common parameters
     */
    Iperf3Args[a++] = "-f";
    if(!tsess->test_spec.units){
        Iperf3Args[a++] = "m";
    }
    else{
        char temp[2];

        temp[0] = (char)tsess->test_spec.units;
        temp[1] = '\0';
        if( !(Iperf3Args[a++] = strdup(temp))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                    "Iperf3PreRunTest():strdup(): %M");
            return NULL;
        }
    }

    if(tsess->test_spec.outformat == 'J'){
        Iperf3Args[a++] = "-J";
    }

    Iperf3Args[a++] = "-p";
    if( !(Iperf3Args[a++] = BWLUInt32Dup(ctx,tsess->tool_port))){
        return NULL;
    }

    if(tsess->test_spec.report_interval){
        Iperf3Args[a++] = "-i";
        if( !(Iperf3Args[a++] =
                    BWLDoubleDup(ctx,tsess->test_spec.report_interval / 1000.0))){
            return NULL;
        }
    }

    if (tsess->test_spec.verbose) {
        Iperf3Args[a++] = "-V";
    }

    /*
     * set some client-specific parameters
     */
    if(!tsess->conf_server){
        Iperf3Args[a++] = "-Z"; // Set the zerocopy mode by default (for backwards compatibility of results)

        if(tsess->test_spec.tos){
            Iperf3Args[a++] = "-S";
            if( !(Iperf3Args[a++] = BWLUInt32Dup(ctx,tsess->test_spec.tos))){
                return NULL;
            }
        }

        if (tsess->test_spec.server_sends)
             Iperf3Args[a++] = "--reverse";

        Iperf3Args[a++] = "-t";
        if( !(Iperf3Args[a++] = BWLUInt32Dup(ctx,tsess->test_spec.duration))){
            return NULL;
        }

        if(tsess->test_spec.parallel_streams > 0){
            Iperf3Args[a++] = "-P";
            if( !(Iperf3Args[a++] =
                        BWLUInt32Dup(ctx,tsess->test_spec.parallel_streams))){
                return NULL;
            }
        }

        if(tsess->test_spec.udp){
            Iperf3Args[a++] = "-u";
        }

        if(tsess->test_spec.len_buffer){
            Iperf3Args[a++] = "-l";
            if( !(Iperf3Args[a++] = BWLUInt32Dup(ctx,tsess->test_spec.len_buffer))){
                return NULL;
            }
        }

        if(tsess->test_spec.bandwidth){
            Iperf3Args[a++] = "-b";
            if( !(Iperf3Args[a++] =
                        BWLUInt64Dup(ctx,tsess->test_spec.bandwidth))){
                return NULL;
            }
        }

        if(tsess->test_spec.window_size){
            Iperf3Args[a++] = "-w";
            if( !(Iperf3Args[a++] = BWLUInt32Dup(ctx,tsess->test_spec.window_size))){
                return NULL;
            }
        }
    }

    Iperf3Args[a++] = NULL;

    /*
     * Report what will be run in the output file
     */
    if (tsess->test_spec.verbose) {
        fprintf(tsess->localfp,"bwctl: exec_line:");
        for(len=0;Iperf3Args[len];len++){
            fprintf(tsess->localfp," %s",Iperf3Args[len]);
        }
        fprintf(tsess->localfp,"\n");
    }

    return (void *)Iperf3Args;
}

/*
 * Function:    Iperf3RunTest
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
Iperf3RunTest(
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

BWLToolDefinitionRec    BWLToolIperf3 = {
    "iperf3",                /* name             */
    "iperf3",                /* def_cmd          */
    "iperf3",               /* def_server_cmd   */
    5001,                   /* def_port         */
    _BWLToolGenericParse,    /* parse            */
    BWLGenericParseThroughputParameters,    /* parse_request */
    BWLGenericUnparseThroughputParameters,  /* unparse_request */
    Iperf3Available,         /* tool_avail       */
    Iperf3ValidateTest,      /* validate_test    */
    _BWLToolGenericInitTest, /* init_test        */
    Iperf3PreRunTest,        /* pre_run          */
    Iperf3RunTest,           /* run              */
    _BWLToolGenericKillTest, /* kill             */
    BWL_TEST_THROUGHPUT,     /* test_types       */
    BWLToolClientSideData,      /* results_side     */
    True,                    /* supports_server_sends */
    True,                    /* supports_endpointless */
    5201,                    /* The server port to use in endpointless tests */
    'J',                     /* parsable format */
};
