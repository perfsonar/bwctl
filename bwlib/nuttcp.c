/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id$
 */
/*
 *    File:         nuttcp.c
 *
 *    Author:       Jeff W. Boote
 *                  Internet2
 *
 *    Date:         Thu Dec 27 15:31:29 MST 2007
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run an
 *    nuttcp throughput tool in bwctl.
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
#include <bwlib/bwlibP.h>

/*
 * Function:    NuttcpAvailable
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
NuttcpAvailable(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    char            confkey[BWL_MAX_TOOLNAME + 10];
    int             len;
    char            *cmd;
                    /* We expect 'nuttcp -V' to print to stdout something like
                    'nuttcp-.3.1' */
    char            *pattern = "nuttcp-"; /* Expected begin of stdout */
    char            buf[1024];
    int             n;

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
                "NuttcpAvailable(): %s unset, using \"%s\"",
                "nuttcp_cmd",tool->def_cmd);
        cmd = tool->def_cmd;
    }

    /*
     * If it exited as expected, check the return string.
     */
    n = ExecCommand(ctx, buf, sizeof(buf), cmd, "-V", NULL);
    if(n == 0){
        if(0 == strncmp(buf,pattern,strlen(pattern))){
            /* nuttcp found! */
            return True;
        }
    }

    /* This is what we exit with if the exec fails so it likely means the tool isn't installed. */
    BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
        "NuttcpAvailable(): Unable to verify that nuttcp is working. It may not be installed. exit status: %d: output: %s", n, buf);

    return False;
}

static BWLBoolean
NuttcpValidateTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        BWLTestSpec         test_spec
        )
{
    /*
     * TODO: Fix this to allow UDP Nuttcp tests.
     */
    if(test_spec.udp){
        BWLError(ctx,BWLErrDEBUG,BWLErrPOLICY,
                "NuttcpPreRunTest: Does not support Nuttcp UDP connections");
        return False;
    }

    return _BWLToolGenericValidateTest(ctx, tool, test_spec);
}


/*
 * Function:    NuttcpPreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running an nuttcp test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the NuttcpRunTest.
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
/* This NuttcpArgs can be a static because it is only used from within a
 * forked process. If bwctl ever goes to threads, this will need to be
 * made thread-local memory.
 */
static char *NuttcpArgs[_BWL_MAX_TOOLARGS*2];
static void *
NuttcpPreRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess
        )
{
    char            confkey[BWL_MAX_TOOLNAME + 10];
    int             len;
    char            *cmd;
    int             a = 0;
    char            recvhost[MAXHOSTNAMELEN];
    size_t          hlen = sizeof(recvhost);
    struct sockaddr *rsaddr;
    socklen_t       rsaddrlen;

    if( !(rsaddr = I2AddrSAddr(tsess->test_spec.server,&rsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "NuttcpPreRunTest: Invalid server I2Addr");
        return NULL;
    }
    if (BWLAddrNodeName(tsess->cntrl->ctx,tsess->test_spec.server,recvhost,hlen, NI_NUMERICHOST) == NULL) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "NuttcpPreRunTest: Invalid server I2Addr");
        return NULL;
    }

    /*
     * Build conf-key name that is used to store the tool cmd
     */
    strcpy(confkey,"V.");
    strncat(confkey,tsess->tool->name,sizeof(confkey));
    len = strlen(confkey);
    strncpy(&confkey[len],"_cmd",sizeof(confkey)-len);

    /* Run nuttcp */
    cmd = (char*)BWLContextConfigGetV(ctx,confkey);
    if(!cmd) cmd = tsess->tool->def_cmd;

    /* Figure out arguments. */
    NuttcpArgs[a++] = cmd;
    /* Be verbose */
    NuttcpArgs[a++] = "-vv";


    if(tsess->test_spec.len_buffer){
        NuttcpArgs[a++] = "-l";
        NuttcpArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.len_buffer);
    }

    NuttcpArgs[a++] = "-p";
    NuttcpArgs[a++] = BWLUInt32Dup(ctx,tsess->tool_port);

    // explicitly set the control port
    NuttcpArgs[a++] = "-P";
    NuttcpArgs[a++] = "5000";

    if(tsess->test_spec.udp){
        NuttcpArgs[a++] = "-u";
    }

    if((!tsess->conf_server) && (tsess->test_spec.bandwidth)){
        NuttcpArgs[a++] = "-R";
        /* nuttcp expects a number of Kbytes. */
        NuttcpArgs[a++] = BWLUInt64Dup(ctx,
                tsess->test_spec.bandwidth / 1024);
    }

    if(tsess->test_spec.window_size){
        NuttcpArgs[a++] = "-w";
        /* nuttcp expects a number of Kbytes. */
        NuttcpArgs[a++] = BWLUInt32Dup(ctx,
                tsess->test_spec.window_size / 1024);
    }

    if(tsess->test_spec.report_interval){
        NuttcpArgs[a++] = "-i";
        if( !(NuttcpArgs[a++] =
                    BWLDoubleDup(ctx,tsess->test_spec.report_interval / 1000.0))){
            return NULL;
        }
    }

    NuttcpArgs[a++] = "-T";
    NuttcpArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.duration);

    switch(rsaddr->sa_family){
#ifdef    AF_INET6
        case AF_INET6:
            NuttcpArgs[a++] = "-6";
            break;
#endif
        case AF_INET:
        default:
            break;
    }

    if(!tsess->conf_server){
        if(tsess->test_spec.tos){
            NuttcpArgs[a++] = "-c";
            NuttcpArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.tos);
        }

        if(tsess->test_spec.parallel_streams > 0){
            NuttcpArgs[a++] = "-N";
            NuttcpArgs[a++] = BWLUInt32Dup(ctx,
                    tsess->test_spec.parallel_streams);
        }

        if (tsess->test_spec.server_sends) {
            NuttcpArgs[a++] = "-r";
        }
        else {
            NuttcpArgs[a++] = "-t";
        }

        if( !(NuttcpArgs[a++] = strdup(recvhost))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                    "NuttcpPreRunTest():strdup(): %M");
            return NULL;
        }
    }

    if(tsess->conf_server){
        NuttcpArgs[a++] = "--nofork";
        NuttcpArgs[a++] = "-1";
    }

    NuttcpArgs[a++] = NULL;

    /*
     * Report what will be run in the output file
     */
    fprintf(tsess->localfp,"bwctl: exec_line:");
    for(len=0;NuttcpArgs[len];len++){
        fprintf(tsess->localfp," %s",NuttcpArgs[len]);
    }
    fprintf(tsess->localfp,"\n");

    return (void *)NuttcpArgs;
}

/*
 * Function:    NuttcpRunTest
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
NuttcpRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess __attribute__((unused)),
        void                *closure
        )
{
    char    **ipargs = (char **)closure;

    /*
     * Now run nuttcp!
     */
    execvp(ipargs[0],ipargs);

    BWLError(ctx,BWLErrFATAL,errno,"execvp(%s): %M",ipargs[0]);
    exit(BWL_CNTRL_FAILURE);
}

BWLToolDefinitionRec    BWLToolNuttcp = {
    "nuttcp",                /* name             */
    "nuttcp",                /* def_cmd          */
    NULL,                   /* def_server_cmd   */
    5001,                   /* def_port         */
    _BWLToolGenericParse,    /* parse            */
    BWLGenericParseThroughputParameters,    /* parse_request */
    BWLGenericUnparseThroughputParameters,  /* unparse_request */
    NuttcpAvailable,         /* tool_avail       */
    NuttcpValidateTest,      /* validate_test    */
    _BWLToolGenericInitTest, /* init_test        */
    NuttcpPreRunTest,        /* pre_run          */
    NuttcpRunTest,           /* run              */
    BWL_TEST_THROUGHPUT,     /* test_types       */
    BWLToolClientSideData,      /* results_side     */
    True,                   /* supports_server_sends */
    True,                    /* supports_endpointless */
    5001,                    /* The server port to use in endpointless tests */
    NULL,                    /* parsable format */
};
