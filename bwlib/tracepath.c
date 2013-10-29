/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id: tracepath.c 599 2013-08-02 17:27:12Z aaron $
 */
/*
 *    File:         tracepath.c
 *
 *    Author:       Aaron Brown
 *                  Internet2
 *
 *    Date:         2013-09-02
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run a
 *    tracepath test in bwctl.
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

#include <sys/socket.h>
#include <netdb.h>

#define TRACEPATH_DEFAULT_CMD         "tracepath"
#define TRACEPATH6_DEFAULT_CMD        "tracepath6"

/*
 * Function:    TracepathAvailable
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
TracepathAvailable(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    BWLBoolean  tracepath_available = False;
    BWLBoolean  tracepath6_available = False;
    char        *tracepath_cmd;
    char        *tracepath6_cmd;
    int         n;
    char        buf[1024];

    /*
     * Fetch the 'tracepath'
     */
    if( !(tracepath_cmd = (char *)BWLContextConfigGetV(ctx,"V.tracepath_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "TracepathAvailable(): %s unset, using \"%s\"",
                "tracepath_cmd",TRACEPATH_DEFAULT_CMD);
        tracepath_cmd = TRACEPATH_DEFAULT_CMD;
    }

    /*
     * Fetch the 'tracepath6'
     */
    if( !(tracepath6_cmd = (char *)BWLContextConfigGetV(ctx,"V.tracepath6_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "TracepathAvailable(): %s unset, using \"%s\"",
                "tracepath6_cmd",TRACEPATH6_DEFAULT_CMD);
        tracepath6_cmd = TRACEPATH6_DEFAULT_CMD;
    }

    n = ExecCommand(ctx, buf, sizeof(buf), tracepath_cmd, NULL);
    if (n == 255) {
        tracepath_available = True;
    }
    else {
        tracepath_available = False;
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "TracepathAvailable(): Unable to verify that '%s' is working. It may not be installed. exit status: %d: output: %s", tracepath_cmd, n, buf);
    }


    n = ExecCommand(ctx, buf, sizeof(buf), tracepath6_cmd, NULL);
    if (n == 255) {
        tracepath6_available = True;
    }
    else {
        tracepath6_available = False;
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "TracepathAvailable(): Unable to verify that '%s' is working. It may not be installed. exit status: %d: output: %s", tracepath6_cmd, n, buf);
    }


    return (tracepath_available || tracepath6_available);
}

/*
 * Function:    TracepathPreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running an tracepath test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the TracepathRunTest.
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
/* This TracepathArgs can be a static because it is only used from within a
 * forked process. If bwctl ever goes to threads, this will need to be
 * made thread-local memory.
 */
static char *TracepathArgs[_BWL_MAX_TOOLARGS*2];
static void *
TracepathPreRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess
        )
{
    char            confkey[BWL_MAX_TOOLNAME + 10];
    int             len;
    char            *cmd;
    char            *default_cmd;
    char            *cmd_variable;
    int             a = 0;
    size_t          hlen;
    struct sockaddr *rsaddr;
    socklen_t       rsaddrlen;
    char            rsaddr_str[INET6_ADDRSTRLEN];
    I2Addr          remote_side;

    // If 'server sends' mode is in effect, the server runs the tracepath command,
    // because the client doesn't need to set anything up. It's a hack, but it
    // should work.
    if((tsess->conf_server && !tsess->test_spec.server_sends) ||
        (tsess->conf_client && tsess->test_spec.server_sends)) {
        fprintf(tsess->localfp,"bwctl: nothing to exec for tracepath server");
        TracepathArgs[0] = NULL;
        return (void *)TracepathArgs;
    }

    if (tsess->test_spec.server_sends) {
        remote_side = tsess->test_spec.client;
    }
    else {
        remote_side = tsess->test_spec.server;
    }

    if( !(rsaddr = I2AddrSAddr(remote_side,&rsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "TracepathPreRunTest(): Invalid server I2Addr");
        return NULL;
    }

    switch(rsaddr->sa_family){
#ifdef    AF_INET6
        case AF_INET6:
            cmd_variable = "V.tracepath6_cmd";
            default_cmd = TRACEPATH6_DEFAULT_CMD;
            break;
#endif
        case AF_INET:
            cmd_variable = "V.tracepath_cmd";
            default_cmd = TRACEPATH_DEFAULT_CMD;
            break;
        default:
            return NULL;
            break;
    }

    /* Run tracepath */
    cmd = (char*)BWLContextConfigGetV(ctx,cmd_variable);
    if(!cmd) cmd = default_cmd;

    /*
     * First figure out the args for tracepath
     */
    TracepathArgs[a++] = cmd;

    if(tsess->test_spec.traceroute_first_ttl){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "TracepathPreRunTest(): Tracepath does not support setting the TTL");
    }

    if(tsess->test_spec.traceroute_last_ttl){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "TracepathPreRunTest(): Tracepath does not support setting the TTL");
    }

    if(tsess->test_spec.traceroute_packet_size){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "TracepathPreRunTest(): Tracepath does not support setting the packet size");
    }

    getnameinfo((struct sockaddr *)rsaddr, rsaddrlen, rsaddr_str, sizeof(rsaddr_str), 0, 0, NI_NUMERICHOST);

    if( !(TracepathArgs[a++] = strdup(rsaddr_str))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"TracepathPreRunTest():strdup(): %M");
        return NULL;
    }

    TracepathArgs[a++] = NULL;

    /*
     * Report what will be run in the output file
     */
    fprintf(tsess->localfp,"bwctl: exec_line:");
    for(len=0;TracepathArgs[len];len++){
        fprintf(tsess->localfp," %s",TracepathArgs[len]);
    }
    fprintf(tsess->localfp,"\n");

    return (void *)TracepathArgs;
}

/*
 * Function:    TracepathRunTest
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
TracepathRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess,
        void                *closure
        )
{
    char    **ipargs = (char **)closure;

    if (ipargs[0] != NULL) {
        /*
         * Now run tracepath!
         */
        execvp(ipargs[0],ipargs);

        BWLError(ctx,BWLErrFATAL,errno,"execvp(%s): %M",ipargs[0]);
        exit(BWL_CNTRL_FAILURE);
    }

    // Special case for the tracepath server. There isn't anything for the receive
    // side to run, so just sleep until duration is up.
    sleep(tsess->test_spec.duration);

    exit(0);
}

/*
 * Function:    TracepathInitTest
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
BWLErrSeverity
TracepathInitTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        uint16_t            *toolport
        )
{
    return BWLErrOK;
}

int
TracepathParse(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        const char          *key,
        const char          *val
        )
{
    if(!strncasecmp(key,"tracepath_cmd",strlen(key))){
        return save_path(ctx,key,val);
    }

    if(!strncasecmp(key,"tracepath6_cmd",strlen(key))){
        return save_path(ctx,key,val);
    }

    return _BWLToolGenericParse(ctx, tool, key, val);
}

BWLToolDefinitionRec    BWLToolTracepath = {
    "tracepath",                  /* name             */
    "tracepath",                  /* def_cmd          */
    NULL,                    /* def_server_cmd   */
    0,                       /* def_port         */
    TracepathParse,               /* parse            */
    BWLGenericParseTracerouteParameters,    /* parse_request */
    BWLGenericUnparseTracerouteParameters,  /* unparse_request */
    TracepathAvailable,           /* tool_avail       */
    TracepathInitTest,            /* init_test        */
    TracepathPreRunTest,          /* pre_run          */
    TracepathRunTest,             /* run              */
    BWL_TEST_TRACEROUTE,    /* test_types       */
    BWLToolSenderSideData,      /* results_side     */
    True,                    /* supports_server_sends */
};
