/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id: traceroute.c 599 2013-08-02 17:27:12Z aaron $
 */
/*
 *    File:         traceroute.c
 *
 *    Author:       Aaron Brown
 *                  Internet2
 *
 *    Date:         2013-09-02
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run a
 *    traceroute test in bwctl.
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

#define TRACEROUTE_DEFAULT_CMD         "traceroute"
#define TRACEROUTE6_DEFAULT_CMD        "traceroute6"

/*
 * Function:    TracerouteAvailable
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
TracerouteAvailable(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    BWLBoolean  traceroute_available = False;
    BWLBoolean  traceroute6_available = False;
    char        *traceroute_cmd;
    char        *traceroute6_cmd;
    int         n;
    char        buf[1024];

    /*
     * Fetch the 'traceroute'
     */
    if( !(traceroute_cmd = (char *)BWLContextConfigGetV(ctx,"V.traceroute_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "TracerouteAvailable(): %s unset, using \"%s\"",
                "traceroute_cmd",TRACEROUTE_DEFAULT_CMD);
        traceroute_cmd = TRACEROUTE_DEFAULT_CMD;
    }

    /*
     * Fetch the 'traceroute6'
     */
    if( !(traceroute6_cmd = (char *)BWLContextConfigGetV(ctx,"V.traceroute6_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "TracerouteAvailable(): %s unset, using \"%s\"",
                "traceroute6_cmd",TRACEROUTE6_DEFAULT_CMD);
        traceroute6_cmd = TRACEROUTE6_DEFAULT_CMD;
    }

    n = ExecCommand(ctx, buf, sizeof(buf), traceroute_cmd, "127.0.0.1", NULL);
    if (n == 0) {
        traceroute_available = True;
    }
    else {
        traceroute_available = False;
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "TracerouteAvailable(): Unable to verify that '%s' is working. It may not be installed. exit status: %d: output: %s", traceroute_cmd, n, buf);
    }


    n = ExecCommand(ctx, buf, sizeof(buf), traceroute6_cmd, "::1", NULL);
    if (n == 0) {
        traceroute6_available = True;
    }
    else {
        traceroute6_available = False;
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "TracerouteAvailable(): Unable to verify that '%s' is working. It may not be installed. exit status: %d: output: %s", traceroute6_cmd, n, buf);
    }


    return (traceroute_available || traceroute6_available);
}


/*
 * Function:    TraceroutePreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running an traceroute test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the TracerouteRunTest.
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
/* This TracerouteArgs can be a static because it is only used from within a
 * forked process. If bwctl ever goes to threads, this will need to be
 * made thread-local memory.
 */
static char *TracerouteArgs[_BWL_MAX_TOOLARGS*2];
static void *
TraceroutePreRunTest(
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
    I2Addr          remote_side;
    I2Addr          local_side;
    char            addr_str[INET6_ADDRSTRLEN];

    // If 'server sends' mode is in effect, the server runs the ping command,
    // because the client doesn't need to set anything up. It's a hack, but it
    // should work.
    if((tsess->conf_server && !tsess->test_spec.server_sends) ||
        (tsess->conf_client && tsess->test_spec.server_sends)) {
        fprintf(tsess->localfp,"bwctl: nothing to exec for ping server");
        TracerouteArgs[0] = NULL;
        return (void *)TracerouteArgs;
    }

    if (tsess->test_spec.server_sends) {
        local_side  = tsess->test_spec.server;
        remote_side = tsess->test_spec.client;
    }
    else {
        local_side  = tsess->test_spec.client;
        remote_side = tsess->test_spec.server;
    }

    if (BWLAddrIsIPv6(ctx, remote_side)) {
        cmd_variable = "V.traceroute6_cmd";
        default_cmd = TRACEROUTE6_DEFAULT_CMD;
    }
    else {
        cmd_variable = "V.traceroute_cmd";
        default_cmd = TRACEROUTE_DEFAULT_CMD;
    }

    /* Run traceroute */
    cmd = (char*)BWLContextConfigGetV(ctx,cmd_variable);
    if(!cmd) cmd = default_cmd;

    /*
     * First figure out the args for traceroute
     */
    TracerouteArgs[a++] = cmd;

    if(tsess->test_spec.traceroute_first_ttl){
        TracerouteArgs[a++] = "-f";
        if( !(TracerouteArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.traceroute_first_ttl))){
            return NULL;
        }
    }

    if(tsess->test_spec.traceroute_last_ttl){
        TracerouteArgs[a++] = "-m";
        if( !(TracerouteArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.traceroute_last_ttl))){
            return NULL;
        }
    }

    if(tsess->test_spec.traceroute_packet_size){
        if( !(TracerouteArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.traceroute_packet_size))){
            return NULL;
        }
    }

    if(tsess->test_spec.outformat){
        switch((char)tsess->test_spec.outformat){
            case 'a':
                TracerouteArgs[a++] = "-n";
                break;
            default:
                fprintf(tsess->localfp,
                        "bwctl: tool(traceroute): Invalid out format (-y) specification %c",
                        (char)tsess->test_spec.outformat);
                return NULL;
        }
    }

    // Bind to the specified address
    TracerouteArgs[a++] = "-s";
    if( BWLAddrNodeName(ctx, local_side, addr_str, sizeof(addr_str), NI_NUMERICHOST) == 0) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"TraceroutePreRunTest():Problem resolving address");
        return NULL;
    }

    if( !(TracerouteArgs[a++] = strdup(addr_str))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"TraceroutePreRunTest():strdup(): %M");
        return NULL;
    }

    if( BWLAddrNodeName(ctx, remote_side, addr_str, sizeof(addr_str), NI_NUMERICHOST) == 0) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"TraceroutePreRunTest():Problem resolving address");
        return NULL;
    }

    if( !(TracerouteArgs[a++] = strdup(addr_str))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"TraceroutePreRunTest():strdup(): %M");
        return NULL;
    }

    if(tsess->test_spec.traceroute_packet_size){
        if( !(TracerouteArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.traceroute_packet_size))){
            return NULL;
        }
    }

    TracerouteArgs[a++] = NULL;

    /*
     * Report what will be run in the output file
     */
    fprintf(tsess->localfp,"bwctl: exec_line:");
    for(len=0;TracerouteArgs[len];len++){
        fprintf(tsess->localfp," %s",TracerouteArgs[len]);
    }
    fprintf(tsess->localfp,"\n");

    return (void *)TracerouteArgs;
}

/*
 * Function:    TracerouteRunTest
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
TracerouteRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess,
        void                *closure
        )
{
    char    **ipargs = (char **)closure;

    if (ipargs[0] != NULL) {
        /*
         * Now run traceroute!
         */
        execvp(ipargs[0],ipargs);

        BWLError(ctx,BWLErrFATAL,errno,"execvp(%s): %M",ipargs[0]);
        exit(BWL_CNTRL_FAILURE);
    }

    // Special case for the traceroute server. There isn't anything for the receive
    // side to run, so just sleep until duration is up.
    sleep(tsess->test_spec.duration);

    exit(0);
}

/*
 * Function:    TracerouteInitTest
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
TracerouteInitTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        uint16_t            *toolport
        )
{
    return BWLErrOK;
}

int
TracerouteParse(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        const char          *key,
        const char          *val
        )
{
    if(!strncasecmp(key,"traceroute_cmd",strlen(key))){
        return save_path(ctx,key,val);
    }

    if(!strncasecmp(key,"traceroute6_cmd",strlen(key))){
        return save_path(ctx,key,val);
    }

    return _BWLToolGenericParse(ctx, tool, key, val);
}

BWLToolDefinitionRec    BWLToolTraceroute = {
    "traceroute",                  /* name             */
    "traceroute",                  /* def_cmd          */
    NULL,                    /* def_server_cmd   */
    0,                       /* def_port         */
    TracerouteParse,               /* parse            */
    BWLGenericParseTracerouteParameters,    /* parse_request */
    BWLGenericUnparseTracerouteParameters,  /* unparse_request */
    TracerouteAvailable,           /* tool_avail       */
    TracerouteInitTest,            /* init_test        */
    TraceroutePreRunTest,          /* pre_run          */
    TracerouteRunTest,             /* run              */
    BWL_TEST_TRACEROUTE,     /* test_types       */
    BWLToolSenderSideData,      /* results_side     */
    True,                    /* supports_server_sends */
    True,                    /* supports_endpointless */
    0,                       /* The server port to use in endpointless tests */
};
