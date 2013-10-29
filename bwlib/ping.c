/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id: ping.c 599 2013-08-02 17:27:12Z aaron $
 */
/*
 *    File:         ping.c
 *
 *    Author:       Aaron Brown
 *                  Internet2
 *
 *    Date:         2013-09-02
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run a
 *    ping test in bwctl.
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

#define PING_DEFAULT_CMD         "ping"
#define PING6_DEFAULT_CMD        "ping6"

/*
 * Function:    PingAvailable
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
PingAvailable(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    BWLBoolean  ping_available = False;
    BWLBoolean  ping6_available = False;
    char        *ping_cmd;
    char        *ping6_cmd;
    int         n;
    char        buf[1024];

    /*
     * Fetch the 'ping'
     */
    if( !(ping_cmd = (char *)BWLContextConfigGetV(ctx,"V.ping_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "PingAvailable(): %s unset, using \"%s\"",
                "ping_cmd",PING_DEFAULT_CMD);
        ping_cmd = PING_DEFAULT_CMD;
    }

    /*
     * Fetch the 'ping6'
     */
    if( !(ping6_cmd = (char *)BWLContextConfigGetV(ctx,"V.ping6_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "PingAvailable(): %s unset, using \"%s\"",
                "ping6_cmd",PING6_DEFAULT_CMD);
        ping6_cmd = PING6_DEFAULT_CMD;
    }

    n = ExecCommand(ctx, buf, sizeof(buf), ping_cmd, "-V", NULL);
    if (n == 0) {
      ping_available = True;
    }
    else {
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "PingAvailable(): Unable to verify that '%s' is working. It may not be installed. exit status: %d: output: %s", ping_cmd, n, buf);
    }

    n = ExecCommand(ctx, buf, sizeof(buf), ping6_cmd, "-V", NULL);
    if (n == 0) {
      ping6_available = True;
    }
    else {
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "PingAvailable(): Unable to verify that '%s' is working. It may not be installed. exit status: %d: output: %s", ping6_cmd, n, buf);
    }

    return (ping_available || ping6_available);
}

/*
 * Function:    PingPreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running an ping test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the PingRunTest.
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
/* This PingArgs can be a static because it is only used from within a
 * forked process. If bwctl ever goes to threads, this will need to be
 * made thread-local memory.
 */
static char *PingArgs[_BWL_MAX_TOOLARGS*2];
static void *
PingPreRunTest(
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
        PingArgs[0] = NULL;
        return (void *)PingArgs;
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
        cmd_variable = "V.ping6_cmd";
        default_cmd = PING6_DEFAULT_CMD;
    }
    else {
        cmd_variable = "V.ping_cmd";
        default_cmd = PING_DEFAULT_CMD;
    }

    /* Run ping */
    cmd = (char*)BWLContextConfigGetV(ctx,cmd_variable);
    if(!cmd) cmd = default_cmd;

    /*
     * First figure out the args for ping
     */
    PingArgs[a++] = cmd;

        // special case. We don't have to do anything, so we just fork a process
        // that waits until killed, or times out after 'duration' seconds.

    PingArgs[a++] = "-c";
    if( !(PingArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.ping_packet_count))){
        return NULL;
    }

    PingArgs[a++] = "-i";
    if( !(PingArgs[a++] = BWLDoubleDup(ctx,(tsess->test_spec.ping_interpacket_time/1000.0)))){
        return NULL;
    }

    if(tsess->test_spec.ping_packet_size){
        PingArgs[a++] = "-s";
        if( !(PingArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.ping_packet_size))){
            return NULL;
        }
    }

    if(tsess->test_spec.ping_packet_ttl){
        PingArgs[a++] = "-t";
        if( !(PingArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.ping_packet_ttl))){
            return NULL;
        }
    }

    // Bind to the specified address
    PingArgs[a++] = "-I";
    if( BWLAddrNodeName(ctx, local_side, addr_str, sizeof(addr_str), NI_NUMERICHOST) == 0) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"PingPreRunTest():Problem resolving address");
        return NULL;
    }

    if( !(PingArgs[a++] = strdup(addr_str))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"PingPreRunTest():strdup(): %M");
        return NULL;
    }

    if( BWLAddrNodeName(ctx, remote_side, addr_str, sizeof(addr_str), NI_NUMERICHOST) == 0) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"PingPreRunTest():Problem resolving address");
        return NULL;
    }

    if( !(PingArgs[a++] = strdup(addr_str))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"PingPreRunTest():strdup(): %M");
        return NULL;
    }

    PingArgs[a++] = NULL;

    /*
     * Report what will be run in the output file
     */
    fprintf(tsess->localfp,"bwctl: exec_line:");
    for(len=0;PingArgs[len];len++){
        fprintf(tsess->localfp," %s",PingArgs[len]);
    }
    fprintf(tsess->localfp,"\n");

    return (void *)PingArgs;
}

/*
 * Function:    PingRunTest
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
PingRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess,
        void                *closure
        )
{
    char    **ipargs = (char **)closure;

    if (ipargs[0] != NULL) {
        /*
         * Now run ping!
         */
        execvp(ipargs[0],ipargs);

        BWLError(ctx,BWLErrFATAL,errno,"execvp(%s): %M",ipargs[0]);
        exit(BWL_CNTRL_FAILURE);
    }

    // Special case for the ping server. There isn't anything for the receive
    // side to run, so just sleep until duration is up.
    sleep(tsess->test_spec.duration);

    exit(0);
}

/*
 * Function:    PingInitTest
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
PingInitTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        uint16_t            *toolport
        )
{
    return BWLErrOK;
}

int
PingParse(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        const char          *key,
        const char          *val
        )
{
    if(!strncasecmp(key,"ping_cmd",strlen(key))){
        return save_path(ctx,key,val);
    }

    if(!strncasecmp(key,"ping6_cmd",strlen(key))){
        return save_path(ctx,key,val);
    }

    return _BWLToolGenericParse(ctx, tool, key, val);
}

BWLToolDefinitionRec    BWLToolPing = {
    "ping",                  /* name             */
    "ping",                  /* def_cmd          */
    NULL,                    /* def_server_cmd   */
    0,                       /* def_port         */
    PingParse,               /* parse            */
    BWLGenericParsePingParameters,    /* parse_request */
    BWLGenericUnparsePingParameters,  /* unparse_request */
    PingAvailable,           /* tool_avail       */
    PingInitTest,            /* init_test        */
    PingPreRunTest,          /* pre_run          */
    PingRunTest,             /* run              */
    BWL_TEST_PING,           /* test_types       */
    BWLToolSenderSideData,      /* results_side     */
    True,                    /* supports_server_sends */
};
