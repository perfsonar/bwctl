/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id: owamp.c 599 2013-08-02 17:27:12Z aaron $
 */
/*
 *    File:         owamp.c
 *
 *    Author:       Aaron Brown
 *                  Internet2
 *
 *    Date:         2013-09-02
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run a
 *    owamp test in bwctl.
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

/*
 * Function:    OwampAvailable
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
OwampAvailable(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    BWLBoolean  owping_available = False;
    BWLBoolean  owampd_available = False;
    char        *owping_cmd;
    char        *owampd_cmd;
    int         n;
    char        buf[1024];

    /*
     * Fetch the 'owping'
     */
    if( !(owping_cmd = (char *)BWLContextConfigGetV(ctx,"V.owamp_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "OwampAvailable(): %s unset, using \"%s\"",
                "owamp_cmd",tool->def_cmd);
        owping_cmd = tool->def_cmd;
    }

    /*
     * Fetch the 'owampd'
     */
    if( !(owampd_cmd = (char *)BWLContextConfigGetV(ctx,"V.owamp_server_cmd"))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "OwampAvailable(): %s unset, using \"%s\"",
                "owamp_server_cmd",tool->def_server_cmd);
        owampd_cmd = tool->def_server_cmd;
    }

    n = ExecCommand(ctx, buf, sizeof(buf), owping_cmd, "-h", NULL);
    if (n == 0) {
        owping_available = True;
    }
    else {
        owping_available = False;
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "OwampAvailable(): Unable to verify that '%s' is working. It may not be installed. exit status: %d: output: %s", owping_cmd, n, buf);
    }


    n = ExecCommand(ctx, buf, sizeof(buf), owampd_cmd, "-h", NULL);
    if (n == 0) {
        owampd_available = True;
    }
    else {
        owampd_available = False;
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "OwampAvailable(): Unable to verify that '%s' is working. It may not be installed. exit status: %d: output: %s", owampd_cmd, n, buf);
    }


    return (owping_available && owampd_available);
}

/*
 * Function:    OwampPreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running an owamp test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the OwampRunTest.
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
/* This OwampArgs can be a static because it is only used from within a
 * forked process. If bwctl ever goes to threads, this will need to be
 * made thread-local memory.
 */
static char *OwampArgs[_BWL_MAX_TOOLARGS*2];
static void *
OwampPreRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess
        )
{
    char            confkey[BWL_MAX_TOOLNAME + 10];
    int             len;
    int             a = 0;
    size_t          hlen;
    struct sockaddr *rsaddr;
    socklen_t       rsaddrlen;
    char            rsaddr_str[INET6_ADDRSTRLEN];
    char            server_str[1024];
    char            *port_range;

    if( !(rsaddr = I2AddrSAddr(tsess->test_spec.server,&rsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "OwampPreRunTest(): Invalid server I2Addr");
        return NULL;
    }

    getnameinfo((struct sockaddr *)rsaddr, rsaddrlen, rsaddr_str, sizeof(rsaddr_str), 0, 0, NI_NUMERICHOST);

    snprintf(server_str, sizeof(server_str), "[%s]:%u", rsaddr_str, tsess->tool_port);

    if(tsess->conf_server){
        char *cmd = (char*)BWLContextConfigGetV(ctx,"V.owampd_cmd");
        if(!cmd) cmd = tsess->tool->def_server_cmd;

        OwampArgs[a++] = cmd;
        OwampArgs[a++] = "-Z";
        OwampArgs[a++] = "-R";
        OwampArgs[a++] = "/tmp";
        OwampArgs[a++] = "-d";
        OwampArgs[a++] = "/tmp";
        OwampArgs[a++] = "-S";
        if( !(OwampArgs[a++] = strdup(server_str))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"OwampPreRunTest():strdup(): %M");
            return NULL;
        }
        port_range = (char*)BWLContextConfigGetV(ctx,"V.owamp_ports");
        if (port_range) {
            OwampArgs[a++] = "-P";
            if( !(OwampArgs[a++] = strdup(port_range))){
                BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"OwampPreRunTest():strdup(): %M");
                return NULL;
            }
        }
    }
    else {
        char *cmd = (char*)BWLContextConfigGetV(ctx,"V.owping_cmd");
        if(!cmd) cmd = tsess->tool->def_cmd;

        OwampArgs[a++] = cmd;

        if (tsess->test_spec.server_sends) {
            OwampArgs[a++] = "-f";
        }
        else {
            OwampArgs[a++] = "-t";
        }

        if(tsess->test_spec.outformat){
            switch((char)tsess->test_spec.outformat){
                case 'M':
                    OwampArgs[a++] = "-M";
                    break;
                case 'R':
                    OwampArgs[a++] = "-R";
                    break;
                default:
                    fprintf(tsess->localfp,
                            "bwctl: tool(owping): Invalid out format (-y) specification '%c'\n",
                            (char)tsess->test_spec.outformat);
                    return NULL;
                    break;
            }
        }

        OwampArgs[a++] = "-c";
        if( !(OwampArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.ping_packet_count))){
            return NULL;
        }

        // XXX: need to divide the interpacket time by 1000
        OwampArgs[a++] = "-i";
        if( !(OwampArgs[a++] = BWLDoubleDup(ctx,(tsess->test_spec.ping_interpacket_time/1000.0)))){
            return NULL;
        }

        if(tsess->test_spec.ping_packet_size){
            OwampArgs[a++] = "-s";
            if( !(OwampArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.ping_packet_size))){
                return NULL;
            }
        }

        if(tsess->test_spec.ping_packet_ttl){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL, "OwampPreRunTest(): owping does not support setting the TTL");
        }

        port_range = (char*)BWLContextConfigGetV(ctx,"V.owamp_ports");
        if (port_range) {
            OwampArgs[a++] = "-P";
            if( !(OwampArgs[a++] = strdup(port_range))){
                BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"OwampPreRunTest():strdup(): %M");
                return NULL;
            }
        }

        if( !(OwampArgs[a++] = strdup(server_str))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,"OwampPreRunTest():strdup(): %M");
            return NULL;
        }

        OwampArgs[a++] = NULL;
    }

    /*
     * Report what will be run in the output file
     */
    fprintf(tsess->localfp,"bwctl: exec_line:");
    for(len=0;OwampArgs[len];len++){
        fprintf(tsess->localfp," %s",OwampArgs[len]);
    }
    fprintf(tsess->localfp,"\n");

    return (void *)OwampArgs;
}

/*
 * Function:    OwampRunTest
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
OwampRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess,
        void                *closure
        )
{
    char    **ipargs = (char **)closure;

    /*
     * Now run owping!
     */
    if(tsess->conf_server && tsess->test_spec.no_server_endpoint){
        // Special case for the owamp server if we're under "no server
        // endpoint" mode.
        sleep(tsess->test_spec.duration);

        exit(0);
    }
    else {
        execvp(ipargs[0],ipargs);
        BWLError(ctx,BWLErrFATAL,errno,"execvp(%s): %M",ipargs[0]);
        exit(BWL_CNTRL_FAILURE);
    }
}

/*
 * Function:    OwampInitTest
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
OwampInitTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        uint16_t            *toolport
        )
{
    char            optname[BWL_MAX_TOOLNAME + 12];
    uint32_t        len;
    BWLPortRange    prange=NULL;

    prange = (BWLPortRange)BWLContextConfigGetV(ctx,"V.owamp_port");

    // If nothing has been specified for this tool, initialize it to a range of
    // 100 ports, starting with the tool's default port. This keeps it from
    // reusing the same port for every request, and potentially colliding.
    if( !prange ) {
        if( prange = calloc(1,sizeof(BWLPortRangeRec))) {
            prange->low  = tool->def_port - 1;
            prange->high = tool->def_port + 100;
            BWLPortsSetI(ctx,prange,tool->def_port);
            BWLContextConfigSet(ctx,optname,prange);
        }
    }

    if( (prange = (BWLPortRange)BWLContextConfigGetV(ctx,optname))){
        *toolport = BWLPortsNext(prange);
    }
    else{
        *toolport = tool->def_port;
    }

    return BWLErrOK;
}

BWLToolDefinitionRec    BWLToolOwamp = {
    "owamp",                  /* name             */
    "owping",                 /* def_cmd          */
    "owampd",                /* def_server_cmd   */
    4000,                    /* def_port         */
    _BWLToolGenericParse,     /* parse            */
    BWLGenericParsePingParameters,    /* parse_request */
    BWLGenericUnparsePingParameters,  /* unparse_request */
    OwampAvailable,           /* tool_avail       */
    OwampInitTest,            /* init_test        */
    OwampPreRunTest,          /* pre_run          */
    OwampRunTest,             /* run              */
    BWL_TEST_LATENCY,        /* test_types       */
    BWLToolClientSideData,      /* results_side     */
    True,                   /* supports_server_sends */
};
