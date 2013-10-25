/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id$
 */
/*
 *    File:         thrulay.c
 *
 *    Author:       Jeff W. Boote
 *                  Internet2
 *
 *    Date:         Mon Sep 03 12:42:26 MDT 2007
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run the
 *    thrulay throughput tool in bwctl.
 *
 *    This file will only be complied in by 'config' if TOOL_THRULAY
 *    is defined.
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
#include <thrulay/client.h>
#include <thrulay/server.h>

/*
 * Function:    ThrulayAvailable
 * 
 * Description:
 *    This file will only be complied in by 'config' if TOOL_THRULAY
 *    is defined. So... The available func always returns True.
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
ThrulayAvailable(
        BWLContext          ctx     __attribute__((unused)),
        BWLToolDefinition   tool    __attribute__((unused))
        )
{
    return True;
}

static thrulay_opt_t thrulay_opt;

/*
 * Function:    ThrulayPreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running a thrulay test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the ThrulayRunTest.
 *
 *              (closure pointer is just non-null value that is not used)
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
static void *
ThrulayPreRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess
        )
{
    char    recvhost[MAXHOSTNAMELEN];
    size_t  hlen;
    int     rc;

    hlen = sizeof(recvhost);
    I2AddrNodeName(tsess->test_spec.server,recvhost,&hlen);
    if(!hlen){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "ThrulayPreRunTest: Invalid server I2Addr");
        return NULL;
    }

    /* -w window size in bytes */
    if(!tsess->test_spec.window_size){
        tsess->test_spec.window_size = THRULAY_DEFAULT_WINDOW;
    }

    /* -m parallel test streams */
    if(tsess->test_spec.parallel_streams < 1){
        tsess->test_spec.parallel_streams = 1;
    }

    if(tsess->conf_server){
        /* Run thrulay server through its API */

        /* Log through stderr and verbose reports. */
        rc = thrulay_server_init(LOGTYPE_STDERR,1);
        if (rc < 0){
            BWLError(ctx,BWLErrFATAL,errno,"Initializing thrulay server: %s",
                    thrulay_server_strerror(rc));
        }

        /*
         * XXX: Make a more informative 'info' message indicating the
         * test that is being done.
         */
        fprintf(tsess->localfp,
                "bwctl: thrulay_server: streams=%d,win_size=%u\n",
                tsess->test_spec.parallel_streams,
                tsess->test_spec.window_size);
    }
    else{
        /* Run thrulay client through its API */

        /* Give default values to the test spec struct */
        thrulay_client_options_init(&thrulay_opt);
        /* But disable output. */
        thrulay_opt.reporting_verbosity = -1;

        if( !(thrulay_opt.server_name = strdup(recvhost))){
            BWLError(ctx,BWLErrFATAL,errno,"ThrulayPreRunTest():strdup(): %M");
            return NULL;
        }

        /* -t test duration in seconds */
        thrulay_opt.test_duration = tsess->test_spec.duration;

        /* -i reporting interval in seconds */
        if(tsess->test_spec.report_interval){
            thrulay_opt.reporting_interval = tsess->test_spec.report_interval;
        }

        /* -l block size */
        if(tsess->test_spec.len_buffer){
            thrulay_opt.block_size = tsess->test_spec.len_buffer;
        }

        /* -p server port */
        thrulay_opt.port = tsess->tool_port;

        /* Rate, if UDP test */
        if(tsess->test_spec.udp){
            thrulay_opt.rate = tsess->test_spec.bandwidth;
        }

        /* -w window size in bytes */
        thrulay_opt.window = tsess->test_spec.window_size;

        /* -m parallel test streams */
        thrulay_opt.num_streams = tsess->test_spec.parallel_streams;


        /* -b (busy wait in UDP test) and -D (DSCP value for TOS
           byte): not used for the moment. */
        /* Multicast options not used too. */

        /*
         * TODO: Fix this to allow UDP Thrulay tests.
         */
        if(tsess->test_spec.udp){
            fprintf(tsess->localfp,
                "bwctl: There are some known problems with using Thrulay and UDP. Only run this if you're debugging the problem.\n");
            BWLError(ctx,BWLErrDEBUG,BWLErrPOLICY,
                "ThrulayPreRunTest: There are some known problems with using Thrulay and UDP. Only run this if you're debugging the problem.\n");
        }

        /*
         * XXX: Make a more informative 'info' message indicating the
         * test that is being done.
         */
        fprintf(tsess->localfp,
                "bwctl: thrulay_client(): protocol=%s, streams=%d,win_size=%u\n"
                "bwctl: thrulay_client(): duration=%d,report_interval=%d\n"
                "bwctl: thrulay_client(): block_size=%d,serv_port=%u,udp_rate=%llu\n",
                ((tsess->test_spec.udp)?"UDP":"TCP"),
                tsess->test_spec.parallel_streams,
                tsess->test_spec.window_size,
                thrulay_opt.test_duration,
                thrulay_opt.reporting_interval,
                thrulay_opt.block_size,
                thrulay_opt.port,
                ((tsess->test_spec.udp)?thrulay_opt.rate:0)
                );
    }

    return (void *)&thrulay_opt;
}

/*
 * Function:    ThrulayRunTest
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
ThrulayRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess,
        void                *closure    __attribute__((unused))
        )
{
    int rc;

    if(tsess->conf_server){
        int     wstatus;
        int     ret=0;
        pid_t   pid;

        /*
         * Now run thrulay server!
         */
        rc = thrulay_server_listen(tsess->tool_port,
                (int)tsess->test_spec.window_size);
        if (rc < 0){
            BWLError(ctx,BWLErrINFO,errno,"Thrulay server listen: %s", 
                    thrulay_server_strerror(rc));
        }
        rc = thrulay_server_start(tsess->test_spec.parallel_streams, NULL);
        if (rc < 0){
            BWLError(ctx,BWLErrINFO,errno,"Thrulay server: %s", 
                    thrulay_server_strerror(rc));
        }

        while(1){
AGAIN:
            pid = waitpid(-1,&wstatus,0);
            switch(pid){
                case 0:
                    BWLError(ctx,BWLErrFATAL,errno,
                            "thrulay_server: waidpid(-1): returned 0");
                    exit(BWL_CNTRL_FAILURE);
                    /* NOTREACHED */
                case -1:
                    if(errno == EINTR) goto AGAIN;
                    if(errno == ECHILD) goto DONE;
                    break;
                default:
                    if(WIFEXITED(wstatus)){
                        ret = MAX(ret,WEXITSTATUS(wstatus));
                        goto AGAIN;
                    }

                    if(WIFSIGNALED(wstatus)){
                        fprintf(tsess->localfp,
                                "bwctl: thrulay_server: stream killed: #%d",
                                WTERMSIG(wstatus));
                        ret = 255;
                        goto DONE;
                    }
            }
        }
DONE:
        exit(ret);
    }
    else{
        /*
         * Now run thrulay client!
         */
        rc = thrulay_client_init(thrulay_opt);
        if (rc < 0){
            BWLError(ctx,BWLErrINFO,errno,"Initializing thrulay client: %s",
                    thrulay_client_strerror(rc));
        }

        rc = thrulay_client_start();
        if (rc < 0){
            BWLError(ctx,BWLErrINFO,errno,"While performing thrulay "
                    "test: %s", thrulay_client_strerror(rc));
        }
        rc = thrulay_client_report_final();
        if (rc < 0){
            BWLError(ctx,BWLErrINFO,errno,"While generating thrulay"
                    " final report: %s", thrulay_client_strerror(rc));
        }
        thrulay_client_exit();
        exit(0);
    }
}


BWLToolDefinitionRec    BWLToolThrulay = {
    "thrulay",              /* name             */
    NULL,                   /* def_cmd          */
    NULL,                   /* def_server_cmd   */
    5003,                   /* def_port         */
    _BWLToolGenericParse,    /* parse            */
    BWLGenericParseThroughputParameters,    /* parse_request */
    BWLGenericUnparseThroughputParameters,  /* unparse_request */
    ThrulayAvailable,       /* tool_avail       */
    _BWLToolGenericInitTest, /* init_test        */
    ThrulayPreRunTest,      /* pre_run          */
    ThrulayRunTest,         /* run              */
    BWL_TEST_THROUGHPUT      /* test_types       */
};
