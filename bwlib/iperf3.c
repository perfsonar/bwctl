/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id: iperf3.c 537 2012-08-18 20:00:00Z jef $
 */
/*
 *    File:         iperf3.c
 *
 *    Author:       Jef Poskanzer
 *                  LBNL
 *
 *    Date:         Sat Aug 18 20:06:56 UTC 2012
 *
 *    Description:
 *
 *    This file encapsulates the functionality required to run an
 *    iperf throughput tool in bwctl, using libiperf.
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
#include <iperf_api.h>

/*
 * Function:    Iperf3Available
 *
 * Description:
 *              Tests whether iperf3 is available.  Since this is
 *              determined at configure time, the answer is always 'yes'.
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
    return True;
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
static void *
Iperf3PreRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess
        )
{
    char            recvhost[MAXHOSTNAMELEN];
    char            sendhost[MAXHOSTNAMELEN];
    size_t          hlen;
    struct iperf_test *iperf_test;

    if (BWLAddrNodeName(tsess->cntrl->ctx,tsess->test_spec.server,recvhost,sizeof(recvhost), NI_NUMERICHOST) == NULL) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "Iperf3PreRunTest(): Invalid server I2Addr");
        return NULL;
    }

    if (BWLAddrNodeName(tsess->cntrl->ctx,tsess->test_spec.client,sendhost,sizeof(sendhost), NI_NUMERICHOST) == NULL) {
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "Iperf3PreRunTest(): Invalid client I2Addr");
        return NULL;
    }

    iperf_test = iperf_new_test();

    /* Set defaults. */
    iperf_defaults(iperf_test);

    /* -v verbose flag */
    if (tsess->test_spec.verbose)
        iperf_set_verbose( iperf_test, 1 );

    /* -t test duration in seconds */
    iperf_set_test_duration( iperf_test, tsess->test_spec.duration );

    /* -i reporting interval in seconds */
    if(tsess->test_spec.report_interval){
        iperf_set_test_reporter_interval( iperf_test, tsess->test_spec.report_interval / 1000.0 );
        iperf_set_test_stats_interval( iperf_test, tsess->test_spec.report_interval / 1000.0 );
    }

    /* Set defaults, if UDP test */
    if(tsess->test_spec.udp){
        set_protocol(iperf_test, Pudp);
        iperf_set_test_blksize( iperf_test, DEFAULT_UDP_BLKSIZE );
        /* iperf_test->new_stream = iperf_new_udp_stream; */
    }

    if (tsess->test_spec.bandwidth) {
        iperf_set_test_rate( iperf_test, tsess->test_spec.bandwidth );
    }

    /* -l block size */
    if(tsess->test_spec.len_buffer){
        iperf_set_test_blksize( iperf_test, tsess->test_spec.len_buffer );
    }

    /* -p server port */
    iperf_set_test_server_port( iperf_test, tsess->tool_port );

    /* -w window size in bytes */
    iperf_set_test_socket_bufsize( iperf_test, tsess->test_spec.window_size );

    /* -m parallel test streams */
    if (tsess->test_spec.parallel_streams == 0) {
        iperf_set_test_num_streams( iperf_test, 1 );
    } else {
        iperf_set_test_num_streams( iperf_test, tsess->test_spec.parallel_streams );
    }

    /* -O omit time */
    if (tsess->test_spec.omit != 0)
        iperf_set_test_omit( iperf_test, tsess->test_spec.omit );

    /* -b (busy wait in UDP test) and -D (DSCP value for TOS
       byte): not used for the moment. */
    /* Multicast options not used too. */

    /*
     * XXX: Perhaps these should be validated earlier, in the CheckTest
     * function chain?
     */
    if(tsess->test_spec.units){
        iperf_set_test_unit_format( iperf_test, tsess->test_spec.units );
    }

    if(tsess->test_spec.outformat){
        switch((char)tsess->test_spec.outformat){
            case 'J':
                iperf_set_test_json_output( iperf_test, 1 );
                break;
            default:
                break;
        }
    }

    // set zero-copy to get better performance
    iperf_set_test_zerocopy( iperf_test, 1 );

    if(tsess->conf_server){
        iperf_set_test_role( iperf_test, 's' ); // specify server side
    }else{
        char *drh;
        iperf_set_test_role( iperf_test, 'c' ); // specify client side
        drh = strdup(recvhost);
        if( !drh ){
            BWLError(ctx,BWLErrFATAL,errno,"Iperf3PreRunTest():strdup(): %M");
            return NULL;
        }
        iperf_set_test_server_hostname( iperf_test, drh );

        if (tsess->test_spec.server_sends) {
             iperf_set_test_reverse( iperf_test, 1 );
        }
    }

    return (void *)iperf_test;
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
    struct iperf_test *iperf_test = closure;

    switch (iperf_get_test_role(iperf_test))
    {
        case 's':
            iperf_run_server(iperf_test);
            exit(0);
        case 'c':
            iperf_run_client(iperf_test);
            exit(0);
        default:
            BWLError(ctx,BWLErrFATAL,EINVAL,"invalid iperf test role: %c\n",iperf_get_test_role(iperf_test));
            exit(-1);
    }
}

BWLToolDefinitionRec    BWLToolIperf3 = {
    "iperf3",                /* name             */
    NULL,                    /* def_cmd          */
    NULL,                    /* def_server_cmd   */
    5001,                    /* def_port         */
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
