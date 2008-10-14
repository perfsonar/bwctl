/*
 *      $Id$
 */
/*
 *	File:		daemon.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Thu Jan 17 23:03:59 MST 2008
 *
 *	Description:	
 *
 *	This file holds convenience functions that are
 *	used to implement the request broker portion of the
 *	daemon. (This is the portion that the bwctl client also
 *	needs to implement if there is no 'local' bwctld.)
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
#include <stdlib.h>

#include <bwlib/bwlib.h>
#include "bwlibP.h"

/*
 * Function:    BWLDaemonParseArg
 *
 * Description:    
 *              parse options common between client/server for providing
 *              'tester' functionality.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    0 if opt not found, neg if error, pos if success
 * Side Effect:    
 */
int
BWLDaemonParseArg(
        BWLContext  ctx,
        const char  *key,
        char        *val
        )
{
    BWLBoolean  tc;

    if( (tc = BWLToolParseArg(ctx,key,val))){
        return tc;
    }

    if(!strncasecmp(key,"access_priority",16)){
        int prio = I2ErrLogSyslogPriority(val);
        if( (prio < 0) ||
                !BWLContextConfigSet(ctx,BWLAccessPriority,(uint32_t)prio)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN, "Unable to set access_priority: \"%s\"",val);
            return -1;
        }
        return 1;
    }

    if(!strncasecmp(key,"peer_port",10)){
        BWLPortRange    pports;

        if( !(pports = calloc(1,sizeof(BWLPortRangeRec)))){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"calloc(1,%d): %M",sizeof(BWLPortRangeRec));
            return -1;
        }
        if( !BWLPortsParse(ctx,val,pports) ||
                !BWLContextConfigSet(ctx,BWLPeerPortRange,pports)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"Unable to set peer_port");
            return -1;
        }

        if( !BWLContextRegisterMemory(ctx,pports)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"Failed to \"register\" peer_ports cleanup");
            return -1;
        }

        return 1;
    }

    if( !strncasecmp(key,"control_timeout",16)){
        char        *end=NULL;
        uint32_t    tlng;

        errno = 0;
        tlng = strtoul(val,&end,10);
        if((end == val) || (errno == ERANGE)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "Invalid control_timeout value: \"%s\"",val);
            return -1;
        }

        if( !BWLContextConfigSet(ctx,BWLControlTimeout,tlng)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "Unable to set control_timeout: \"%s\"",val);
            return -1;
        }

        return 1;
    }

    if( !strncasecmp(key,"bottleneck_capacity",20)){
        I2numT    bneck;
        if( I2StrToNum(&bneck,val) ||
                !BWLContextConfigSet(ctx,BWLBottleNeckCapacity,bneck)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "Unable to set bottlenect_capacity: \"%s\"",val);
            return -1;
        }

        return 1;

    }

    if( !strncasecmp(key,"sync_fuzz",10)){
        char    *end=NULL;
        double  tdbl;

        errno = 0;
        tdbl = strtod(val,&end);
        if((end == val) || (errno == ERANGE) || (tdbl < 0.0)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "Invalid value sync_fuzz: \"%s\"", val);
            return -1;
        }
        if( !BWLContextConfigSet(ctx,BWLSyncFuzz,tdbl)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "Unable to set sync_fuzz: \"%s\"",val);
            return -1;
        }

        return 1;
    }

    if( !strncasecmp(key,"allow_unsync",13)){
        if( !BWLContextConfigSet(ctx,BWLAllowUnsync,(void*)True)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "Unable to set allow_unsync: \"%s\"",val);
            return -1;
        }

        return 1;
    }

    return 0;
}
