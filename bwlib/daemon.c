/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2008			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
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
 */
#include <stdlib.h>

#include <bwlib/bwlib.h>
#include "bwlibP.h"

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

    if(!strncasecmp(key,"peerports",10) ||
            !strncasecmp(key,"peer_ports",11)){
        BWLPortRange    pports;

        if( !(pports = calloc(1,sizeof(BWLPortRangeRec)))){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"calloc(1,%d): %M",sizeof(BWLPortRangeRec));
            return -1;
        }
        if( !BWLPortsParse(ctx,val,pports) ||
                !BWLContextConfigSet(ctx,BWLPeerPortRange,pports)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"Unable to set peer_ports");
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
