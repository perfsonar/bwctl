/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id$
 */
/************************************************************************
*                                                                       *
*                           Copyright (C)  2007                         *
*                               Internet2                               *
*                           All Rights Reserved                         *
*                                                                       *
************************************************************************/
/*
 *    File:         iperf.c
 *
 *    Author:       Jeff W. Boote
 *                  Internet2
 *
 *    Date:         Mon Sep 03 12:42:26 MDT 2007
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run an
 *    iperf throughput tool in bwctl.
 */
#include <bwlib/bwlibP.h>

/*
 * Function:    IperfAvailable
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
IperfAvailable(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    return False;
}
BWLToolDefinitionRec    BWLToolIperf = {
    "iperf",                /* name */
    5001,                   /* def_port */
    BWLToolGenericParse,    /* parse */
    IperfAvailable,         /* tool_avail */
    BWLToolGenericInitTest /* init_test */
};
