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
 *    File:         tools.c
 *
 *    Author:       Jeff W. Boote
 *                  Internet2
 *
 *    Date:         Fri Aug 31 13:48:52 MDT 2007
 *
 *    Description:    
 *
 *    This file is used to define the current set of understood/known
 *    tester tools for bwctl. Currently there is no way for individuals to
 *    add tools since the existance of a particular test program is
 *    communicated by a bit-field. (It needs to be unique across all
 *    clients/servers.) In the future, the protocol could be
 *    changed to something more extensible (XML messages) at which point
 *    it could be possible to communicate all kinds of extra information
 *    if wanted. (Hey, throughput and memory are cheap these days - might as
 *    well use them. But, this is work for another day.) Each tool would
 *    still need to have a unique identifiable signature, but perhaps the
 *    names 'iperf', 'nuttcp' would be enough... Probably need to include
 *    a version indication as well.
 *
 *    Currently, this is just setup to use the autoconf to compile in specific
 *    tool 'drivers' or not. Additionally, when bwctl[d] is started it
 *    will look to determine which testers are actually available in
 *    the environment to cull-out this list.
 *
 *    Much of the functionality to run multiple tools was initially
 *    developed by Federico Montesino Pauzols as part of a thrulay Google
 *    Summer of Code project mentored by Jeff W. Boote. That effort put
 *    all of this functionality in-line within the existant structure. This
 *    file is an effort to refactor that functionality into a more modular,
 *    and hopefully extensible configuration.
 */
#include <bwlib/drivers.h>

BWLToolDefinitionRec    BWLToolNoneRec = {
    ""
};
BWLToolDefinition   BWLToolNone = &BWLToolNoneRec;

/* autoconf seletion of tools here... */
#ifdef  TOOL_IPERF
extern BWLToolDefinition    BWLToolIperf;
#else
#define BWLToolIperf    BWLToolNone
#endif

#ifdef  TOOL_NUTTCP
extern BWLToolDefinition    BWLToolNuttcp;
#else
#define BWLToolNuttcp    BWLToolNone
#endif

#ifdef  TOOL_THRULAY
extern BWLToolDefinition    BWLToolThrulay;
#else
#define BWLToolThrulay    BWLToolNone
#endif

BWLToolRec tool_list[] = {
    {BWL_TOOL_THRULAY, BWLToolThrulay},
    {BWL_TOOL_NUTTCP, BWLToolNuttcp},
    {BWL_TOOL_IPERF, BWLToolIperf},
    {BWL_TOOL_UNDEFINED, BWLToolNone},
};

