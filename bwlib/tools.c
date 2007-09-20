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
#include <bwlib/bwlibP.h>

static BWLToolDefinitionRec BWLToolNone = {
    "",
    NULL
};

/* autoconf seletion of tools here... */
#ifdef  TOOL_IPERF
extern BWLToolDefinitionRec BWLToolIperf;
#else
#define BWLToolIperf    BWLToolNone
#endif

#ifdef  TOOL_NUTTCP
extern BWLToolDefinitionRec BWLToolNuttcp;
#else
#define BWLToolNuttcp    BWLToolNone
#endif

#ifdef  TOOL_THRULAY
extern BWLToolDefinitionRec BWLToolThrulay;
#else
#define BWLToolThrulay    BWLToolNone
#endif

BWLToolRec tool_list[] = {
    {BWL_TOOL_THRULAY, &BWLToolThrulay},
    {BWL_TOOL_NUTTCP, &BWLToolNuttcp},
    {BWL_TOOL_IPERF, &BWLToolIperf}
};

BWLBoolean
BWLToolInitialize(
        BWLContext  ctx
        )
{
    uint32_t    i,m,n;

    /*
     * If there is a reasonable way to 'register' the bit signature for
     * a tool... (Needed for ServerGreeting message.)
     * Then tools could eventually be dynamically registered.
     * Having an 'initialize' function instead of relying on static
     * config makes this a simple extension later.
     */
    m = I2Number(tool_list);
    ctx->tool_list_size = 0;
    n = 0;
    for(i=0;i<m;i++){
        if( strlen(tool_list[i].tool->name)){
            ctx->tool_list_size++;
        }
    }

    if(!ctx->tool_list_size){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"BWLToolInitialize: No tools compiled in");
        return False;
    }

    if( !(ctx->tool_list = calloc(sizeof(BWLToolRec),ctx->tool_list_size))){
        BWLError(ctx,BWLErrFATAL,errno,"BWLToolInitialize: calloc(): %M");
        return False;
    }

    for(i=0,n=0;i<m;i++){
        if( strlen(tool_list[i].tool->name)){
            ctx->tool_list[n++] = tool_list[i];
        }
    }

    return True;
}

BWLBoolean
BWLToolParseArg(
        BWLContext  ctx,
        const char  *key,
        const char  *val
        )
{
    uint32_t    i;
    int         err;

    for(i=0;i<ctx->tool_list_size;i++){
        /* See if this key/val is valid for this tool */
        err = ctx->tool_list[i].tool->parse(ctx,ctx->tool_list[i].tool,key,val);

        /* return success or failure, if recognized */
        if(err){
            return err;
        }
    }

    /*
     * Arg not found
     */
    return False;
}

/*
 * Function:    BWLToolGenericParse
 *
 * Description:    
 *      This function will handle:
 *      ${TOOL}_cmd
 *      ${TOOL}_server_cmd
 *      ${TOOL}_ports
 *
 *      These are common to most tools - so providing a common implementation
 *      is reasonable.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:
 * Returns:    
 * Side Effect:    
 */
int
BWLToolGenericParse(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        const char          *key,
        const char          *val
        )
{
    char        optname[BWL_MAX_TOOLNAME + 10];
    uint32_t    len;

    strcpy(optname,"V.");
    strncat(optname,tool->name,sizeof(optname));
    len = strlen(optname);

    strncpy(&optname[len],"_cmd",sizeof(optname)-len);
    if(!strncasecmp(key,optname,strlen(optname))){
        if(BWLContextConfigSet(ctx,optname,val)){
            return 1;
        }
        else{
            return -1;
        }
    }

    strncpy(&optname[len],"server_cmd",sizeof(optname)-len);
    if(!strncasecmp(key,optname,strlen(optname))){
        if(BWLContextConfigSet(ctx,optname,val)){
            return 1;
        }
        else{
            return -1;
        }
    }

    strncpy(&optname[len],"_ports",sizeof(optname)-len);
    if(!strncasecmp(key,optname,strlen(optname))){
        BWLPortRangeRec portrange;
        BWLPortRange    ports;

        if(!BWLParsePorts(val,&portrange,BWLContextErrHandle(ctx),NULL)){
            BWLError(ctx,BWLErrFATAL,errno,
                        "BWLToolGenericParse: %s: \'%s\' - invalid port range",
                        optname,val);
            return -1;
        }

        if( !(ports = calloc(sizeof(BWLPortRangeRec),1))){
            BWLError(ctx,BWLErrFATAL,errno,
                        "BWLToolGenericParse: calloc(): %M");
            return -1;
        }
        *ports = portrange;

        if(BWLContextConfigSet(ctx,optname,ports)){
            return 1;
        }
        else{
            return -1;
        }
    }

    return 0;
}
