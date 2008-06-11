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
 *    this functionality in-line within the existant structure. This
 *    file is an effort to refactor that functionality into a more modular,
 *    and hopefully extensible configuration.
 */
#include <bwlib/bwlibP.h>
#include <assert.h>

static BWLToolDefinitionRec BWLToolNone = {
    "",
    NULL,
    NULL,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
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
    {BWL_TOOL_IPERF, &BWLToolIperf},
    {BWL_TOOL_NUTTCP, &BWLToolNuttcp},
    {BWL_TOOL_THRULAY, &BWLToolThrulay},
    {BWL_TOOL_UNDEFINED, &BWLToolNone}
};

BWLBoolean
_BWLToolInitialize(
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

BWLToolType
BWLToolGetID(
        BWLContext  ctx,
        const char  *name
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if( (strncasecmp(ctx->tool_list[i].tool->name,name,
                        strlen(ctx->tool_list[i].tool->name)+1) == 0)){
            return ctx->tool_list[i].id;
        }
    }

    return BWL_TOOL_UNDEFINED;
}

uint32_t
BWLToolGetNumTools(
        BWLContext  ctx
        )
{
    return ctx->tool_list_size;
}

const char *
BWLToolGetNameByID(
        BWLContext  ctx,
        BWLToolType tool_id
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(tool_id == ctx->tool_list[i].id){
            return ctx->tool_list[i].tool->name;
        }
    }

    return NULL;
}

const char *
BWLToolGetNameByIndex(
        BWLContext ctx,
        uint32_t    i
        )
{
    assert(i < ctx->tool_list_size);

    return ctx->tool_list[i].tool->name;
}

int
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
 * This must currently be called from the CheckTestPolicy function
 * that is registered with the daemon. This is because the 'policy'
 * portion of the code needs to succeed before initializing the test,
 * but, the 'policy' portion also wants to know what toolport is
 * actually used and I did not want to add another 'phase' to the
 * policy checking.
 */
BWLErrSeverity
BWLToolInitTest(
        BWLContext  ctx,
        BWLToolType id,
        uint16_t    *toolport
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(ctx->tool_list[i].id == id){
            return ctx->tool_list[i].tool->init_test(ctx,ctx->tool_list[i].tool,
                    toolport);
        }
    }

    /*
     * Arg not found
     */
    return BWLErrFATAL;
}

BWLErrSeverity
_BWLToolLookForTesters(
        BWLContext  ctx
        )
{
    uint32_t    i;

    assert(!ctx->tool_avail);

    for(i=0;i<ctx->tool_list_size;i++){
        if(ctx->tool_list[i].tool->tool_avail(ctx,ctx->tool_list[i].tool)){
            ctx->tool_avail |= ctx->tool_list[i].id;
        }
        else{
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "Couldn't initialize tool \"%s\". Disabling it.",
                    ctx->tool_list[i].tool->name);
        }
    }

    if(!ctx->tool_avail){
        BWLError(ctx,BWLErrFATAL,BWLErrUNSUPPORTED,
                "Unable to initialize *ANY* throughput tools");
        return BWLErrFATAL;
    }

    return BWLErrOK;
}

/*
 * Function:    _BWLToolGetDefinition
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
BWLToolDefinition
_BWLToolGetDefinition(
        BWLContext  ctx,
        BWLToolType id)
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(ctx->tool_list[i].id == id){
            return ctx->tool_list[i].tool;
        }
    }

    /*
     * Arg not found
     */
    return NULL;
}

/*
 * Function:    _BWLToolPreRunTest
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
void *
_BWLToolPreRunTest(
        BWLContext      ctx,
        BWLTestSession  tsess
        )
{
    return tsess->tool->pre_run(ctx,tsess);
}

/*
 * Function:    _BWLToolRunTest
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
void
_BWLToolRunTest(
        BWLContext      ctx,
        BWLTestSession  tsess,
        void            *closure
        )
{
    tsess->tool->run(ctx,tsess,closure);
}

/*
 * Function:    _BWLToolGenericParse
 *
 * Description:    
 *      This function will handle:
 *      ${TOOL}_cmd
 *      ${TOOL}_server_cmd
 *      ${TOOL}_port
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
static int
save_path(
        BWLContext  ctx,
        const char  *key,
        const char  *val
        )
{
    char    optname[BWL_MAX_TOOLNAME + 12];
    char    *str;

    if( !(str = strdup(val))){
        BWLError(ctx,BWLErrFATAL,errno,"strdup(%s): %M",val);
        return -1;
    }
    if( !BWLContextRegisterMemory(ctx,str)){
        BWLError(ctx,BWLErrFATAL,errno,
                "BWLToolGenericParse: BWLContextRegisterMemor(): %M");
        return -1;
    }

    strcpy(optname,"V.");
    strncat(optname,key,sizeof(optname));
    if(BWLContextConfigSet(ctx,optname,str)){
        return 1;
    }

    return -1;
}
static int
save_ports(
        BWLContext      ctx,
        const char      *key,
        BWLPortRangeRec *portrangerec
        )
{
    char            optname[BWL_MAX_TOOLNAME + 12];
    BWLPortRange    ports;

    if( !(ports = calloc(sizeof(BWLPortRangeRec),1))){
        BWLError(ctx,BWLErrFATAL,errno,
                "BWLToolGenericParse: calloc(): %M");
        return -1;
    }
    if( !BWLContextRegisterMemory(ctx,ports)){
        BWLError(ctx,BWLErrFATAL,errno,
                "BWLToolGenericParse: BWLContextRegisterMemor(): %M");
        return -1;
    }
    *ports = *portrangerec;

    strcpy(optname,"V.");
    strncat(optname,key,sizeof(optname));
    if(BWLContextConfigSet(ctx,optname,ports)){
        return 1;
    }

    return -1;
}
int
_BWLToolGenericParse(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        const char          *key,
        const char          *val
        )
{
    char        confkey[BWL_MAX_TOOLNAME + 10];
    uint32_t    len;

    strncpy(confkey,tool->name,sizeof(confkey));
    len = strlen(confkey);

    /*
     * Check each configuration file 'key' that this tool supports, and
     * see if LoadConfig is currently loading one of these.
     */

    strncpy(&confkey[len],"_cmd",sizeof(confkey)-len);
    if(!strncasecmp(key,confkey,strlen(confkey))){
        return save_path(ctx,key,val);
    }

    strncpy(&confkey[len],"_server_cmd",sizeof(confkey)-len);
    if(!strncasecmp(key,confkey,strlen(confkey))){
        return save_path(ctx,key,val);
    }

    strncpy(&confkey[len],"_port",sizeof(confkey)-len);
    if(!strncasecmp(key,confkey,strlen(confkey))){
        BWLPortRangeRec portrange;

        if(!BWLPortsParse(ctx,val,&portrange)){
            BWLError(ctx,BWLErrFATAL,errno,
                    "BWLToolGenericParse: %s: \'%s\' - invalid port range",
                    confkey,val);
            return -1;
        }

        return save_ports(ctx,key,&portrange);
    }

    /* key not handled */

    return 0;
}

/*
 * Function:    _BWLToolGenericInitTest
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
_BWLToolGenericInitTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        uint16_t            *toolport
        )
{
    char            optname[BWL_MAX_TOOLNAME + 12];
    uint32_t        len;
    BWLPortRange    prange=NULL;

    strcpy(optname,"V.");
    strncpy(&optname[2],tool->name,sizeof(optname)-2);
    len = strlen(optname);
    strncpy(&optname[len],"_ports",sizeof(optname)-len);

    if( (prange = (BWLPortRange)BWLContextConfigGetV(ctx,optname))){
        *toolport = BWLPortsNext(prange);
    }
    else{
        *toolport = tool->def_port;
    }

    return BWLErrOK;
}
