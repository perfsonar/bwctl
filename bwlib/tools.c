/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id$
 */
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
#include <assert.h>
#include <signal.h>

static BWLBoolean _TasksetAvailable(BWLContext ctx);

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

static taskset_available = True;

/* autoconf seletion of tools here... */

extern BWLToolDefinitionRec BWLToolOwamp;
extern BWLToolDefinitionRec BWLToolPing;
extern BWLToolDefinitionRec BWLToolTraceroute;
extern BWLToolDefinitionRec BWLToolTracepath;
extern BWLToolDefinitionRec BWLToolParisTraceroute;

#ifdef  TOOL_IPERF
extern BWLToolDefinitionRec BWLToolIperf;
#else
#define BWLToolIperf    BWLToolNone
#endif

extern BWLToolDefinitionRec BWLToolIperf3;

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
    {BWL_TOOL_OWAMP,  &BWLToolOwamp},
    {BWL_TOOL_TRACEPATH, &BWLToolTracepath},
    {BWL_TOOL_TRACEROUTE, &BWLToolTraceroute},
    {BWL_TOOL_PARIS_TRACEROUTE, &BWLToolParisTraceroute},
    {BWL_TOOL_PING,  &BWLToolPing},
    {BWL_TOOL_IPERF, &BWLToolIperf},
    {BWL_TOOL_IPERF3, &BWLToolIperf3},
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

BWLTestType
BWLToolGetTestTypesByID(
        BWLContext  ctx,
        BWLToolType tool_id
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(tool_id == ctx->tool_list[i].id){
            return ctx->tool_list[i].tool->test_types;
        }
    }

    return BWL_TEST_UNDEFINED;
}


BWLTestSideData
BWLToolGetResultsSideByID(
        BWLContext  ctx,
        BWLToolType tool_id,
        BWLTestSpec *spec
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(tool_id == ctx->tool_list[i].id){
            return ctx->tool_list[i].tool->results_side(ctx, spec);
        }
    }

    return BWL_DATA_UNKNOWN;
}

BWLBoolean
BWLToolSupportsServerSendByID(
        BWLContext  ctx,
        BWLToolType tool_id
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(tool_id == ctx->tool_list[i].id){
            return ctx->tool_list[i].tool->supports_server_sends;
        }
    }

    return False;
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

BWLTestType
BWLToolGetTestTypesByIndex(
        BWLContext ctx,
        uint32_t    i
        )
{
    assert(i < ctx->tool_list_size);

    return ctx->tool_list[i].tool->test_types;
}


const char *
BWLToolGetToolNames(
        BWLContext ctx,
        BWLToolAvailability tools
        )
{
    static char names[BWL_MAX_TOOLNAME*10]; /* enough to hold all names */
    char unknown[BWL_MAX_TOOLNAME];
    uint32_t tid;
    const char *name;

    names[0] = '\0';
    tid = 1;
    while ( tools != 0 ) {
        if ( tid & tools ) {
            name = BWLToolGetNameByID( ctx, tid );
            if ( name == NULL ) {
                (void) sprintf( unknown, "unknown(id=%x)", tid );
                name = unknown;
            }
            (void) strcat( names, name );
            (void) strcat( names, " " );
        }
        /* Remove tid from the tool mask and go to the next bit. */
        tools &= ~tid;
        tid <<= 1;
    }
    return names;
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

BWLErrSeverity
BWLToolParseRequestParameters(
        BWLToolType         id,
        BWLContext          ctx,
        const uint8_t       *buf,
        BWLTestSpec         *tspec,
        BWLProtocolVersion  protocol_version
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(ctx->tool_list[i].id == id){
            if (ctx->tool_list[i].tool->parse_request) {
                return ctx->tool_list[i].tool->parse_request(ctx,buf,tspec,protocol_version);
            }
            else {
                return BWLErrOK;
            }
        }
    }

    /*
     * Arg not found
     */
    return BWLErrFATAL;
}

BWLErrSeverity
BWLToolUnparseRequestParameters(
        BWLToolType         id,
        BWLContext          ctx,
        uint8_t             *buf,
        BWLTestSpec         *tspec,
        BWLProtocolVersion  protocol_version,
        BWLTestSession      tsession
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(ctx->tool_list[i].id == id){
            if (ctx->tool_list[i].tool->parse_request) {
                return ctx->tool_list[i].tool->unparse_request(ctx,buf,tspec,protocol_version,tsession);
            }
            else {
                return BWLErrOK;
            }
        }
    }

    /*
     * Arg not found
     */
    return BWLErrFATAL;
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

BWLBoolean
BWLToolValidateTest(
        BWLContext  ctx,
        BWLToolType id,
        BWLTestSpec test_spec
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(ctx->tool_list[i].id == id){
            return ctx->tool_list[i].tool->validate_test(ctx,ctx->tool_list[i].tool,
                    test_spec);
        }
    }

    return False;
}

BWLErrSeverity
_BWLToolLookForTesters(
        BWLContext  ctx
        )
{
    uint32_t    i;
    BWLToolAvailability compiled_in;

    assert(!ctx->tool_avail);

    compiled_in = 0;
    for(i=0;i<ctx->tool_list_size;i++){
        compiled_in |= ctx->tool_list[i].id;
    }
    BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
            "Compiled-in tools: %s", BWLToolGetToolNames(ctx,compiled_in));

    for(i=0;i<ctx->tool_list_size;i++){
        char confkey[BWL_MAX_TOOLNAME + 20];

        // Check if the tool is disabled in the configuration file
        snprintf(confkey, sizeof(confkey) - 1, "V.disable_%s", ctx->tool_list[i].tool->name);
        if (BWLContextConfigGetV(ctx,confkey)) {
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "Tool \"%s\" is disabled in the configuration file",
                    ctx->tool_list[i].tool->name);
            continue;
        }

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
                "Unable to initialize *ANY* tools");
        return BWLErrFATAL;
    }

    taskset_available = _TasksetAvailable(ctx);

    BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
            "Available tools: %s", BWLToolGetToolNames(ctx,ctx->tool_avail));

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
 *      disable_${TOOL}
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
    strncat(optname,key,sizeof(optname) - strlen(optname) - 1);
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
    strncat(optname,key,sizeof(optname) - strlen(optname) - 1);
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
    char        confkey[BWL_MAX_TOOLNAME + 20];
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

    snprintf(confkey, sizeof(confkey) - 1, "disable_%s", tool->name);
    if(!strncasecmp(key,confkey,strlen(confkey))){
        return save_path(ctx,key,val);
    }

    snprintf(confkey, sizeof(confkey) - 1, "!disable_%s", tool->name);
    if(!strncasecmp(key,confkey,strlen(confkey))){
        // don't save it, but acknowledge the variable
        return 1;
    }

    snprintf(confkey, sizeof(confkey) - 1, "%s_cpu_affinity", tool->name);
    if(!strncasecmp(key,confkey,strlen(confkey))){
        if (!BWLParseCPUAffinityString(val)) {
            BWLError(ctx,BWLErrFATAL,errno,
                    "BWLToolGenericParse: %s: \'%s\' - invalid cpu affinity string",
                    confkey,val);
            return -1;
        }

        return save_path(ctx,key,val);
    }

    snprintf(confkey, sizeof(confkey) - 1, "test_cpu_affinity");
    if(!strncasecmp(key,confkey,strlen(confkey))){
        if (!BWLParseCPUAffinityString(val)) {
            BWLError(ctx,BWLErrFATAL,errno,
                    "BWLToolGenericParse: %s: \'%s\' - invalid cpu affinity string",
                    confkey,val);
            return -1;
        }

        return save_path(ctx,key,val);
    }

    snprintf(confkey, sizeof(confkey) - 1, "test_port");
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
    strncpy(&optname[len],"_port",sizeof(optname)-len);

    prange = (BWLPortRange)BWLContextConfigGetV(ctx,optname);

    // Check if a default "test_port" range is set
    if( !prange ) {
        prange = (BWLPortRange)BWLContextConfigGetV(ctx,"V.test_port");
    }

    // If nothing has been specified for this tool, initialize it to a range of
    // 100 ports, starting with the tool's default port. This keeps it from
    // reusing the same port for every request, and potentially colliding.
    if( !prange ) {
        prange = calloc(1,sizeof(BWLPortRangeRec));
        if(prange) {
            prange->low  = 5202;
            prange->high = 5900;
            BWLPortsSetI(ctx,prange,5202);
            BWLContextConfigSet(ctx,"V.test_port",prange);
        }
    }

    if( prange ) {
        *toolport = BWLPortsNext(prange);
    }
    else{
        *toolport = tool->def_port;
    }

    return BWLErrOK;
}

BWLTestSideData BWLToolServerSideData(
        BWLContext          ctx,
        BWLTestSpec         *spec
        ) {

     return BWL_DATA_ON_SERVER;
}

BWLTestSideData BWLToolClientSideData(
        BWLContext          ctx,
        BWLTestSpec         *spec
        ) {

     return BWL_DATA_ON_CLIENT;
}

char
BWLToolGetParsableFormatByID(
        BWLContext ctx,
        uint32_t    tool_id
        )
{
    int i;
    for(i=0;i<ctx->tool_list_size;i++){
        if(tool_id == ctx->tool_list[i].id){
            return ctx->tool_list[i].tool->parsable_format;
        }
    }

    return '\0';
}


BWLTestSideData BWLToolSenderSideData(
        BWLContext          ctx,
        BWLTestSpec         *spec
        ) {

     if (spec->server_sends) {
         return BWL_DATA_ON_SERVER;
     }
     else {
         return BWL_DATA_ON_CLIENT;
     }
}

BWLToolAvailability
BWLToolGetCommonTools(
        BWLContext ctx,
        BWLToolAvailability tools_1,
        BWLToolAvailability tools_2,
        BWLTestType test_type
        )
{
    BWLToolAvailability common_tools = tools_1 & tools_2;
    BWLToolAvailability tid;

    for (tid = 1; tid > 0; tid <<= 1) {
        if (BWLToolGetTestTypesByID(ctx, tid) == test_type)
            continue;

        common_tools &= ~tid;
    }

    return common_tools;
}

uint16_t BWLToolStandardTesterPort(
        BWLContext          ctx,
        BWLTestSpec         *spec
        ) {

     if (spec->server_sends) {
         return BWL_DATA_ON_SERVER;
     }
     else {
         return BWL_DATA_ON_CLIENT;
     }
}

uint16_t
BWLToolStandardTesterPortByID(
        BWLContext  ctx,
        BWLToolType tool_id
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(tool_id == ctx->tool_list[i].id){
            return ctx->tool_list[i].tool->standard_tester_port;
        }
    }

    return 0;
}

BWLBoolean
BWLToolSupportsEndpointlessTestsByID(
        BWLContext  ctx,
        BWLToolType tool_id
        )
{
    uint32_t    i;

    for(i=0;i<ctx->tool_list_size;i++){
        if(tool_id == ctx->tool_list[i].id){
            return ctx->tool_list[i].tool->supports_endpointless;
        }
    }

    return False;
}

BWLBoolean
_BWLToolGenericValidateTest(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        BWLTestSpec         test_spec
        )
{
    if (test_spec.server_sends &&
        !tool->supports_server_sends) {
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                "%s does not support firewall mode", tool->name);
        return False;
    }

    if (test_spec.no_server_endpoint &&
        !tool->supports_endpointless) {
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                "%s does not support endpointless tests", tool->name);
        return False;
    }

    return True;
}

BWLBoolean
_BWLToolGenericKillTest(
        BWLContext   ctx,
        pid_t        pid,
        int          force
        ) {
    int signal = force?SIGKILL:SIGTERM;

    if(killpg(pid,signal) == 0){
        return True;
    }
    else if (errno == ESRCH) {
        return True;
    }
    else {
        return False;
    }
}

static BWLBoolean
_TasksetAvailable(
        BWLContext          ctx
        )
{
    int             len;
    char            *cmd;
    char            buf[1024];
    int             n;

    /*
     * Fetch 'tool' name
     */
    if( !(cmd = (char *)BWLContextConfigGetV(ctx,"V.taskset_cmd"))){
        cmd = "taskset";
    }

    n = ExecCommand(ctx, buf, sizeof(buf), cmd, "-h", NULL);
    if(n == 0) {
        return True;
   }

   BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
        "_TasksetAvailable(): Unable to find 'taskset' command. Setting the CPU affinity will not be supported");

   return False;
}

int
BWLToolGenericFillCPUAffinityCommand(
        BWLContext          ctx,
        BWLToolDefinition   tool,
        char **cmdline
        )
{
    char confkey[1024];
    char *cmd, *cpu_affinity;
    int i;

    if (!taskset_available)
        return 0;

    snprintf(confkey, sizeof(confkey) - 1, "V.%s_cpu_affinity", tool->name);
    cpu_affinity = (char*)BWLContextConfigGetV(ctx,confkey);
    if (!cpu_affinity) {
        cpu_affinity = (char*)BWLContextConfigGetV(ctx,"V.test_cpu_affinity");
    }

    if (!cpu_affinity)
        return 0;

    if( !(cmd = (char *)BWLContextConfigGetV(ctx,"V.taskset_cmd"))){
        cmd = "taskset";
    }

    i = 0;

    cmdline[i++] = cmd;
    cmdline[i++] = "-c";
    cmdline[i++] = cpu_affinity;

    return i;
}
