/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabs-mode: nil -*-
 *      $Id$
 */
/*
 *    File:         nuttcp.c
 *
 *    Author:       Jeff W. Boote
 *                  Internet2
 *
 *    Date:         Thu Dec 27 15:31:29 MST 2007
 *
 *    Description:    
 *
 *    This file encapsulates the functionality required to run an
 *    nuttcp throughput tool in bwctl.
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

/*
 * Function:    NuttcpAvailable
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
NuttcpAvailable(
        BWLContext          ctx,
        BWLToolDefinition   tool
        )
{
    char            confkey[BWL_MAX_TOOLNAME + 10];
    int             len;
    char            *cmd;
    int             fdpipe[2];
    pid_t           pid;
    int             status;
    int             rc;
                    /* We expect 'nuttcp -V' to print to stdout something like
                    'nuttcp-.3.1' */
    char            *pattern = "nuttcp-"; /* Expected begin of stdout */
    char            buf[PATH_MAX];
    const uint32_t  buf_size = I2Number(buf);

    /*
     * Build conf-key name that is used to store the tool cmd
     */
    strcpy(confkey,"V.");
    strncat(confkey,tool->name,sizeof(confkey));
    len = strlen(confkey);
    strncpy(&confkey[len],"_cmd",sizeof(confkey)-len);

    /*
     * Fetch 'tool' name
     */
    if( !(cmd = (char *)BWLContextConfigGetV(ctx,confkey))){
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                "NuttcpAvailable(): %s unset, using \"%s\"",
                "nuttcp_cmd",tool->def_cmd);
        cmd = tool->def_cmd;
    }

    /*
     * nuttcp is quite weird regarding exit codes and output.
     *
     * 'nuttcp -v' and 'nuttcp -h exit 1!
     * Also, the output of 'nuttcp -v' and 'nuttcp -h' go to stderr, not stdout
     *
     */
    if(socketpair(AF_UNIX,SOCK_STREAM,0,fdpipe) < 0){
        BWLError(ctx,BWLErrFATAL,errno,"NuttcpAvailable():socketpair(): %M");
        return False;
    }

    pid = fork();

    /* fork error */
    if(pid < 0){
        BWLError(ctx,BWLErrFATAL,errno,"NuttcpAvailable():fork(): %M");
        return False;
    }

    /*
     * child:
     *
     * Redirect stderr to pipe - then exec nuttcp -v, which should send
     * an identifying version string into the pipe.
     */
    if(0 == pid){
        /* Redirect stderr from nuttcp into fdpipe[1]*/
        dup2(fdpipe[1],STDERR_FILENO);
        dup2(fdpipe[1],STDOUT_FILENO);
        close(fdpipe[0]);
        close(fdpipe[1]);

        execlp(cmd,cmd,"-V",NULL);
        buf[buf_size-1] = '\0';
        snprintf(buf,buf_size-1,"exec(%s)",cmd);
        perror(buf);
        exit(1);
    }

    /*
     * parent:
     *
     * Wait for child to exit, then read the output from the
     * child.
     *
     * XXX: This solution depends on the pipe buffer being large enough
     * to hold the complete output of the nuttcp -v command. (Otherwise
     * nuttcp will block...) This has not been a problem in practice, but
     * a more thourough solution would make sure SIGCHLD will be sent,
     * and wait for either that signal or I/O using select(2).
     *
     * May need to do this eventually anyway, if nuttcp ever starts
     * sending the messages via stdout - then this solution will need
     * to watch for data on both stdout and stderr.
     */

    close(fdpipe[1]);
    while(((rc = waitpid(pid,&status,0)) == -1) && errno == EINTR);
    if(rc < 0){
        BWLError(ctx,BWLErrFATAL,errno,
                "NuttcpAvailable(): waitpid(), rc = %d: %M",rc);
        return False;
    }

    /*
     * If nuttcp did not even exit...
     */
    if(!WIFEXITED(status)){
        if(WIFSIGNALED(status)){
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "NuttcpAvailable(): nuttcp exited due to signal=%d",
                    WTERMSIG(status));
        }
        BWLError(ctx,BWLErrWARNING,errno,"NuttcpAvailable(): nuttcp unusable");
        return False;
    }

    /*
     * Read any output from the child
     */
    buf[0] = '\0';
    if( (rc = read(fdpipe[0],buf,buf_size-1)) > 0){
        /* unsure the string is nul terminated */
        for(len=buf_size;len>rc;len--){
            buf[len-1] = '\0';
        }
    }
    close(fdpipe[0]);

    /*
     * If it exited as expected, check the return string.
     */
    if(WEXITSTATUS(status) == 0){
        if(0 == strncmp(buf,pattern,strlen(pattern))){
            /* nuttcp found! */
            return True;
        }
    } else if (WEXITSTATUS(status) == 1) {
        /* This is what we exit with if the exec fails so it likely means the tool isn't installed. */
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "NuttcpAvailable(): We were unable to verify that nuttcp is working. Likely you do not have it installed. exit status: 1: output: %s", buf);
    } else {
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "NuttcpAvailable(): nuttcp invalid: exit status %d: output:\n%s",
            WEXITSTATUS(status),buf);
    }

    return False;
}

/*
 * Function:    NuttcpPreRunTest
 *
 * Description:    
 *              Does all 'prep' work for running an nuttcp test.
 *
 *              Returns a 'closure' pointer. NULL indicates
 *              failure.
 *              This 'closure' pointer is passed on to the NuttcpRunTest.
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
/* This NuttcpArgs can be a static because it is only used from within a
 * forked process. If bwctl ever goes to threads, this will need to be
 * made thread-local memory.
 */
static char *NuttcpArgs[_BWL_MAX_TOOLARGS*2];
static void *
NuttcpPreRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess
        )
{
    char            confkey[BWL_MAX_TOOLNAME + 10];
    int             len;
    char            *cmd;
    int             a = 0;
    char            recvhost[MAXHOSTNAMELEN];
    size_t          hlen = sizeof(recvhost);
    struct sockaddr *rsaddr;
    socklen_t       rsaddrlen;

    if( !(rsaddr = I2AddrSAddr(tsess->test_spec.receiver,&rsaddrlen))){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "NuttcpPreRunTest: Invalid receiver I2Addr");
        return NULL;
    }
    I2AddrNodeName(tsess->test_spec.receiver,recvhost,&hlen);
    if(!hlen){
        BWLError(tsess->cntrl->ctx,BWLErrFATAL,EINVAL,
                "NuttcpPreRunTest: Invalid receiver I2Addr");
        return NULL;
    }

    /*
     * TODO: Fix this to allow UDP Nuttcp tests.
     */
    if(tsess->test_spec.udp){
        fprintf(tsess->localfp, "bwctl: Server does not currently support Nuttcp UDP connections\n");
        BWLError(ctx,BWLErrDEBUG,BWLErrPOLICY,
                "NuttcpPreRunTest: Do not support Nuttcp UDP connections");
        return NULL;
    }

    /*
     * Build conf-key name that is used to store the tool cmd
     */
    strcpy(confkey,"V.");
    strncat(confkey,tsess->tool->name,sizeof(confkey));
    len = strlen(confkey);
    strncpy(&confkey[len],"_cmd",sizeof(confkey)-len);

    /* Run nuttcp */
    cmd = (char*)BWLContextConfigGetV(ctx,confkey);
    if(!cmd) cmd = tsess->tool->def_cmd;

    /* Figure out arguments. */
    NuttcpArgs[a++] = cmd;
    /* Be verbose */
    NuttcpArgs[a++] = "-vv";
    if(tsess->conf_receiver){
        NuttcpArgs[a++] = "-r";

        if(tsess->test_spec.parallel_streams > 0){
            NuttcpArgs[a++] = "-N";
            NuttcpArgs[a++] = BWLUInt32Dup(ctx,
                    tsess->test_spec.parallel_streams);
        }
    }
    else{
        if(tsess->test_spec.tos){
            NuttcpArgs[a++] = "-c";
            NuttcpArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.tos);
        }
    }

    if(tsess->test_spec.len_buffer){
        NuttcpArgs[a++] = "-l";
        NuttcpArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.len_buffer);
    }

    NuttcpArgs[a++] = "-p";
    NuttcpArgs[a++] = BWLUInt32Dup(ctx,tsess->tool_port);

    if(tsess->test_spec.udp){
        NuttcpArgs[a++] = "-u";
        if((!tsess->conf_receiver) && (tsess->test_spec.bandwidth)){
            NuttcpArgs[a++] = "-R";
            /* nuttcp expects a number of Kbytes. */
            NuttcpArgs[a++] = BWLUInt64Dup(ctx,
                    tsess->test_spec.bandwidth / 1024);
        }
    }

    if(tsess->test_spec.window_size){
        NuttcpArgs[a++] = "-w";
        /* nuttcp expects a number of Kbytes. */
        NuttcpArgs[a++] = BWLUInt32Dup(ctx,
                tsess->test_spec.window_size / 1024);
    }

    NuttcpArgs[a++] = "-T";
    NuttcpArgs[a++] = BWLUInt32Dup(ctx,tsess->test_spec.duration);

    /* tsess->test_spec.report_interval (-i) is ignored, as the
       transmitter/receiver mode of nuttcp does not support is.*/

    switch(rsaddr->sa_family){
#ifdef    AF_INET6
        case AF_INET6:
            NuttcpArgs[a++] = "-6";
            break;
#endif
        case AF_INET:
        default:
            break;
    }

    if(!tsess->conf_receiver){
        NuttcpArgs[a++] = "-t";
        if( !(NuttcpArgs[a++] = strdup(recvhost))){
            BWLError(tsess->cntrl->ctx,BWLErrFATAL,errno,
                    "NuttcpPreRunTest():strdup(): %M");
            return NULL;
        }
    }

    if(tsess->conf_receiver){
        NuttcpArgs[a++] = "--nofork";
    }

    NuttcpArgs[a++] = NULL;

    /*
     * Report what will be run in the output file
     */
    fprintf(tsess->localfp,"bwctl: exec_line:");
    for(len=0;NuttcpArgs[len];len++){
        fprintf(tsess->localfp," %s",NuttcpArgs[len]);
    }
    fprintf(tsess->localfp,"\n");

    return (void *)NuttcpArgs;
}

/*
 * Function:    NuttcpRunTest
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
NuttcpRunTest(
        BWLContext          ctx,
        BWLTestSession      tsess __attribute__((unused)),
        void                *closure
        )
{
    char    **ipargs = (char **)closure;

    /*
     * Now run nuttcp!
     */
    execvp(ipargs[0],ipargs);

    BWLError(ctx,BWLErrFATAL,errno,"execvp(%s): %M",ipargs[0]);
    exit(BWL_CNTRL_FAILURE);
}

BWLToolDefinitionRec    BWLToolNuttcp = {
    "nuttcp",                /* name             */
    "nuttcp",                /* def_cmd          */
    NULL,                   /* def_server_cmd   */
    5001,                   /* def_port         */
    _BWLToolGenericParse,    /* parse            */
    NuttcpAvailable,         /* tool_avail       */
    _BWLToolGenericInitTest, /* init_test        */
    NuttcpPreRunTest,        /* pre_run          */
    NuttcpRunTest            /* run              */
};
