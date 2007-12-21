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
    char        confkey[BWL_MAX_TOOLNAME + 10];
    uint32_t    len;
    char        *cmd;
    int         fdpipe[2];
    pid_t       pid;
    int         status;
    int         rc;

    /*
     * Build conf-key name that is used to store the tool cmd
     */
    strncpy(confkey,tool->name,sizeof(confkey));
    len = strlen(confkey);
    strncpy(&confkey[len],"_cmd",sizeof(confkey)-len);

    /*
     * Fetch 'tool' name
     */
    if( !(cmd = (char *)BWLContextConfigGetV(ctx,confkey))){
        cmd = tool->def_cmd;
    }

    /*
     * iperf is quite weird regarding exit codes and output.
     *
     * 'iperf -v' and 'iperf -h exit 1!
     * Also, the output of 'iperf -v' and 'iperf -h' go to stderr, not stdout
     *
     */
    if(socketpair(AF_UNIX,SOCK_STREAM,0,fdpipe) < 0){
        BWLError(ctx,BWLErrFATAL,errno,"IperfAvailable():socketpair(): %M");
        return False;
    }

    pid = fork();

    /* fork error */
    if(pid < 0){
        BWLError(ctx,BWLErrFATAL,errno,"IperfAvailable():fork(): %M");
        return False;
    }

    /*
     * child:
     *
     * Redirect stderr to pipe - then exec iperf -v, which should send
     * an identifying version string into the pipe.
     */
    if(0 == pid){
        /* Redirect stderr from iperf into fdpipe[1]*/
        dup2(fdpipe[1],STDERR_FILENO);
        close(fdpipe[0]);
        close(fdpipe[1]);

        execlp(cmd,cmd,"-v",NULL);
        BWLError(ctx,BWLErrFATAL,errno,"IperfAvailable():execlp(%s): %M",cmd);
        exit(BWL_CNTRL_FAILURE);
    }

    /*
     * parent:
     *
     * Wait for child to exit, then read the output from the
     * child.
     *
     * XXX: This solution depends on the pipe buffer being large enough
     * to hold the complete output of the iperf -v command. (Otherwise
     * iperf will block...) This has not been a problem in practice, but
     * a more thourough solution would make sure SIGCHLD will be sent,
     * and wait for either that signal or I/O using select(2).
     *
     * May need to do this eventually anyway, if iperf ever starts
     * sending the messages via stdout - then this solution will need
     * to watch for data on both stdout and stderr.
     */

    while(((rc = waitpid(pid,&status,0)) == -1) && errno == EINTR);
    if(rc < 0){
        BWLError(ctx,BWLErrFATAL,errno,
                "IperfAvailable(): waitpid(), rc = %d: %M",rc);
        return False;
    }

    /*
     * If iperf did not even exit...
     */
    if(!WIFEXITED(status)){
        if(WIFSIGNALED(status)){
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "IperfAvailable(): iperf exited due to signal=%d",
                    WTERMSIG(status));
        }
        BWLError(ctx,BWLErrWARNING,errno,"IperfAvailable(): iperf unusable");
        return False;
    }

    /*
     * iperf exits with a value of 1 for -v, go figure.
     */
    if(WEXITSTATUS(status) == 1){
        /* We expect 'iperf -v' to print to stderr something like
           'iperf version 2.0.2 (03 May 2005) pthreads' */
        char *pattern = "iperf version "; /* Expected begin. of stderr */
        char buf[80];
        const uint8_t buf_size = I2Number(buf);

        close(fdpipe[1]);
        rc = read(fdpipe[0],buf,buf_size);
        close(fdpipe[0]);
        if(0 == strncmp(buf,pattern,strlen(pattern))){
            /* iperf found! */
            return True;
        }
    }

    BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
            "IperfAvailable(): iperf returns unexpected output: exit status %d",
            WEXITSTATUS(status));

    return False;
}

BWLToolDefinitionRec    BWLToolIperf = {
    "iperf",                /* name */
    "iperf",                /* def_cmd */
    NULL,                   /* def_server_cmd */
    5001,                   /* def_port */
    BWLToolGenericParse,    /* parse */
    IperfAvailable,         /* tool_avail */
    BWLToolGenericInitTest /* init_test */
};
