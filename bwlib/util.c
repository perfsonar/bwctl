/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2003			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		util.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:27:47 MDT 2003
 *
 *	Description:	
 */
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <bwlib/bwlib.h>

#include "bwlibP.h"

/*
 * Function:    BWLParsePorts
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
I2Boolean
BWLParsePorts(
        char            *pspec,
        BWLPortRange    prange,
        BWLPortRange    *prange_ret,
        I2ErrHandle     ehand,
        FILE            *fout
        )
{
    char    *tstr,*endptr;
    long    tint;

    if(!pspec) return False;

    tstr = pspec;
    endptr = NULL;

    while(isspace((int)*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto failed;
    }
    prange->low = (uint16_t)tint;

    while(isspace((int)*endptr)) endptr++;

    switch(*endptr){
        case '\0':
            /* only allow a single value if it is 0 */
            if(prange->low){
                goto failed;
            }
            prange->high = prange->low;
            goto done;
            break;
        case '-':
            endptr++;
            break;
        default:
            goto failed;
    }

    tstr = endptr;
    endptr = NULL;
    while(isspace((int)*tstr)) tstr++;
    tint = strtol(tstr,&endptr,10);
    if(!endptr || (tstr == endptr) || (tint < 0) || (tint > (int)0xffff)){
        goto failed;
    }
    prange->high = (uint16_t)tint;

    if(prange->high < prange->low){
        goto failed;
    }

done:
    /*
     * If ephemeral is specified, shortcut by not setting.
     */
    if(!prange->high && !prange->low)
        return True;

    /*
     * Set.
     */
    *prange_ret = prange;

    return True;

failed:
    if(ehand){
        I2ErrLogP(ehand,EINVAL,"Invalid port-range: \"%s\"",pspec);
    }
    else if(fout){
        fprintf(fout,"Invalid port-range: \"%s\"",pspec);
    }

    return False;
}

BWLTesterAvailability
LookForTesters(BWLContext ctx)
{
    const uint8_t command_size = 80;
    char command[command_size];
    char *tester;
    FILE *command_pipe;
    pid_t pid;
    int rc, status;
    int fdpipe[2];
    BWLTesterAvailability result = 0x00000000;

    /* Check for thrulay (libthrulay availability) */
#if defined(HAVE_LIBTHRULAY) && defined(HAVE_THRULAY_SERVER_H) && defined(HAVE_THRULAY_CLIENT_H)
    result |= BWL_TESTER_THRULAY;
#endif

    /* Check for iperf */
    tester = (char*)BWLContextConfigGet(ctx,BWLIperfCmd);
    if(!tester){
	tester = _BWL_IPERF_CMD;
    }

    /* iperf is quite weird as for exit codes and output. */
    /* 'iperf -v' and 'iperf -h exit 1! */
    /* The output of 'iperf -v' and 'iperf -h' and so on goes to stderr
       and cannot be read through popen! */
    rc = pipe(fdpipe);
    if(0 != rc){
	BWLError(ctx,BWLErrFATAL,errno,"while checking for iperf, pipe(): %M");
    }
    pid = fork();
    if(-1 == pid){
	BWLError(ctx,BWLErrFATAL,errno,"while checking for iperf, fork(): %M");
	exit(BWL_CNTRL_FAILURE);
    }
    else if(0 == pid){
	/* Redirect stderr from iperf */
	dup2(fdpipe[1],2);
	close(fdpipe[0]);
	close(fdpipe[1]);
	execlp(tester,tester,"-v",0);
	BWLError(ctx,BWLErrFATAL,errno,"execlp(%s): %M",tester);
	exit(EXIT_FAILURE);
    }
    else{
	rc = waitpid(pid,&status,0);
	if(rc && WIFEXITED(status)){
	    if(1 == WEXITSTATUS(status)){
		/* We expect 'iperf -v' to print to stderr something like
		   'iperf version 2.0.2 (03 May 2005) pthreads' */
		char *pattern = "iperf version "; /* Expected begin. of stderr */
		const uint8_t buf_size = 80;
		char buf[buf_size];
		
		close(fdpipe[1]);
		rc = read(fdpipe[0],buf,buf_size);
		close(fdpipe[0]);
		if(0 == strncmp(buf,pattern,strlen(pattern))){
		    /* iperf found! */
		    result |= BWL_TESTER_IPERF;
		}
		else{
		    BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
			 "iperf was found but its ouput looks strange");
		}
	    }
	    else{
		BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
			 "iperf not found on this system");
	    }
	}
	else{
	    BWLError(ctx,BWLErrWARNING,errno,
		     "while checking for iperf, waitpid(): %M");
	    exit(BWL_CNTRL_FAILURE);
	}
    }

    /* Check for nuttcp */
    /* We expect 'nuttcp -V' to print to stdout something like
       'nuttcp-5.3.1' */
    tester = (char*)BWLContextConfigGet(ctx,BWLNuttcpCmd);
    if(!tester){
	tester = _BWL_NUTTCP_CMD;
    }
    /* Run 'nuttcp -V' */
    snprintf(command,command_size,"%s -V",tester);
    command_pipe = popen(command,"r");
    if(NULL != command_pipe){
	/* Check output */
	char *pattern = "nuttcp-";        /* Expected beginning of output */
	const uint8_t buf_size = 80;
	char buf[buf_size];

	fgets(buf,buf_size,command_pipe);
	if(0 == strncmp(buf,pattern,strlen(pattern))){
	    /* nuttcp found! */
	    result |= BWL_TESTER_NUTTCP;
	}
	else {
	    BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
		     "nuttcp was not found or its ouput looks strange");
	}
    } else {
	BWLError(ctx,BWLErrWARNING,errno,
		 "while checking for nuttcp, popen(): %M");
	exit(BWL_CNTRL_FAILURE);
    }
    pclose(command_pipe);

    return result;
}
