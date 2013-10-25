/*
 *      $Id$
 */
/*
 *	File:		util.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:27:47 MDT 2003
 *
 *	Description:	
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
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>  
#include <sys/types.h>
#include <sys/wait.h>
#include <bwlib/bwlib.h>

#include <sys/socket.h>
#include <netdb.h>

#include "bwlibP.h"

/*
 * Function:    BWLPortsSetI
 *
 * Description:    
 *              Initialize port-range so the 'next port' function starts
 *              with the given 'i' port. If i is 0, this function initializes
 *              the port-range with a random port (or failing that, uses
 *              the lowest value in the port-range).
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
BWLPortsSetI(
        BWLContext      ctx,
        BWLPortRange    prange,
        uint16_t        i
        )
{
    uint16_t    range;

    /*
     * Initialize current port
     */
    if((i != 0) && (i > prange->low) && (i < prange->high)){
        prange->i = i;
    }
    else{
        prange->i = prange->low;
        if( (range = BWLPortsRange(prange))){
            uint32_t    r;

            /*
             * Get a random 32bit num to aid in selecting first port.
             * (Silently fail - it is not that big of a deal if the
             * first port is selected.)
             */
            if(I2RandomBytes(ctx->rand_src,(uint8_t*)&r,4) == 0){
                prange->i = prange->low + ((double)r / 0xffffffff * range);
            }
        }
    }

    return;
}

/*
 * Function:    BWLPortsParse
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
BWLPortsParse(
        BWLContext      ctx,
        const char      *pspec,
        BWLPortRange    prange
        )
{
    char        chmem[BWL_MAX_TOOLNAME];
    char        *tstr,*endptr;
    long        tint;

    if(!pspec || (strlen(pspec) >= sizeof(chmem))){
	BWLError(ctx,BWLErrFATAL,EINVAL,"Invalid port-range: \"%s\"",pspec);
        return False;
    }
    strcpy(chmem,pspec);

    tstr = chmem;
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
    BWLPortsSetI(ctx,prange,0);
    return True;

failed:
    BWLError(ctx,BWLErrFATAL,EINVAL,"Invalid port-range: \"%s\"",pspec);

    return False;
}

uint16_t
BWLPortsNext(
        BWLPortRange   prange
        )
{
    uint16_t    i;

    assert(prange);

    if( !BWLPortsRange(prange)){
        return prange->i;
    }

    /* save i to return */
    i = prange->i;

    /* compute next i */
    prange->i -= prange->low;
    prange->i = (prange->i + 1) % BWLPortsRange(prange);
    prange->i += prange->low;

    return i;
}

char *
BWLUInt64Dup(
        BWLContext  ctx,
        uint64_t    n
        )
 {
    char    nbuf[100];
    int     len;
    char    *ret;

    nbuf[sizeof(nbuf)-1] = '\0';
    len = snprintf(nbuf,sizeof(nbuf)-1,"%llu",(unsigned long long)n);
    if((len < 0) || ((unsigned)len >= sizeof(nbuf))){
        BWLError(ctx,BWLErrFATAL,errno,"snprintf(): %M");
        return NULL;
    }

    if((ret = strdup(nbuf)))
        return ret;

    BWLError(ctx,BWLErrFATAL,errno,"strdup(): %M");
    return NULL;
 }

char *
BWLUInt32Dup(
        BWLContext  ctx,
        uint32_t    n
        )
{
    return BWLUInt64Dup(ctx,(uint64_t)n);
}


char *
BWLDoubleDup(
        BWLContext  ctx,
        double      n
        )
 {
    char    nbuf[100];
    int     len;
    char    *ret;

    nbuf[sizeof(nbuf)-1] = '\0';
    len = snprintf(nbuf,sizeof(nbuf)-1,"%lf",n);
    if((len < 0) || ((unsigned)len >= sizeof(nbuf))){
        BWLError(ctx,BWLErrFATAL,errno,"snprintf(): %M");
        return NULL;
    }

    if((ret = strdup(nbuf)))
        return ret;

    BWLError(ctx,BWLErrFATAL,errno,"strdup(): %M");
    return NULL;
 }

int
ExecCommand(
        BWLContext          ctx,
        char                *output_buf,
        int                 output_buf_size,
        char                *command,
        ...
        )
{
    int      fdpipe[2];
    pid_t    pid;
    int      status;
    int      rc;
    int      i;
    char     **argv;
    va_list  ap;

    /* Count the number of commands so we know how much to allocate */
    va_start(ap, command);
    i = 1;
    while (va_arg(ap, char *) != NULL)
        i++;
    va_end(ap);

    argv = calloc(i + 1, sizeof(char *));
    if(argv == NULL) {
        BWLError(ctx,BWLErrFATAL,errno,"ExecCommand():pipe(): %M");
        return -1;
    }

    i = 1;
    argv[0] = command;

    va_start(ap, command);
    while ((argv[i] = va_arg(ap, char *)) != NULL)
        i++;
    va_end(ap);

    if(pipe(fdpipe) < 0) {
        BWLError(ctx,BWLErrFATAL,errno,"ExecCommand():pipe(): %M");
        return -1;
    }

    pid = fork();

    /* fork error */
    if(pid < 0){
        BWLError(ctx,BWLErrFATAL,errno,"ExecCommand():fork(): %M");
        return -1;
    }

    if(0 == pid){
        char buf[1024];

        /*
         * Redirect stdout/stderr into their respective pipes.
         */
        dup2(fdpipe[1],STDOUT_FILENO);
        dup2(fdpipe[1],STDERR_FILENO);
        close(fdpipe[0]);
        close(fdpipe[1]);

        execvp(command,argv);
        snprintf(buf,sizeof(buf)-1,"ExecCommand(): exec(%s)",command);
        perror(buf);
        exit(1);
    }

    close(fdpipe[1]);

    while(((rc = waitpid(pid,&status,0)) == -1) && errno == EINTR);
    if(rc < 0){
        BWLError(ctx,BWLErrFATAL,errno,
                "ExecCommand(): waitpid(), rc = %d: %M",rc);
        return -1;
    }

    /*
     * If iperf did not even exit...
     */
    if(!WIFEXITED(status)){
        if(WIFSIGNALED(status)){
            BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                    "ExecCommand(): %s exited due to signal=%d",
                    command, WTERMSIG(status));
        }
        BWLError(ctx,BWLErrWARNING,errno,"ExecCommand(): %s unusable", command);
        return -1;
    }

    if (output_buf) {
        /*
         * Read any output from the child
         */
        bzero(output_buf, output_buf_size);
        read(fdpipe[0],output_buf,output_buf_size - 1);
        close(fdpipe[0]);
    }
        
    return WEXITSTATUS(status);
}

char *
BWLAddrNodeName(
        BWLContext ctx,
        I2Addr     addr,
        char      *buf,
        size_t     len,
        int        flags
        )
{
    struct sockaddr *saddr;
    socklen_t       saddrlen;

    if( !(saddr = I2AddrSAddr(addr,&saddrlen))){
        BWLError(ctx,BWLErrFATAL,EINVAL, "I2AddrServName(): Invalid address");
        return NULL;
    }

    if (getnameinfo((struct sockaddr *)saddr, saddrlen, buf, len, 0, 0, flags) != 0) {
        BWLError(ctx,BWLErrFATAL,EINVAL, "I2AddrServName(): Problem resolving address");
        return NULL;
    }

    return buf;
}

BWLBoolean
BWLAddrIsIPv6(
        BWLContext ctx,
        I2Addr     addr
        )
{
    struct sockaddr *saddr;
    socklen_t       saddrlen;
    BWLBoolean      retval;

    if( !(saddr = I2AddrSAddr(addr,&saddrlen))){
        BWLError(ctx,BWLErrFATAL,EINVAL, "I2AddrServName(): Invalid address");
        return False;
    }

    retval = False;

#ifdef    AF_INET6
    if (saddr->sa_family == AF_INET6) {
        retval = True;
    }
#endif

    return retval;
}
