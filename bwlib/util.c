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
#include <netdb.h>
#include <ifaddrs.h>

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
    char     **argv = NULL;
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
        goto error_out;
    }

    i = 1;
    argv[0] = command;

    va_start(ap, command);
    while ((argv[i] = va_arg(ap, char *)) != NULL)
        i++;
    va_end(ap);

    if(pipe(fdpipe) < 0) {
        BWLError(ctx,BWLErrFATAL,errno,"ExecCommand():pipe(): %M");
        goto error_out;
    }

    pid = fork();

    /* fork error */
    if(pid < 0){
        BWLError(ctx,BWLErrFATAL,errno,"ExecCommand():fork(): %M");
        goto error_out;
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
        goto error_out;
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
        goto error_out;
    }

    if (output_buf) {
        /*
         * Read any output from the child
         */
        bzero(output_buf, output_buf_size);
        read(fdpipe[0],output_buf,output_buf_size - 1);
        close(fdpipe[0]);
    }
        
    free(argv);

    return WEXITSTATUS(status);

error_out:
    if (argv)
        free(argv);
    return -1;
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

char *
BWLDiscoverSourceAddr(
        BWLContext ctx,
        const char *remote_addr,
        const char *local_interface,
        char       *buf,
        size_t     buflen
        )
{
    int rc;
    I2Addr temp_addr;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    char *retval;
    char temp_address[1024];
    size_t temp_address_len;
    char temp_port[10];
    struct sockaddr_storage sbuff;
    socklen_t               saddrlen = sizeof(sbuff);

    // An unorthodox way of parsing the address...
    temp_addr = I2AddrByNode(NULL, remote_addr);
    if (!temp_addr) {
        BWLError(ctx,BWLErrDEBUG,EINVAL, "BWLDiscoverSourceAddr(): Invalid address: I2AddrByNode failed");
        return NULL;
    }

    temp_address_len = sizeof(temp_address);

    remote_addr = I2AddrNodeName(temp_addr, temp_address, &temp_address_len);

    I2AddrFree(temp_addr);

    snprintf(temp_port, sizeof(temp_port), "%d", (rand() % 16000 + 1));

    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    if( BWLContextConfigGetV(ctx,BWLIPv4Only)){
        hints.ai_family = AF_INET;
    }
    else if( BWLContextConfigGetV(ctx,BWLIPv6Only)){
        hints.ai_family = AF_INET6;
    }
    else {
        hints.ai_family = AF_UNSPEC;
    }

    if ((rc = getaddrinfo(remote_addr, temp_port, &hints, &result)) != 0) {
        BWLError(ctx,BWLErrDEBUG,EINVAL, "BWLDiscoverSourceAddr(): Invalid address: %s", gai_strerror(rc));
        return NULL;
    }

    retval = NULL;

    for(rp = result; rp != NULL; rp = rp->ai_next){
        if (local_interface) {
            struct ifaddrs *ifaddr, *ifa;

            if (getifaddrs(&ifaddr) == -1) {
                return NULL;
            }

            for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                if (strcmp(ifa->ifa_name, local_interface) != 0)
                    continue;
    
                if (ifa->ifa_addr == NULL)
                    continue;
    
                if (rp->ai_family != ifa->ifa_addr->sa_family)
                    continue;

	        // This is a hacky method of getting the addrlen. It should match
                // the remote_addrinfo's addrlen.
                if (getnameinfo(ifa->ifa_addr, rp->ai_addrlen, buf, buflen, NULL, 0, NI_NUMERICHOST) == 0) {
                    retval = buf;
                    break;
                }
            }

            freeifaddrs(ifaddr);

            if (retval)
                break;
        }
        else {
            int temp_sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (temp_sd < 0) {
                continue;
            }

            if (connect(temp_sd, rp->ai_addr, rp->ai_addrlen) != 0) {
                close(temp_sd);
                continue;
            }

            if(getsockname(temp_sd,(void*)&sbuff,&saddrlen) == 0){
                if (getnameinfo((struct sockaddr *)&sbuff, saddrlen, buf, buflen, NULL, 0, NI_NUMERICHOST) == 0) {
                    close(temp_sd);
                    retval = buf;
                    break;
                }
            }

            close(temp_sd);
        }
    }

    if (result) {
        freeaddrinfo(result);
    }

    return retval;
}

BWLBoolean
BWLIsInterface(
        const char *interface
        )
{
    BWLBoolean retval;
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        return False;
    }

    retval = False;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, interface) == 0) {
            retval = True;
            break;
        }
    }

    freeifaddrs(ifaddr);

    return retval;
}

BWLBoolean
BWLAddrIsLoopback(
        I2Addr    addr
        )
{
    struct addrinfo *sai;
    struct sockaddr *saddr;
    socklen_t       saddrlen;
    BWLBoolean      retval;

    if((saddr = I2AddrSAddr(addr,&saddrlen))){
        if (I2SockAddrIsLoopback(saddr, saddrlen)) {
            retval = True;
        }
        else {
            retval = False;
        }
    }
    else if ((sai = I2AddrAddrInfo(addr, NULL, NULL))) {
        retval = True;

        while(sai != NULL) {
            if (!I2SockAddrIsLoopback(sai->ai_addr, sai->ai_addrlen)) {
                // It has at least one non-loopback address
                retval = False;
            }

            sai = sai->ai_next;
        }
    }
    else {
        retval = False;
    }

    return retval;
}

BWLBoolean
BWLCntrlIsLocal(
        BWLControl cntrl
        )
{
    BWLBoolean      retval;
    struct ifaddrs  *ifaddr, *ifa;
    struct sockaddr *addr;
    socklen_t       addr_len;

    if (BWLAddrIsLoopback(cntrl->remote_addr)) {
        return True;
    }

    if (getifaddrs(&ifaddr) == -1) {
        return False;
    }

    retval = False;

    addr = I2AddrSAddr(cntrl->remote_addr, &addr_len);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        if (BWLSockaddrCompare(ifa->ifa_addr, addr)) {
            retval = True;
            break;
        }
    }

    freeifaddrs(ifaddr);
 
    return retval;
}

BWLBoolean
BWLSockaddrCompare(
        struct sockaddr *sa,
        struct sockaddr *sb
        )
{
    if (sa->sa_family != sb->sa_family)
        return False;

    /*
     * With IPv6 address structures, assume a non-hostile implementation that
     * stores the address as a contiguous sequence of bits. Any holes in the
     * sequence would invalidate the use of memcmp().
     */
    if (sa->sa_family == AF_INET) {
        if (((struct sockaddr_in *)(sa))->sin_addr.s_addr == ((struct sockaddr_in *)(sb))->sin_addr.s_addr) {
            return True;
        }
#ifdef AF_INET6
    } else if (sa->sa_family == AF_INET6) {
        if (0 == memcmp((char *) &(((struct sockaddr_in6 *)(sa))->sin6_addr),
                         (char *) &(((struct sockaddr_in6 *)(sb))->sin6_addr),
                         sizeof((((struct sockaddr_in6 *)(sa))->sin6_addr)))) {
            return True;
        }
#endif
    }

    return False;
}
