/*
 ** ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 **      $Id$
 */
/************************************************************************
 *                                                                       *
 *                       Copyright (C)  2003                             *
 *                           Internet2                                   *
 *                       All Rights Reserved                             *
 *                                                                       *
 ************************************************************************/
/*
 **    File:        api.c
 **
 **    Author:      Jeff W. Boote
 **
 **    Date:        Tue Sep 16 14:24:49 MDT 2003
 **
 **    Description:    
 */
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>

#include "./bwlibP.h"

#ifndef EFTYPE
#define    EFTYPE    ENOSYS
#endif

BWLErrSeverity
BWLAddrFree(
        BWLAddr    addr
        )
{
    BWLErrSeverity    err = BWLErrOK;

    if(!addr)
        return err;

    if(addr->ai){
        if(!addr->ai_free){
            freeaddrinfo(addr->ai);
        }else{
            struct addrinfo    *ai, *next;

            ai = addr->ai;
            while(ai){
                next = ai->ai_next;

                if(ai->ai_addr) free(ai->ai_addr);
                if(ai->ai_canonname) free(ai->ai_canonname);
                free(ai);

                ai = next;
            }
        }
        addr->ai = NULL;
        addr->saddr = NULL;
    }

    if((addr->fd >= 0) && !addr->fd_user){
        if(close(addr->fd) < 0){
            BWLError(addr->ctx,BWLErrWARNING,
                    errno,":close(%d)",addr->fd);
            err = BWLErrWARNING;
        }
    }

    free(addr);

    return err;
}

BWLAddr
_BWLAddrAlloc(
        BWLContext    ctx
        )
{
    BWLAddr    addr = calloc(1,sizeof(struct BWLAddrRec));

    if(!addr){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                ":calloc(1,%d):%M",sizeof(struct BWLAddrRec));
        return NULL;
    }

    addr->ctx = ctx;

    addr->node_set = 0;
    strncpy(addr->node,"unknown",sizeof(addr->node));
    addr->port_set = 0;
    strncpy(addr->port,"unknown",sizeof(addr->port));
    addr->ai_free = 0;
    addr->ai = NULL;

    addr->saddr = NULL;
    addr->saddrlen = 0;

    addr->fd_user = 0;
    addr->fd= -1;

    return addr;
}

static struct addrinfo*
_BWLCopyAddrRec(
        BWLContext              ctx,
        const struct addrinfo   *src
        )
{
    struct addrinfo    *dst = calloc(1,sizeof(struct addrinfo));

    if(!dst){
        BWLError(ctx,BWLErrFATAL,errno,
                ":calloc(1,sizeof(struct addrinfo))");
        return NULL;
    }

    *dst = *src;

    if(src->ai_addr){
        dst->ai_addr = malloc(src->ai_addrlen);
        if(!dst->ai_addr){
            BWLError(ctx,BWLErrFATAL,errno,
                    "malloc(%u):%s",src->ai_addrlen,
                    strerror(errno));
            free(dst);
            return NULL;
        }
        memcpy(dst->ai_addr,src->ai_addr,src->ai_addrlen);
        dst->ai_addrlen = src->ai_addrlen;
    }
    else
        dst->ai_addrlen = 0;

    if(src->ai_canonname){
        int    len = strlen(src->ai_canonname);

        if(len > MAXHOSTNAMELEN){
            BWLError(ctx,BWLErrWARNING,
                    BWLErrUNKNOWN,
                    ":Invalid canonname!");
            dst->ai_canonname = NULL;
        }else{
            dst->ai_canonname = malloc(sizeof(char)*(len+1));
            if(!dst->ai_canonname){
                BWLError(ctx,BWLErrWARNING,
                        errno,":malloc(sizeof(%d)",len+1);
                dst->ai_canonname = NULL;
            }else
                strcpy(dst->ai_canonname,src->ai_canonname);
        }
    }

    dst->ai_next = NULL;

    return dst;
}

BWLAddr
_BWLAddrCopy(
        BWLAddr from
        )
{
    BWLAddr         to;
    struct addrinfo **aip;
    struct addrinfo *ai;

    if(!from)
        return NULL;

    if( !(to = _BWLAddrAlloc(from->ctx)))
        return NULL;

    if(from->node_set){
        strncpy(to->node,from->node,sizeof(to->node));
        to->node_set = True;
    }

    if(from->port_set){
        strncpy(to->port,from->port,sizeof(to->port));
        to->port_set = True;
    }

    aip = &to->ai;
    ai = from->ai;

    while(ai){
        to->ai_free = 1;
        *aip = _BWLCopyAddrRec(from->ctx,ai);
        if(!*aip){
            BWLAddrFree(to);
            return NULL;
        }
        if(ai->ai_addr == from->saddr){
            to->saddr = (*aip)->ai_addr;
            to->saddrlen = (*aip)->ai_addrlen;
        }

        aip = &(*aip)->ai_next;
        ai = ai->ai_next;
    }

    to->fd = from->fd;

    if(to->fd > -1)
        to->fd_user = True;

    return to;
}

BWLAddr
BWLAddrByNode(
        BWLContext    ctx,
        const char    *node
        )
{
    BWLAddr        addr;
    char        buff[MAXHOSTNAMELEN+1];
    const char    *nptr=node;
    char        *pptr=NULL;
    char        *s1,*s2;

    if(!node)
        return NULL;

    if(!(addr=_BWLAddrAlloc(ctx)))
        return NULL;

    strncpy(buff,node,MAXHOSTNAMELEN);

    /*
     * Pull off port if specified. If syntax doesn't match URL like
     * node:port - ipv6( [node]:port) - then just assume whole string
     * is nodename and let getaddrinfo report problems later.
     * (This service syntax is specified by rfc2396 and rfc2732.)
     */

    /*
     * First try ipv6 syntax since it is more restrictive.
     */
    if( (s1 = strchr(buff,'['))){
        s1++;
        if(strchr(s1,'[')) goto NOPORT;
        if(!(s2 = strchr(s1,']'))) goto NOPORT;
        *s2++='\0';
        if(strchr(s2,']')) goto NOPORT;
        if(*s2++ != ':') goto NOPORT;
        nptr = s1;
        pptr = s2;
    }
    /*
     * Now try ipv4 style.
     */
    else if( (s1 = strchr(buff,':'))){
        *s1++='\0';
        if(strchr(s1,':')) goto NOPORT;
        nptr = buff;
        pptr = s1;
    }


NOPORT:
    /*
     * Set hostname if it was specified.
     */
    if(nptr && strlen(nptr)){
        strncpy(addr->node,nptr,MAXHOSTNAMELEN);
        addr->node_set = 1;
    }

    if(pptr && strlen(pptr)){
        strncpy(addr->port,pptr,MAXHOSTNAMELEN);
        addr->port_set = 1;
    }

    return addr;
}

BWLAddr
BWLAddrByWildcard(
        BWLContext  ctx,
        int         socktype
        )
{
    struct addrinfo    *ai=NULL;
    struct addrinfo    hints;
    BWLAddr        addr;
    int        ai_err;


    memset(&hints,0,sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_PASSIVE;

    if( (ai_err = getaddrinfo(NULL,BWL_CONTROL_SERVICE_NAME,&hints,&ai)!=0)
            || !ai){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "getaddrinfo(): %s",gai_strerror(ai_err));
        return NULL;
    }

    if( !(addr = _BWLAddrAlloc(ctx))){
        freeaddrinfo(ai);
        return NULL;
    }

    addr->ai = ai;

    return addr;
}

/*
 * Function:    BWLAddrBySAddr
 *
 * Description:    
 *     Construct an BWLAddr record given a sockaddr struct.
 *
 * In Args:    
 *              Set socktype == 0 if it doesn't matter. (but realize
 *              this is here because the saddr will probably by used
 *              to create a socket...
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
BWLAddr
BWLAddrBySAddr(
        BWLContext      ctx,
        struct sockaddr *saddr,
        socklen_t       saddrlen,
        int             socktype
        )
{
    BWLAddr               addr;
    struct addrinfo     *ai=NULL;
    int                    gai;
    struct sockaddr_in  v4addr;

    if(!saddr){
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
                "BWLAddrBySAddr: Invalid saddr");
        return NULL;
    }

    switch(saddr->sa_family){
#ifdef    AF_INET6
        struct sockaddr_in6    *v6addr;

        case AF_INET6:
        /*
         * If this is a mapped addr - create a sockaddr_in
         * instead of the sockaddr_in6. (This is so addr
         * matching will work in other parts of the code, and
         * users of v4 will not be confused by security limits
         * on v6 addresses causing problems.)
         */
        v6addr = (struct sockaddr_in6*)saddr;
        if(IN6_IS_ADDR_V4MAPPED(&v6addr->sin6_addr)){
            memset(&v4addr,0,sizeof(v4addr));
#ifdef    HAVE_STRUCT_SOCKADDR_SA_LEN
            v4addr.sin_len = sizeof(v4addr);
#endif
            v4addr.sin_family = AF_INET;
            v4addr.sin_port = v6addr->sin6_port;
            memcpy(&v4addr.sin_addr.s_addr,
                    &v6addr->sin6_addr.s6_addr[12],4);
            saddr = (struct sockaddr*)&v4addr;
            saddrlen = sizeof(v4addr);
        }
#endif
        break;

        /* fall through */
        case AF_INET:
        case AF_UNIX:
        break;

        default:
        BWLError(ctx,BWLErrFATAL,BWLErrINVALID,"Invalid addr family");
        return NULL;
        break;
    }

    if(!(addr = _BWLAddrAlloc(ctx)))
        return NULL;

    if(!(ai = malloc(sizeof(struct addrinfo)))){
        BWLError(addr->ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "malloc():%s",strerror(errno));
        (void)BWLAddrFree(addr);
        return NULL;
    }

    if(!(addr->saddr = malloc(saddrlen))){
        BWLError(addr->ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "malloc():%s",strerror(errno));
        (void)BWLAddrFree(addr);
        (void)free(ai);
        return NULL;
    }
    memcpy(addr->saddr,saddr,saddrlen);
    ai->ai_addr = addr->saddr;
    addr->saddrlen = saddrlen;
    ai->ai_addrlen = saddrlen;

    ai->ai_flags = 0;
    ai->ai_family = saddr->sa_family;
    ai->ai_socktype = socktype;
    ai->ai_protocol = IPPROTO_IP;    /* reasonable default.    */
    ai->ai_canonname = NULL;
    ai->ai_next = NULL;

    addr->ai = ai;
    addr->ai_free = True;
    addr->so_type = socktype;
    addr->so_protocol = IPPROTO_IP;

    if(addr->saddr->sa_family == AF_UNIX){
        strncpy(addr->node,"unixsock",sizeof(addr->node));
        strncpy(addr->port,"unnamed",sizeof(addr->port));
    }
    else if( (gai = getnameinfo(addr->saddr,addr->saddrlen,
                    addr->node,sizeof(addr->node),
                    addr->port,sizeof(addr->port),
                    NI_NUMERICHOST | NI_NUMERICSERV)) != 0){
        BWLError(ctx,BWLErrWARNING,BWLErrUNKNOWN,
                "getnameinfo(): %s",gai_strerror(gai));
        strncpy(addr->node,"unknown",sizeof(addr->node));
        strncpy(addr->port,"unknown",sizeof(addr->port));
    }

    addr->node_set = True;
    addr->port_set = True;

    return addr;
}

BWLAddr
BWLAddrBySockFD(
        BWLContext  ctx,
        int         fd
        )
{
    struct sockaddr_storage sbuff;
    struct sockaddr         *saddr = (struct sockaddr*)&sbuff;
    socklen_t               saddrlen = sizeof(sbuff);
    int                     so_type;
    socklen_t               so_typesize = sizeof(so_type);
    BWLAddr                 addr;

    if(getpeername(fd,(void*)saddr,&saddrlen) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"getsockname(): %M");
        return NULL;
    }

    /*
     * *BSD getsockname returns 0 size for AF_UNIX.
     * fake a sockaddr to describe this.
     */
    if(!saddrlen){
        saddr->sa_family = AF_UNIX;
        /*
         * Set the size of this "fake" sockaddr to include
         * the sa_family member. (and possibly the sa_len member)
         */
        saddrlen = (char*)&saddr->sa_family - (char*)saddr;
        saddrlen += sizeof(saddr->sa_family);
#ifdef    HAVE_STRUCT_SOCKADDR_SA_LEN
        if(saddrlen <= ((char*)&saddr->sa_len - (char*)saddr)){
            saddrlen = (char*)&saddr->sa_len - (char*)saddr;
            saddrlen += sizeof(saddr->sa_len);
        }
        saddr->sa_len = saddrlen;
#endif
    }

    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,
                (void*)&so_type,&so_typesize) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"getsockopt(): %M");
        return NULL;
    }

    addr = BWLAddrBySAddr(ctx,saddr,saddrlen,so_type);
    if(!addr)
        return NULL;

    addr->fd_user = 1;
    addr->fd = fd;

    return addr;
}

BWLAddr
BWLAddrByLocalSockFD(
        BWLContext  ctx,
        int         fd
        )
{
    struct sockaddr_storage sbuff;
    struct sockaddr         *saddr = (struct sockaddr*)&sbuff;
    socklen_t               saddrlen = sizeof(sbuff);
    int                     so_type;
    socklen_t               so_typesize = sizeof(so_type);
    BWLAddr                 addr;

    if(getsockname(fd,(void*)saddr,&saddrlen) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"getsockname(): %M");
        return NULL;
    }

    /*
     * *BSD getsockname returns 0 size for AF_UNIX.
     * fake a sockaddr to describe this.
     */
    if(!saddrlen){
        saddr->sa_family = AF_UNIX;
        /*
         * Set the size of this "fake" sockaddr to include
         * the sa_family member. (and possibly the sa_len member)
         */
        saddrlen = (char*)&saddr->sa_family - (char*)saddr;
        saddrlen += sizeof(saddr->sa_family);
#ifdef    HAVE_STRUCT_SOCKADDR_SA_LEN
        if(saddrlen <= ((char*)&saddr->sa_len - (char*)saddr)){
            saddrlen = (char*)&saddr->sa_len - (char*)saddr;
            saddrlen += sizeof(saddr->sa_len);
        }
        saddr->sa_len = saddrlen;
#endif
    }

    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,
                (void*)&so_type,&so_typesize) != 0){
        BWLError(ctx,BWLErrFATAL,errno,"getsockopt(): %M");
        return NULL;
    }

    addr = BWLAddrBySAddr(ctx,saddr,saddrlen,so_type);
    if(!addr)
        return NULL;

    addr->fd_user = 1;
    addr->fd = fd;

    return addr;
}

/*
 * Function:    BWLAddrByControl
 *
 * Description:    
 *     Create an BWLAddr record for the remote address based upon the
 *     control socket connection. (wrapper for getpeername)
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
BWLAddr
BWLAddrByControl(
        BWLControl    cntrl
        )
{
    BWLAddr addr;

    if(cntrl->remote_addr && cntrl->remote_addr->saddr){
        return BWLAddrBySAddr(cntrl->ctx,
                cntrl->remote_addr->saddr,
                cntrl->remote_addr->saddrlen,
                cntrl->remote_addr->so_type);
    }
    else if(cntrl->sockfd < 0){
        BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                "BWLAddrByControl: No socket");
    }

    if(!(addr = BWLAddrBySockFD(cntrl->ctx,cntrl->sockfd))){
        return NULL;
    }

    /*
     * Remove sockfd - this call was made to get the "address" not to
     * copy the socket itself.
     */
    addr->fd = -1;

    return addr;
}

/*
 * Function:    BWLAddrByLocalControl
 *
 * Description:    
 *     Create an BWLAddr record for the local address based upon the
 *     control socket connection. (This is used to make a test request
 *     to to the same address that the control connection is coming from -
 *     it is very useful when you allow the local connection to wildcard
 *     since the test connection cannot wildcard.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
BWLAddr
BWLAddrByLocalControl(
        BWLControl    cntrl
        )
{
    BWLAddr addr;

    if(cntrl->local_addr && cntrl->local_addr->saddr){
        return BWLAddrBySAddr(cntrl->ctx,
                cntrl->local_addr->saddr,
                cntrl->local_addr->saddrlen,
                cntrl->local_addr->so_type);
    }
    else if(cntrl->sockfd < 0){
        BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                "BWLAddrByLocalControl: No socket");
    }

    if(!(addr = BWLAddrByLocalSockFD(cntrl->ctx,cntrl->sockfd))){
        return NULL;
    }

    /*
     * Remove sockfd - this call was made to get the "address" not to
     * copy the socket itself.
     */
    addr->fd = -1;

    return addr;
}

/*
 * Function:    BWLAddrSetSAddr
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
 *              Does not copy the memory and does not directly free it.
 *              (It is expected that this memory points at the saddr
 *              portion of one of the getaddrinfo structures returned
 *              from BWLAddrAddrInfo.)
 */
BWLBoolean
BWLAddrSetSAddr(
        BWLAddr addr,
        struct sockaddr *saddr,
        socklen_t       saddr_len
        )
{
    if(addr->fd > -1){
        BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,
                "BWLAddrSetSAddr: Addr already associated with socket: %M");
        return False;
    }

    addr->saddr = saddr;
    addr->saddrlen = saddr_len;

    return True;
}

/*
 * Function:    BWLAddrSetFD
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
BWLBoolean
BWLAddrSetFD(
        BWLAddr addr,
        int     fd,
        int     close_on_free
        )
{
    if(!addr)
        return False;

    if((fd > -1) && (fd != addr->fd) && (addr->fd > -1)){
        BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,
                "BWLAddrSetFD: Addr already associated with socket: %M");
        return False;
    }

    addr->fd = fd;
    addr->fd_user = !close_on_free;

    return True;
}

/*
 * Function:    BWLAddrSetPort
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
BWLBoolean
BWLAddrSetPort(
        BWLAddr     addr,
        uint16_t   port
        )
{
    uint16_t   *pptr;

    if(!addr)
        return False;

    if(addr->fd > -1){
        BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,
                "BWLAddrSetPort: Addr already associated with socket: %M");
        return False;
    }

    /*
     * If saddr is already set - than modify the port.
     */
    if(addr->saddr){
        /*
         * decode v4 and v6 sockaddrs.
         */
        switch(addr->saddr->sa_family){
            struct sockaddr_in    *saddr4;
#ifdef    AF_INET6
            struct sockaddr_in6    *saddr6;

            case AF_INET6:
            saddr6 = (struct sockaddr_in6*)addr->saddr;
            pptr = &saddr6->sin6_port;
            break;
#endif
            case AF_INET:
            saddr4 = (struct sockaddr_in*)addr->saddr;
            pptr = &saddr4->sin_port;
            break;
            default:
            BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,
                    "BWLAddrSetPort: Invalid address family");
            return False;
        }
        *pptr = htons(port);

    }

    snprintf(addr->port,sizeof(addr->port),"%u",port);
    addr->port_set = !(port == 0);

    return True;
}

/*
 * Function:    BWLAddrSetSocktype
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
BWLBoolean
BWLAddrSetSocktype(
        BWLAddr     addr,
        int         so_type
        )
{
    if(!addr)
        return False;

    if(addr->so_type == so_type)
        return True;

    if(addr->fd > -1){
        BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,
                "BWLAddrSetSocktype: Addr already associated with socket: %M");
        return False;
    }

    addr->so_type = so_type;

    return True;
}

/*
 * Function:    BWLAddrSetPassive
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
BWLBoolean
BWLAddrSetPassive(
        BWLAddr     addr,
        BWLBoolean  passive
        )
{
    if(!addr)
        return False;

    if(addr->passive == passive)
        return True;

    if(addr->fd > -1){
        BWLError(addr->ctx,BWLErrFATAL,BWLErrINVALID,
                "BWLAddrSetPassive: Addr already associated with socket: %M");
        return False;
    }

    addr->passive = passive;

    return True;
}

int
BWLAddrFD(
        BWLAddr addr
        )
{
    if(!addr || (addr->fd < 0))
        return -1;

    return addr->fd;
}

/*
 * Does not copy the saddr... Don't mess with this memory!
 */
socklen_t
_BWLAddrSAddr(
        BWLAddr         addr,
        struct sockaddr **saddr
        )
{
    if(!addr || !addr->saddr){
        return 0;
    }

    *saddr = addr->saddr;
    return addr->saddrlen;
}

/*
 * Function:    BWLAddrNodeName
 *
 * Description:    
 *              This function gets a char* node name for a given BWLAddr.
 *              The len parameter is an in/out parameter.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
BWLBoolean
BWLAddrNodeName(
        BWLAddr addr,
        char    *buf,
        size_t  *len
        )
{
    size_t  hostlen=0;
    size_t  servlen=0;
    char    *host=NULL;
    char    *serv=NULL;

    assert(buf);
    assert(len);
    assert(*len > 0);

    if(!addr){
        goto bail;
    }

    if(!addr->node_set){
        host = addr->node;
        hostlen = sizeof(addr->node);
    }
    if(!addr->port_set){
        serv = addr->port;
        servlen = sizeof(addr->port);
    }

    if(!addr->node_set && addr->saddr &&
            getnameinfo(addr->saddr,addr->saddrlen,
                host,hostlen,serv,servlen,
                NI_NUMERICHOST|NI_NUMERICSERV) == 0){
        addr->node_set = 1;
        addr->port_set = 1;
    }

    if(addr->node_set){
        *len = MIN(*len,sizeof(addr->node));
        strncpy(buf,addr->node,*len);
        return True;
    }

bail:
    *len = 0;
    buf[0] = '\0';
    return False;
}

/*
 * Function:    BWLAddrNodeService
 *
 * Description:    
 *              This function gets a char* service name for a given BWLAddr.
 *              The len parameter is an in/out parameter.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
BWLBoolean
BWLAddrNodeService(
        BWLAddr addr,
        char    *buf,
        size_t  *len
        )
{
    size_t  hostlen=0;
    size_t  servlen=0;
    char    *host=NULL;
    char    *serv=NULL;
    assert(buf);
    assert(len);
    assert(*len > 0);

    if(!addr){
        goto bail;
    }

    if(!addr->node_set){
        host = addr->node;
        hostlen = sizeof(addr->node);
    }
    if(!addr->port_set){
        serv = addr->port;
        servlen = sizeof(addr->port);
    }

    if(!addr->port_set && addr->saddr &&
            getnameinfo(addr->saddr,addr->saddrlen,
                host,hostlen,serv,servlen,
                NI_NUMERICHOST|NI_NUMERICSERV) == 0){
        addr->node_set = 1;
        addr->port_set = 1;
    }

    if(addr->port_set){
        *len = MIN(*len,sizeof(addr->port));
        strncpy(buf,addr->port,*len);
        return True;
    }

bail:
    *len = 0;
    buf[0] = '\0';
    return False;
}

/*
 * Function:    BWLAddrAddrInfo
 *
 * Description:    
 *
 * In Args:    
 *              def_node:   only used if internal node is not set
 *              def_serv:   only used if internal port not set
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
struct addrinfo
*BWLAddrAddrInfo(
        BWLAddr     addr,
        char        *def_node,
        char        *def_serv
        )
{
    struct addrinfo hints;
    char            *host=NULL;
    char            *port=NULL;
    int             gai;

    if(addr->ai)
        return addr->ai;

    memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_UNSPEC;

    if(addr->so_type){
        hints.ai_socktype = addr->so_type;
    }
    else{
		hints.ai_socktype = SOCK_STREAM;
    }

    if(addr->passive){
        hints.ai_flags = AI_PASSIVE;
    }

    if(addr->node_set && (strncmp(addr->node,"unknown",sizeof(addr->node)))){
        host = addr->node;
    }
    else if(def_node){
        host = def_node;
    }

    if(addr->port_set && (strncmp(addr->port,"unknown",sizeof(addr->port)))){
        port = addr->port;
    }
    else if(def_serv){
        port = def_serv;
    }

    if(((gai = getaddrinfo(host,port,&hints,&addr->ai)) != 0) || !addr->ai){
        BWLError(addr->ctx,BWLErrFATAL,BWLErrUNKNOWN,"getaddrinfo(): %s",
                gai_strerror(gai));
        return NULL;
    }
    addr->ai_free = 0;

    return addr->ai;
}

/*
 * Function:    BWLGetContext
 *
 * Description:    
 *              Returns the context pointer that was referenced when the
 *              given control connection was created.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
BWLContext
BWLGetContext(
        BWLControl  cntrl
        )
{
    return cntrl->ctx;
}

/*
 * Function:    BWLGetMode
 *
 * Description:    
 *              Returns the "mode" of the control connection.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
BWLSessionMode
BWLGetMode(
        BWLControl  cntrl
        )
{
    return cntrl->mode;
}

/*
 * Function:    BWLControlFD
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
int
BWLControlFD(
        BWLControl  cntrl
        )
{
    return cntrl->sockfd;
}

/*
 * Function:    BWLGetRTTBound
 *
 * Description: Returns a very rough estimate of the upper-bound rtt to
 *              the server.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 *         bound or 0 if unavailable
 * Side Effect:    
 */
BWLNum64
BWLGetRTTBound(
        BWLControl  cntrl
        )
{
    return cntrl->rtt_bound;
}

/*
 * Function:    _BWLFailControlSession
 *
 * Description:    
 *              Simple convienience to set the state and return the failure at
 *              the same time.
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
_BWLFailControlSession(
        BWLControl  cntrl,
        int         level
        )
{
    cntrl->state = _BWLStateInvalid;
    return (BWLErrSeverity)level;
}

/*
 * Function:    _BWLTestSessionAlloc
 *
 * Description:    
 *
 * This function is used to allocate/initialize the memory record used
 * to maintain state information about a "configured" test.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 * Side Effect:    
 */
BWLTestSession
_BWLTestSessionAlloc(
        BWLControl  cntrl,
        BWLBoolean  send,
        BWLAddr     sender,
        BWLAddr     receiver,
        uint16_t   recv_port,
        BWLTestSpec *test_spec
        )
{
    BWLTestSession  test;

    /*
     * Address records must exist.
     */
    if(!sender || ! receiver){
        BWLError(cntrl->ctx,BWLErrFATAL,BWLErrINVALID,
                "_BWLTestSessionAlloc:Invalid Addr arg");
        return NULL;
    }

    if(!(test = calloc(1,sizeof(BWLTestSessionRec)))){
        BWLError(cntrl->ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "calloc(1,BWLTestSessionRec): %M");
        return NULL;
    }

    /*
     * Initialize address records and test description record fields.
     */
    test->cntrl = cntrl;
    memcpy(&test->test_spec,test_spec,sizeof(BWLTestSpec));

    /*
     * Overwrite sender/receiver with passed-in values
     */
    test->test_spec.sender = sender;
    test->test_spec.receiver = receiver;

    test->conf_receiver = !send;
    test->conf_sender = !test->conf_receiver;

    if(send){
        test->conf_sender = True;
        test->recv_port = recv_port;
    }
    else{
        test->conf_receiver = True;
        test->recv_port = 0;
    }

    return test;
}

/*
 * Function:    _BWLTestSessionFree
 *
 * Description:    
 *     This function is used to free the memory associated with a "configured"
 *     test session.
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
_BWLTestSessionFree(
        BWLTestSession  tsession,
        BWLAcceptType   aval
        )
{
    BWLErrSeverity  err=BWLErrOK;

    if(!tsession){
        return BWLErrOK;
    }

    /*
     * remove this tsession from the cntrl->tests list.
     */
    if(tsession->cntrl->tests == tsession){
        tsession->cntrl->tests = NULL;
    }

    (void)_BWLEndpointStop(tsession,aval,&err);

    if(tsession->closure){
        _BWLCallTestComplete(tsession,aval);
    }

    BWLAddrFree(tsession->test_spec.sender);
    BWLAddrFree(tsession->test_spec.receiver);

    while(tsession->localfp &&
            (fclose(tsession->localfp) < 0) &&
            (errno == EINTR));
    while(tsession->remotefp &&
            (fclose(tsession->remotefp) < 0) &&
            (errno == EINTR));

    free(tsession);

    return err;
}


/*
 * Function:    _BWLCreateSID
 *
 * Description:    
 *     Generate a "unique" SID from addr(4)/time(8)/random(4) values.
 *
 * In Args:    
 *
 * Out Args:    
 *
 * Scope:    
 * Returns:    
 *     0 on success
 * Side Effect:    
 */
int
_BWLCreateSID(
        BWLTestSession    tsession
        )
{
    uint8_t    *aptr;

#ifdef    AF_INET6
    if(tsession->test_spec.receiver->saddr->sa_family == AF_INET6){
        struct sockaddr_in6    *s6;

        s6 = (struct sockaddr_in6*)tsession->test_spec.receiver->saddr;
        /* point at last 4 bytes of addr */
        aptr = &s6->sin6_addr.s6_addr[12];
    }else
#endif
        if(tsession->test_spec.receiver->saddr->sa_family == AF_INET){
            struct sockaddr_in    *s4;

            s4 = (struct sockaddr_in*)tsession->test_spec.receiver->saddr;
            aptr = (uint8_t*)&s4->sin_addr;
        }
        else{
            BWLError(tsession->cntrl->ctx,BWLErrFATAL,BWLErrUNSUPPORTED,
                    "_BWLCreateSID:Unknown address family");
            return 1;
        }

    memcpy(&tsession->sid[0],aptr,4);

    _BWLEncodeTimeStamp(&tsession->sid[4],&tsession->localtime);

    if(I2RandomBytes(tsession->cntrl->ctx->rand_src,&tsession->sid[12],4)
            != 0){
        return 1;
    }

    return 0;
}

BWLPacketSizeT
BWLTestPayloadSize(
        BWLSessionMode    mode, 
        uint32_t    padding
        )
{
    BWLPacketSizeT msg_size;

    switch (mode) {
        case BWL_MODE_OPEN:
            msg_size = 14;
            break;
        case BWL_MODE_AUTHENTICATED:
        case BWL_MODE_ENCRYPTED:
            msg_size = 32;
            break;
        default:
            return 0;
            /* UNREACHED */
    }

    return msg_size + padding;
}

/* These lengths assume no IP options. */
#define BWL_IP4_HDR_SIZE    20    /* rfc 791 */
#define BWL_IP6_HDR_SIZE    40    /* rfc 2460 */
#define BWL_UDP_HDR_SIZE    8    /* rfc 768 */

/*
 ** Given the protocol family, OWAMP mode and packet padding,
 ** compute the size of resulting full IP packet.
 */
BWLPacketSizeT
BWLTestPacketSize(
        int             af,    /* AF_INET, AF_INET6 */
        BWLSessionMode  mode, 
        uint32_t       padding
        )
{
    BWLPacketSizeT payload_size, header_size;

    switch (af) {
        case AF_INET:
            header_size = BWL_IP4_HDR_SIZE + BWL_UDP_HDR_SIZE;
            break;
        case AF_INET6:
            header_size = BWL_IP6_HDR_SIZE + BWL_UDP_HDR_SIZE;
            break;
        default:
            return 0;
            /* UNREACHED */
    }

    if(!(payload_size = BWLTestPayloadSize(mode,padding)))
        return 0;

    return payload_size + header_size;
}
