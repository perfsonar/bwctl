/*
 **      $Id$
 */
/************************************************************************
 *									*
 *			     Copyright (C)  2003			*
 *				Internet2				*
 *			     All Rights Reserved			*
 *									*
 ************************************************************************/
/*
 **	File:		context.c
 **
 **	Author:		Jeff W. Boote
 **
 **	Date:		Tue Sep 16 14:25:42 MDT 2003
 **
 **	Description:	
 *
 *    License:
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the following copyright notice,
 *       this list of conditions and the disclaimer below.
 * 
 *        Copyright (c) 2003-2008, Internet2
 * 
 *                              All rights reserved.
 * 
 *     * Redistribution in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 *    *  Neither the name of Internet2 nor the names of its contributors may be
 *       used to endorse or promote products derived from this software without
 *       explicit prior written permission.
 * 
 * You are under no obligation whatsoever to provide any enhancements to Internet2,
 * or its contributors.  If you choose to provide your enhancements, or if you
 * choose to otherwise publish or distribute your enhancement, in source code form
 * without contemporaneously requiring end users to enter into a separate written
 * license agreement for such enhancements, then you thereby grant Internet2, its
 * contributors, and its members a non-exclusive, royalty-free, perpetual license
 * to copy, display, install, use, modify, prepare derivative works, incorporate
 * into the software or other computer software, distribute, and sublicense your
 * enhancements or derivative works thereof, in binary and source code form.
 * 
 * DISCLAIMER - THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * “AS IS” AND WITH ALL FAULTS.  THE UNIVERSITY OF DELAWARE, INTERNET2, ITS CONTRI-
 * BUTORS, AND ITS MEMBERS DO NOT IN ANY WAY WARRANT, GUARANTEE, OR ASSUME ANY RES-
 * PONSIBILITY, LIABILITY OR OTHER UNDERTAKING WITH RESPECT TO THE SOFTWARE. ANY E-
 * XPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRAN-
 * TIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT
 * ARE HEREBY DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE,
 * ACCURACY, AND EFFORT IS WITH THE USER THEREOF.  IN NO EVENT SHALL THE COPYRIGHT
 * OWNER, CONTRIBUTORS, OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELO-
 * PMENT, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTIT-
 * UTE GOODS OR SERVICES; REMOVAL OR REINSTALLATION LOSS OF USE, DATA, SAVINGS OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILIT-
 * Y, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHE-
 * RWISE) ARISING IN ANY WAY OUT OF THE USE OR DISTRUBUTION OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */
#include "bwlibP.h"

#include <assert.h>
#include <signal.h>
#include <stdarg.h>


/*
 * Function:	notmuch
 *
 * Description:	
 * 		This is a "do nothing" signal handler. It is in place
 * 		to ensure this process recieves SIGCHLD events.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
static void
notmuch(
        int	signo
       )
{
    switch(signo){
        case SIGCHLD:
            break;
        default:
            abort();
            raise(SIGFPE);
    }
}

/*
 * Function:	BWLContextErrHandle
 *
 * Description:	
 * 	Returns the ErrHandle that was set for this context upon creation.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
I2ErrHandle
BWLContextErrHandle(
        BWLContext	ctx
        )
{
    return ctx->eh;
}

/*
 * Function:    BWLContextSetErrMask
 *
 * Description:    
 *              Used to specify the least severe error level that should 
 *              be printed. To get all errors printed, specify BWLErrOK.
 *              (a level of BWLErrOK specifically means don't print, so
 *              these are NEVER printed anyway.)
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
BWLContextSetErrMask(
        BWLContext      ctx,
        BWLErrSeverity  errmask
        )
{
    ctx->errmaskprio = errmask;

    return;
}

/*
 * Function:    BWLContextErrMask
 *
 * Description:    
 *              Used to retrieve the current error level that will
 *              actually be printed.
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
BWLContextErrMask(
        BWLContext  ctx
        )
{
    return ctx->errmaskprio;
}

typedef union _BWLContextHashValue{
    void        *value;
    void        (*func)(void);
    uint32_t    u32;
    int32_t     i32;
    uint64_t    u64;
    double      dbl;
} _BWLContextHashValue;

struct _BWLContextHashRecord{
    char                    key[_BWL_CONTEXT_MAX_KEYLEN+1];
    _BWLContextHashValue    val;
};

struct _BWLFreeHashRecord{
    BWLContext	ctx;
    I2Table	table;
};

static I2Boolean
free_hash_entries(
        I2Datum	key,
        I2Datum	value,
        void	*app_data
        )
{
    struct _BWLFreeHashRecord	*frec =
        (struct _BWLFreeHashRecord*)app_data;

    /*
     * Delete hash so key.dptr will not be referenced again.
     * (key.dptr is part of value.dptr alloc)
     */
    if(I2HashDelete(frec->table,key) != 0){
        BWLError(frec->ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "Unable to clean out Context hash?");
        return False;
    }

    free(value.dptr);

    return True;
}

static void
freefreelist(
        BWLContextFreeList  *list
        )
{
    uint32_t    i;

    if(!list)
        return;

    freefreelist(list->next);

    for(i=0;i<list->len;i++){
        free(list->list[i]);
    }
    free(list);

    return;
}

void
BWLContextFree(
        BWLContext	ctx
        )
{
    struct _BWLFreeHashRecord	frec; 

    while(ctx->cntrl_list){
        BWLControlClose(ctx->cntrl_list);
    }

    frec.ctx = ctx;
    frec.table = ctx->table;

    if(ctx->table){
        I2HashIterate(ctx->table,free_hash_entries,(void*)&frec);
        I2HashClose(ctx->table);
        ctx->table = NULL;
    }

    if(ctx->rand_src){
        I2RandomSourceClose(ctx->rand_src);
        ctx->rand_src = NULL;
    }

    if(ctx->lib_eh && ctx->eh){
        I2ErrClose(ctx->eh);
        ctx->eh = NULL;
    }

    freefreelist(ctx->flist);
    ctx->flist = NULL;

    free(ctx->tool_list);
    free(ctx);

    return;
}


BWLErrSeverity
BWLControlClose(
        BWLControl cntrl
        )
{
    BWLErrSeverity			err = BWLErrOK;
    BWLErrSeverity			lerr = BWLErrOK;
    struct _BWLFreeHashRecord	frec; 
    BWLControl			*list = &cntrl->ctx->cntrl_list;

    /*
     * remove all test sessions
     */
    while(cntrl->tests){
        lerr = _BWLTestSessionFree(cntrl->tests,BWL_CNTRL_FAILURE);
        err = MIN(err,lerr);
    }

    frec.ctx = cntrl->ctx;
    frec.table = cntrl->table;

    if(cntrl->table){
        I2HashIterate(cntrl->table,free_hash_entries,(void*)&frec);
        I2HashClose(cntrl->table);
    }

    /*
     * Remove cntrl from ctx list.
     */
    while(*list && (*list != cntrl))
        list = &(*list)->next;
    if(*list == cntrl)
        *list = cntrl->next;

    /*
     * these functions will close the control socket if it is open.
     */
    I2AddrFree(cntrl->remote_addr);
    I2AddrFree(cntrl->local_addr);

    free(cntrl);

    return err;
}

BWLControl
_BWLControlAlloc(
        BWLContext      ctx,
        BWLErrSeverity  *err_ret
        )
{
    BWLControl	cntrl;

    if( !(cntrl = calloc(1,sizeof(BWLControlRec)))){
        BWLError(ctx,BWLErrFATAL,errno,
                ":calloc(1,%d)",sizeof(BWLControlRec));
        *err_ret = BWLErrFATAL;
        return NULL;
    }

    /*
     * Init state fields
     */
    cntrl->ctx = ctx;

    /*
     * Initialize control policy state hash.
     */
    if( !(cntrl->table = I2HashInit(ctx->eh,_BWL_CONTEXT_TABLE_SIZE,
                    NULL,NULL))){
        *err_ret = BWLErrFATAL;
        free(cntrl);
        return NULL;
    }

    /*
     * Init addr fields
     */
    cntrl->sockfd = -1;

    /*
     * Init I/O fields
     */
    cntrl->retn_on_intr = (int *)BWLContextConfigGetV(ctx,BWLInterruptIO);

    /*
     * Init encryption fields
     */
    memset(cntrl->userid_buffer,'\0',sizeof(cntrl->userid_buffer));

    /*
     * Put this control record on the ctx list.
     */
    cntrl->next = ctx->cntrl_list;
    ctx->cntrl_list = cntrl;

    return cntrl;
}

static BWLBoolean
ConfigSetU(
        I2Table	                table,
        const char              *key,
        _BWLContextHashValue    val
        )
{
    struct _BWLContextHashRecord    *rec,*trec;
    I2Datum			    k,v,t;

    assert(table);
    assert(key);
    assert(strlen(key) < _BWL_CONTEXT_MAX_KEYLEN);

    if(!(rec = calloc(1,sizeof(struct _BWLContextHashRecord)))){
        return False;
    }
    /* ensure nul byte */
    rec->key[_BWL_CONTEXT_MAX_KEYLEN] = '\0';

    /* set key datum */
    strncpy(rec->key,key,_BWL_CONTEXT_MAX_KEYLEN);
    rec->val = val;

    k.dptr = rec->key;
    k.dsize = strlen(rec->key);

    /* set value datum */
    v.dptr = rec;
    v.dsize = sizeof(rec);

    /*
     * If there is already a key by this entry - free that record.
     */
    if(I2HashFetch(table,k,&t)){
        trec = (struct _BWLContextHashRecord*)t.dptr;
        I2HashDelete(table,k);
        free(trec);
    }

    if(I2HashStore(table,k,v) == 0){
        return True;
    }

    free(rec);
    return False;
}

/*
 * Have to expand the va_arg in-line, so since I don't want to
 * duplicate this code in multilpe stdarg functions, I'm using
 * this ugly macro.
 */
#define ASSIGN_UNION(u,k,l,rc) \
    do{                                             \
        rc = True;                                  \
        if( !strncmp(k,"V.",2)){                    \
            u.value = (void *)va_arg(l, void*);     \
        }                                           \
        else if( !strncmp(k,"F.",2)){               \
            u.func = (BWLFunc)va_arg(l, BWLFunc);   \
        }                                           \
        else if( !strncmp(k,"U32.",4)){             \
            u.u32 = (uint32_t)va_arg(l, uint32_t);  \
        }                                           \
        else if( !strncmp(k,"I32.",4)){             \
            u.i32 = (int32_t)va_arg(l, int32_t);    \
        }                                           \
        else if( !strncmp(k,"U64.",4)){             \
            u.u64 = (int64_t)va_arg(l, uint64_t);   \
        }                                           \
        else if( !strncmp(k,"DBL.",4)){             \
            u.dbl = (double)va_arg(l, double);      \
        }                                           \
        else{                                       \
            rc = False;                             \
        }                                           \
    } while(0)


static BWLBoolean
ConfigSetVA(
        I2Table     table,
        const char  *key,
        va_list     ap
        )
{
    _BWLContextHashValue    val;
    int                     ret;

    ASSIGN_UNION(val,key,ap,ret);

    if(!ret) return False;

    return ConfigSetU(table,key,val);
}

static BWLBoolean
ConfigGetU(
        I2Table	                table,
        const char              *key,
        _BWLContextHashValue    *val
        )
{
    struct _BWLContextHashRecord	*rec;
    I2Datum				k,v;
    char				kval[_BWL_CONTEXT_MAX_KEYLEN+1];

    assert(key);

    kval[_BWL_CONTEXT_MAX_KEYLEN] = '\0';
    strncpy(kval,key,_BWL_CONTEXT_MAX_KEYLEN);
    k.dptr = kval;
    k.dsize = strlen(kval);

    if(!I2HashFetch(table,k,&v)){
        return False;
    }

    rec = (struct _BWLContextHashRecord*)v.dptr;
    *val = rec->val;

    return True;
}

static void *
ConfigGetV(
        I2Table     table,
        const char  *key
        )
{
    _BWLContextHashValue    val;

    if( strncmp(key,"V.",2)){
        errno = EINVAL;
        return NULL;
    }

    if( !ConfigGetU(table,key,&val)){
        return NULL;
    }

    return val.value;
}

static BWLBoolean
ConfigGetU32(
        I2Table     table,
        const char  *key,
        uint32_t    *ui32
        )
{
    _BWLContextHashValue    val;

    if( strncmp(key,"U32.",4)){
        errno = EINVAL;
        return False;
    }

    if( !ConfigGetU(table,key,&val)){
        return False;
    }

    *ui32 = val.u32;

    return True;
}

static BWLFunc
ConfigGetF(
        I2Table     table,
        const char  *key
        )
{
    _BWLContextHashValue    val;

    if( strncmp(key,"F.",2)){
        errno = EINVAL;
        return NULL;
    }

    if( !ConfigGetU(table,key,&val)){
        return NULL;
    }

    return val.func;
}

static BWLBoolean
ConfigGetU64(
        I2Table     table,
        const char  *key,
        uint64_t    *u64
        )
{
    _BWLContextHashValue    val;

    if( strncmp(key,"U64.",4)){
        errno = EINVAL;
        return False;
    }

    if( !ConfigGetU(table,key,&val)){
        return False;
    }

    *u64 = val.u64;

    return True;
}

static BWLBoolean
ConfigGetDbl(
        I2Table     table,
        const char  *key,
        double      *dbl
        )
{
    _BWLContextHashValue    val;

    if( strncmp(key,"DBL.",4)){
        errno = EINVAL;
        return False;
    }

    if( !ConfigGetU(table,key,&val)){
        return False;
    }

    *dbl = val.dbl;

    return True;
}

static BWLBoolean
ConfigDelete(
        I2Table	    table,
        const char  *key
        )
{
    I2Datum	k;
    char	kval[_BWL_CONTEXT_MAX_KEYLEN+1];

    assert(key);

    kval[_BWL_CONTEXT_MAX_KEYLEN] = '\0';
    strncpy(kval,key,_BWL_CONTEXT_MAX_KEYLEN);
    k.dptr = kval;
    k.dsize = strlen(kval);

    if(I2HashDelete(table,k) == 0){
        return True;
    }

    return False;
}

/*
 * Function:	BWLContextCreate
 *
 * Description:	
 * 	This function is used to initialize a "context" for the bwlib
 * 	library. The context is used to define how error reporting
 * 	and other semi-global state should be defined.
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
BWLContextCreate(
        I2ErrHandle	eh,
        ...
        )
{
    struct sigaction    act;
    I2LogImmediateAttr  ia;
    BWLContext          ctx = calloc(1,sizeof(BWLContextRec));
    char                *tmpdir;
    va_list             ap;
    char                *key;

    if(!ctx){
        I2ErrLogP(eh,ENOMEM,": calloc(1,%d): %M",sizeof(BWLContextRec));
        return NULL;
    }

    ctx->errmaskprio = _BWL_DEFAULT_ERRORMASK;

    if(!eh){
        ctx->lib_eh = True;
        ia.line_info = (I2NAME|I2MSG);
        ia.fp = stderr;
        ctx->eh = I2ErrOpen("bwlib",I2ErrLogImmediate,&ia,NULL,NULL);
        if(!ctx->eh){
            BWLError(NULL,BWLErrFATAL,BWLErrUNKNOWN,"Cannot init error module");
            free(ctx);
            return NULL;
        }
    }
    else{
        ctx->lib_eh = False;
        ctx->eh = eh;
    }

    if(!_BWLToolInitialize(ctx)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"Cannot init tools module");
            free(ctx);
            return NULL;
    }

    if( !(ctx->table = I2HashInit(ctx->eh,_BWL_CONTEXT_TABLE_SIZE,NULL,NULL))){
        BWLContextFree(ctx);
        return NULL;
    }

    va_start(ap,eh);
    while( (key = (char *)va_arg(ap, char *)) != NULL){
        _BWLContextHashValue    val;
        int                     ret;

        ASSIGN_UNION(val,key,ap,ret);

        if( !ret || !ConfigSetU(ctx->table,key,val)){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "Unable to set Context value for %s",key);
            BWLContextFree(ctx);
            return NULL;
        }
    }
    va_end(ap);

    if( !(ctx->rand_src = I2RandomSourceInit(ctx->eh,I2RAND_DEV,NULL))){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "Failed to initialize randomness sources");
        BWLContextFree(ctx);
        return NULL;
    }

    if( (tmpdir = getenv("TMPDIR")))
        strncpy(ctx->tmpdir,tmpdir,PATH_MAX);
    else
        strncpy(ctx->tmpdir,_BWL_DEFAULT_TMPDIR,PATH_MAX);

    if(strlen(ctx->tmpdir) + strlen(_BWL_PATH_SEPARATOR) +
            strlen(_BWL_TMPFILEFMT) > PATH_MAX){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN, "TMPDIR too long");
        BWLContextFree(ctx);
        return NULL;
    }

    /*
     * Do NOT exit on SIGPIPE. To defeat this in the least intrusive
     * way only set SIG_IGN if SIGPIPE is currently set to SIG_DFL.
     * Presumably if someone actually set a SIGPIPE handler, they
     * knew what they were doing...
     */
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;
    if(sigaction(SIGPIPE,NULL,&act) != 0){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"sigaction(): %M");
        BWLContextFree(ctx);
        return NULL;
    }
    if(act.sa_handler == SIG_DFL){
        act.sa_handler = SIG_IGN;
        if(sigaction(SIGPIPE,&act,NULL) != 0){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "sigaction(): %M");
            BWLContextFree(ctx);
            return NULL;
        }
    }

    /*
     * This library uses calls to select that are intended to
     * interrupt select in the case of SIGCHLD, so I must
     * ensure that the process is getting SIGCHLD events.
     */
    memset(&act,0,sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    /* fetch current handler */
    if(sigaction(SIGCHLD,NULL,&act) != 0){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,"sigaction(): %M");
        BWLContextFree(ctx);
        return NULL;
    }
    /* If there is no current handler - set a "do nothing" one. */
    if(act.sa_handler == SIG_DFL){
        act.sa_handler = notmuch;
        if(sigaction(SIGCHLD,&act,NULL) != 0){
            BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                    "sigaction(): %M");
            BWLContextFree(ctx);
            return NULL;
        }
    }

    return ctx;
}

BWLBoolean
BWLContextFinalize(
        BWLContext  ctx
        )
{
    if(_BWLInitNTP(ctx) != 0){
        BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
                "Unable to initialize clock interface.");
        return False;
    }

    ctx->valid = True;
    return True;
}

BWLBoolean
BWLContextFindTools(
        BWLContext  ctx
        )
{
    if( _BWLToolLookForTesters(ctx) != BWLErrOK){
        return False;
    }

    return True;
}

/*
 * Function:    BWLContextRegisterMemory
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
BWLContextRegisterMemory(
        BWLContext  ctx,
        void        *ptr
        )
{
    BWLContextFreeList  **flptr;

    assert(ptr);
    assert(ctx);

    /*
     * fwd to the 'last' flist ptr record with room for more.
     */
    for(flptr = &ctx->flist;
            *flptr && (*flptr)->len >= _BWL_CONTEXT_FLIST_SIZE;
            flptr = &((*flptr)->next));

    /*
     * If fwd'd to a null ptr, alloc a new record.
     */
    if( !*flptr){
        if( !(*flptr = calloc(1,sizeof(BWLContextFreeList)))){
            BWLError(ctx,BWLErrWARNING,ENOMEM,
                    "BWLContextRegisterMemory(): calloc(1,%d): %M",
                    sizeof(BWLContextFreeList));
            return False;
        }
    }

    (*flptr)->list[(*flptr)->len++] = ptr;

    return True;
}

/*
 * Function:	BWLContextConfigSet
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
BWLContextConfigSet(
        BWLContext  ctx,
        const char  *key,
        ...
        )
{
    BWLBoolean  ret;
    va_list     ap;

    assert(ctx);

    va_start(ap,key);
    ret = ConfigSetVA(ctx->table,key,ap);
    va_end(ap);

    return ret;
}

void *
BWLContextConfigGetV(
        BWLContext  ctx,
        const char  *key
        )
{
    assert(ctx);

    return ConfigGetV(ctx->table,key);
}

BWLFunc
BWLContextConfigGetF(
        BWLContext  ctx,
        const char  *key
        )
{
    assert(ctx);

    return ConfigGetF(ctx->table,key);
}

BWLBoolean
BWLContextConfigGetU32(
        BWLContext  ctx,
        const char  *key,
        uint32_t    *ui32
        )
{
    assert(ctx);

    return ConfigGetU32(ctx->table,key,ui32);
}

BWLBoolean
BWLContextConfigGetU64(
        BWLContext  ctx,
        const char  *key,
        uint64_t    *u64
        )
{
    assert(ctx);

    return ConfigGetU64(ctx->table,key,u64);
}

BWLBoolean
BWLContextConfigGetDbl(
        BWLContext  ctx,
        const char  *key,
        double      *dbl
        )
{
    assert(ctx);

    return ConfigGetDbl(ctx->table,key,dbl);
}

BWLBoolean
BWLContextConfigDelete(
        BWLContext  ctx,
        const char  *key
        )
{
    assert(ctx);

    return ConfigDelete(ctx->table,key);
}

/*
 * Function:	BWLControlConfigSet
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
BWLControlConfigSet(
        BWLControl  cntrl,
        const char  *key,
        ...
        )
{
    BWLBoolean  ret;
    va_list     ap;

    assert(cntrl);

    va_start(ap,key);
    ret = ConfigSetVA(cntrl->table,key,ap);
    va_end(ap);

    return ret;
}

void *
BWLControlConfigGetV(
        BWLControl  cntrl,
        const char  *key
        )
{
    assert(cntrl);

    return ConfigGetV(cntrl->table,key);
}

BWLFunc
BWLControlConfigGetF(
        BWLControl  cntrl,
        const char  *key
        )
{
    assert(cntrl);

    return ConfigGetF(cntrl->table,key);
}

BWLBoolean
BWLControlConfigGetU32(
        BWLControl  cntrl,
        const char  *key,
        uint32_t    *ui32
        )
{
    assert(cntrl);

    return ConfigGetU32(cntrl->table,key,ui32);
}

BWLBoolean
BWLControlConfigGetU64(
        BWLControl  cntrl,
        const char  *key,
        uint64_t    *u64
        )
{
    assert(cntrl);

    return ConfigGetU64(cntrl->table,key,u64);
}

BWLBoolean
BWLControlConfigGetDbl(
        BWLControl  cntrl,
        const char  *key,
        double      *dbl
        )
{
    assert(cntrl);

    return ConfigGetDbl(cntrl->table,key,dbl);
}

BWLBoolean
BWLControlConfigDelete(
        BWLControl  cntrl,
        const char  *key
        )
{
    assert(cntrl);

    return ConfigDelete(cntrl->table,key);
}

/*
 * Function:	_BWLCallGetAESKey
 *
 * Description:
 * 	Calls the get_key function that is defined by the application.
 * 	If the application didn't define the get_key function, then provide
 * 	the default response of False.
 */
BWLBoolean
_BWLCallGetAESKey(
        BWLContext	ctx,		/* library context	*/
        const BWLUserID userid,		/* identifies key	*/
        uint8_t	        *key_ret,	/* key - return		*/
        BWLErrSeverity	*err_ret	/* error - return	*/
        )
{
    BWLGetAESKeyFunc	func;

    *err_ret = BWLErrOK;

    func = (BWLGetAESKeyFunc)BWLContextConfigGetF(ctx,BWLGetAESKey);

    /*
     * Default action is no encryption support.
     */
    if(!func){
        return False;
    }

    return func(ctx,userid,key_ret,err_ret);
}

/*
 * Function:	_BWLCallCheckControlPolicy
 *
 * Description:
 * 	Calls the check_control_func that is defined by the application.
 * 	If the application didn't define the check_control_func, then provide
 * 	the default response of True(allowed).
 */
BWLBoolean
_BWLCallCheckControlPolicy(
        BWLControl	cntrl,		/* control record		*/
        BWLSessionMode	mode,		/* requested mode       	*/
        const BWLUserID	userid,		/* key identity			*/
        struct sockaddr	*local_sa_addr,	/* local addr or NULL		*/
        struct sockaddr	*remote_sa_addr,/* remote addr			*/
        BWLErrSeverity	*err_ret	/* error - return		*/
        )
{
    BWLCheckControlPolicyFunc	func;

    *err_ret = BWLErrOK;

    func = (BWLCheckControlPolicyFunc)BWLContextConfigGetF(cntrl->ctx,
            BWLCheckControlPolicy);

    /*
     * Default action is to allow anything.
     */
    if(!func){
        return True;
    }

    return func(cntrl,mode,userid,local_sa_addr,remote_sa_addr,err_ret);
}

/*
 * Function:	_BWLCallCheckTestPolicy
 *
 * Description:
 * 	Calls the check_test_func that is defined by the application.
 * 	If the application didn't define the check_test_func, then provide
 * 	the default response of True(allowed).
 */
BWLBoolean
_BWLCallCheckTestPolicy(
        BWLControl	cntrl,		/* control handle		*/
        BWLTestSession	tsess,
        BWLErrSeverity	*err_ret	/* error - return		*/
        )
{
    BWLCheckTestPolicyFunc  func;
    struct sockaddr         *lsaddr;
    struct sockaddr         *rsaddr;
    socklen_t               lsaddrlen;
    socklen_t               rsaddrlen;

    *err_ret = BWLErrOK;

    func = (BWLCheckTestPolicyFunc)BWLContextConfigGetF(cntrl->ctx,
            BWLCheckTestPolicy);
    /*
     * Default action is to fail since the function needs to
     * return the reservation time and the port for the test.
     */
    if(!func){
        return False;
    }

    if(tsess->conf_sender){
        lsaddr = I2AddrSAddr(tsess->test_spec.sender,&lsaddrlen);
        rsaddr = I2AddrSAddr(tsess->test_spec.receiver,&rsaddrlen);
    }
    else{
        lsaddr = I2AddrSAddr(tsess->test_spec.receiver,&rsaddrlen);
        rsaddr = I2AddrSAddr(tsess->test_spec.sender,&lsaddrlen);
    }

    return func(cntrl,tsess->sid,tsess->conf_sender,lsaddr,rsaddr,
            lsaddrlen,&tsess->test_spec,tsess->fuzz,&tsess->reserve_time,
            &tsess->tool_port,&tsess->closure,err_ret);
}

/*
 * Function:	_BWLCallTestComplete
 *
 * Description:
 * 	Calls the "BWLTestComplete" that is defined by the application.
 * 	If the application didn't define the "BWLTestComplete" function, then
 * 	this is a no-op.
 *
 * 	The primary use for this hook is to free memory and other resources
 * 	(bandwidth etc...) allocated on behalf of this test.
 */
void
_BWLCallTestComplete(
        BWLTestSession	tsession,
        BWLAcceptType	aval
        )
{
    BWLTestCompleteFunc	func;

    func = (BWLTestCompleteFunc)BWLContextConfigGetF(tsession->cntrl->ctx,
            BWLTestComplete);
    /*
     * Default action is nothing...
     */
    if(!func){
        return;
    }

    func(tsession->cntrl,tsession->closure,aval);

    return;
}

/*
 * Function:	_BWLCallProcessResults
 *
 * Description:
 * 	Calls the BWLProcessResultsFunc that is defined by the application.
 *
 */
BWLErrSeverity
_BWLCallProcessResults(
        BWLTestSession	tsession
        )
{
    BWLProcessResultsFunc	func;

    func = (BWLProcessResultsFunc)BWLContextConfigGetF(tsession->cntrl->ctx,
            BWLProcessResults);
    /*
     * Default action is to do nothing...
     */
    if(!func){
        return BWLErrOK;
    }

    if(tsession->conf_sender){
        return func(tsession->cntrl,True,&tsession->test_spec,
                tsession->localfp,tsession->remotefp);
    }
    else{
        return func(tsession->cntrl,False,&tsession->test_spec,
                tsession->remotefp,tsession->localfp);
    }
}
