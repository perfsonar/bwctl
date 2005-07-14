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
*/
#include <assert.h>
#include <signal.h>

#include "bwlibP.h"

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
	I2ErrHandle	eh
)
{
	struct sigaction	act;
	I2LogImmediateAttr	ia;
	BWLContext		ctx = calloc(1,sizeof(BWLContextRec));
	char			*tmpdir;

	if(!ctx){
		BWLError(eh,
			BWLErrFATAL,ENOMEM,":calloc(1,%d): %M",
						sizeof(BWLContextRec));
		return NULL;
	}

	if(!eh){
		ctx->lib_eh = True;
		ia.line_info = (I2NAME|I2MSG);
		ia.fp = stderr;
		ctx->eh = I2ErrOpen("libbwlib",I2ErrLogImmediate,&ia,
				NULL,NULL);
		if(!ctx->eh){
			BWLError(NULL,BWLErrFATAL,BWLErrUNKNOWN,
					"Cannot init error module");
			free(ctx);
			return NULL;
		}
	}
	else{
		ctx->lib_eh = False;
		ctx->eh = eh;
	}

        ctx->access_prio = BWLErrINFO;

	if(_BWLInitNTP(ctx) != 0){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"Unable to initialize clock interface.");
		BWLContextFree(ctx);
		return NULL;
	}

	if( !(ctx->table = I2HashInit(ctx->eh,_BWL_CONTEXT_TABLE_SIZE,
								NULL,NULL))){
		BWLContextFree(ctx);
		return NULL;
	}

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

/*
 * Function:	BWLContextGetErrHandle
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
extern I2ErrHandle
BWLContextGetErrHandle(
	BWLContext	ctx
	)
{
	return ctx->eh;
}

/*
 * Function:    BWLContextSetAccessLogPriority
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
BWLContextSetAccessLogPriority(
        BWLContext  ctx,
        int         prio
        )
{
    ctx->access_prio = prio;

    return;
}

struct _BWLContextHashRecord{
	char	key[_BWL_CONTEXT_MAX_KEYLEN+1];
	void	*value;
};

struct _BWLFreeHashRecord{
	BWLContext	ctx;
	I2Table		table;
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

	free(ctx);

	return;
}

BWLErrSeverity
BWLControlClose(BWLControl cntrl)
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
	lerr = BWLAddrFree(cntrl->remote_addr);
	err = MIN(err,lerr);
	lerr = BWLAddrFree(cntrl->local_addr);
	err = MIN(err,lerr);

	free(cntrl);

	return err;
}

BWLControl
_BWLControlAlloc(
	BWLContext		ctx,
	BWLErrSeverity		*err_ret
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
	cntrl->retn_on_intr = (int *)BWLContextConfigGet(ctx,BWLInterruptIO);

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
ConfigSet(
	I2Table		table,
	const char	*key,
	void		*value
	)
{
	struct _BWLContextHashRecord	*rec,*trec;
	I2Datum				k,v,t;

	assert(table);
	assert(key);

	if(!(rec = calloc(1,sizeof(struct _BWLContextHashRecord)))){
		return False;
	}
	/* ensure nul byte */
	rec->key[_BWL_CONTEXT_MAX_KEYLEN] = '\0';

	/* set key datum */
	strncpy(rec->key,key,_BWL_CONTEXT_MAX_KEYLEN);
	rec->value = value;

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

static void *
ConfigGet(
	I2Table		table,
	const char	*key
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
		return NULL;
	}

	rec = (struct _BWLContextHashRecord*)v.dptr;

	return rec->value;
}

static BWLBoolean
ConfigDelete(
	I2Table		table,
	const char	*key
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
 * Function:	BWLContextSet
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
	BWLContext	ctx,
	const char	*key,
	void		*value
	)
{
	assert(ctx);

	return ConfigSet(ctx->table,key,value);
}

void *
BWLContextConfigGet(
	BWLContext	ctx,
	const char	*key
	)
{
	assert(ctx);

	return ConfigGet(ctx->table,key);
}

BWLBoolean
BWLContextConfigDelete(
	BWLContext	ctx,
	const char	*key
	)
{
	assert(ctx);

	return ConfigDelete(ctx->table,key);
}

/*
 * Function:	BWLControlSet
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
	BWLControl	cntrl,
	const char	*key,
	void		*value
	)
{
	assert(cntrl);

	return ConfigSet(cntrl->table,key,value);
}

void *
BWLControlConfigGet(
	BWLControl	cntrl,
	const char	*key
	)
{
	assert(cntrl);

	return ConfigGet(cntrl->table,key);
}

BWLBoolean
BWLControlConfigDelete(
	BWLControl	cntrl,
	const char	*key
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
	const BWLUserID	userid,		/* identifies key	*/
	uint8_t	*key_ret,	/* key - return		*/
	BWLErrSeverity	*err_ret	/* error - return	*/
)
{
	BWLGetAESKeyFunc	func;

	*err_ret = BWLErrOK;

	func = (BWLGetAESKeyFunc)BWLContextConfigGet(ctx,BWLGetAESKey);

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

	func = (BWLCheckControlPolicyFunc)BWLContextConfigGet(cntrl->ctx,
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
	BWLCheckTestPolicyFunc	func;
	BWLAddr			local;
	BWLAddr			remote;

	*err_ret = BWLErrOK;

	func = (BWLCheckTestPolicyFunc)BWLContextConfigGet(cntrl->ctx,
							BWLCheckTestPolicy);
	/*
	 * Default action is to fail since the function needs to
	 * return the reservation time and the port for the test.
	 */
	if(!func){
		return False;
	}

	if(tsess->conf_sender){
		local = tsess->test_spec.sender;
		remote = tsess->test_spec.receiver;
	}
	else{
		local = tsess->test_spec.receiver;
		remote = tsess->test_spec.sender;
	}

	return func(cntrl,tsess->sid,tsess->conf_sender,local->saddr,
			remote->saddr,local->saddrlen,&tsess->test_spec,
			tsess->fuzz,&tsess->reserve_time,&tsess->recv_port,
			&tsess->closure,err_ret);
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

	func = (BWLTestCompleteFunc)BWLContextConfigGet(tsession->cntrl->ctx,
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

	func = (BWLProcessResultsFunc)BWLContextConfigGet(tsession->cntrl->ctx,
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
