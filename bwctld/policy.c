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
**	File:		policy.c
**
**	Author:		Jeff W. Boote
**
**	Date:		Tue Sep  9 16:08:44 MDT 2003
**
**	Description:	
**      Default policy  functions used by BWLIB applications.
*/
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h>
#include <assert.h>

#include <bwlib/bwlib.h>
#include "policy.h"

/*
 * Function:	parsekeys
 *
 * Description:	
 * 		Read all keys from the keyfile and populate the
 * 		keys hash with the mappings from users to keys.
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
parsekeys(
	BWLDPolicy	policy,
	FILE		*fp,
	char		**lbuf,
	size_t		*lbuf_max
	)
{
	int		rc=0;
	BWLUserID	username;
	BWLKey		tkey;
	I2Datum		key,val;
	I2ErrHandle	eh = BWLContextGetErrHandle(policy->ctx);

	/*
	 * TODO: Replace with an autoconf test
	 */
	{
		size_t	tsize;
		tsize = sizeof(username);
		assert(I2MAXIDENTITYLEN <= tsize);
		tsize = sizeof(BWLKey);
		assert(I2KEYLEN == tsize);
	}

	if(!fp){
		return 0;
	}

	while((rc = I2ParseKeyFile(eh,fp,rc,lbuf,lbuf_max,NULL,NULL,
					username,tkey)) > 0){

		/*
		 * Make sure the username is not already in the hash.
		 */
		key.dptr = username;
		key.dsize = strlen(username);
		if(I2HashFetch(policy->keys,key,&val)){
			BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"username \"%s\" duplicated",username);
			return -rc;
		}

		/*
		 * alloc memory for the username key.
		 */
		if(!(key.dptr = strdup(username))){
			BWLError(policy->ctx,BWLErrFATAL,errno,
						"strdup(username): %M");
			return -rc;
		}

		/*
		 * alloc memory for AESkey value.
		 */
		if(!(val.dptr = malloc(sizeof(tkey)))){
			free(key.dptr);
			BWLError(policy->ctx,BWLErrFATAL,errno,
						"malloc(AESKEY): %M");
			return -rc;
		}
		memcpy(val.dptr,tkey,sizeof(tkey));
		val.dsize = sizeof(tkey);

		if(I2HashStore(policy->keys,key,val) != 0){
			free(key.dptr);
			free(val.dptr);
			BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"Unable to store AESKey for %s",
					username);
			return -rc;
		}
	}

	return rc;
}

/*
 * INTVAL are consumables that are tracked in the "used" limits of
 * each node. The other limits are fixed values with a yes/no at each
 * level of the tree.
 */
enum limtype{LIMINT,LIMBOOL,LIMFIXEDINT,LIMNOT};
struct limdesc{
	BWLDMesgT	limit;
	char		*lname;
	enum limtype	ltype;
	BWLDLimitT	def_value;
};

static struct limdesc	limkeys[] = {
{BWLDLimParent,		"parent",		LIMNOT,		0},
{BWLDLimBandwidth,	"bandwidth",		LIMFIXEDINT,	0},
{BWLDLimPending,	"pending",		LIMINT,		0},
{BWLDLimEventHorizon,	"event_horizon",	LIMFIXEDINT,	0},
{BWLDLimDuration,	"duration",		LIMFIXEDINT,	0},
{BWLDLimAllowOpenMode,	"allow_open_mode",	LIMBOOL,	1},
{BWLDLimAllowTCP,	"allow_tcp",		LIMBOOL,	1},
{BWLDLimAllowUDP,	"allow_udp",		LIMBOOL,	0}
};

static BWLDLimitT
GetDefLimit(
	BWLDMesgT	lim
	)
{
	size_t	i;

	for(i=0;i<I2Number(limkeys);i++){
		if(lim == limkeys[i].limit){
			return limkeys[i].def_value;
		}
	}

	return 0;
}

static char *
GetLimName(
	BWLDMesgT	lim
	)
{
	size_t	i;
	
	for(i=0;i<I2Number(limkeys);i++){
		if(lim == limkeys[i].limit){
			return limkeys[i].lname;
		}
	}

	return "unknown";
}

static int
parselimitline(
	BWLDPolicy	policy,
	char		*line,
	size_t		maxlim
	)
{
	size_t			i,j,k;
	char			*cname;
	BWLDLimRec		limtemp[I2Number(limkeys)];
	BWLDPolicyNodeRec	tnode;
	BWLDPolicyNode	node;
	I2Datum			key,val;

	/*
	 * Grab new classname
	 */
	if(!(line = strtok(line,I2WSPACESET))){
		return 1;
	}
	cname = line;

	/*
	 * verify classname has not been defined before.
	 */
	key.dptr = cname;
	key.dsize = strlen(cname);
	if(key.dsize > BWLDMAXCLASSLEN){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
			"classname \"%s\" too long - max length = %u",cname,
			BWLDMAXCLASSLEN);
		return 1;
	}
	if(I2HashFetch(policy->limits,key,&val)){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
			"classname \"%s\" duplicated",cname);
		return 1;
	}

	/*
	 * parse "with"
	 */
	if(!(line = strtok(NULL,I2WSPACESET))){
		return 1;
	}
	/* compare strings INCLUDING the '\0' */
	if(strncasecmp(line,"with",5)){
		return 1;
	}

	memset(&tnode,0,sizeof(tnode));
	memset(limtemp,0,sizeof(limtemp));

	tnode.policy = policy;

	/*
	 * Process key/value pairs delimited by ','
	 */
	while((line = strtok(NULL,","))){
		char		*limname,*limval;
		BWLBoolean	found;

		if(tnode.ilim >= maxlim){
			BWLError(policy->ctx,BWLErrFATAL,
				BWLErrINVALID,
				"Too many limit declarations");
			return 1;
		}

		/*
		 * Grab the keyname off the front.
		 */
		while(isspace((int)*line)){line++;}
		limname = line;
		while(!isspace((int)*line) && (*line != '=')){
			line++;
		}
		*line++ = '\0';

		/*
		 * Grab the valname
		 */
		while(isspace((int)*line) || (*line == '=')){
			line++;
		}
		limval = line;
		while(!isspace((int)*line) && (*line != '\0')){
			line++;
		}
		*line = '\0';

		if(!strncasecmp(limname,"parent",7)){
			if(!policy->root){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"\"parent\" specified for root node.");
				return 1;
			}
			if(tnode.parent){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
						"multiple parents specified.");
				return 1;
			}

			/* validate and fetch parent */
			key.dptr = limval;
			key.dsize = strlen(limval);
			if(!I2HashFetch(policy->limits,key,&val)){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"parent \"%s\" undefined",limval);
				return 1;
			}
			tnode.parent = val.dptr;
			continue;
		}

		found = False;
		for(i=0;i < I2Number(limkeys);i++){
			/* skip "special" limit types */
			if(limkeys[i].ltype == LIMNOT){
				continue;
			}

			/* skip non-matching limit names */
			if(strncasecmp(limname,limkeys[i].lname,
						strlen(limkeys[i].lname)+1)){
				continue;
			}

			/* i now points at correct record in limkeys */
			found=True;
			break;
		}

		if(!found){
			BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
				"Unknown limit name \"%s\".",limname);
			return 1;
		}

		/* check for a multiple definition */
		for(j=0;j<tnode.ilim;j++){
			if(limtemp[j].limit == limkeys[i].limit){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"multiple %s values specified.",
					limname);
				return 1;
			}
		}

		/*
		 * Set the next record in limtemp with this limname/limvalue.
		 */
		limtemp[tnode.ilim].limit = limkeys[i].limit;
		switch(limkeys[i].ltype){

		case LIMINT:
		case LIMFIXEDINT:
			if(I2StrToNum(&limtemp[tnode.ilim].value,limval)){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid value specified for \"%s\".",
					limname);
				return 1;
			}
			break;
		case LIMBOOL:
			if(!strncasecmp(limval,"on",3)){
				limtemp[tnode.ilim].value = 1;
			}else if(strncasecmp(limval,"off",4)){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid value specified for \"%s\".",
					limname);
				return 1;
			}
			break;
		default:
			/* NOTREACHED */
			BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"limkeys array is invalid!");
		}

		tnode.ilim++;
	}

	/*
	 * Now copy the parent parameters that were not overridden.
	 */
	if(tnode.parent){
		for(i=0;i<tnode.parent->ilim;i++){
			for(j=0;j<tnode.ilim;j++){
				if(tnode.parent->limits[i].limit ==
							limtemp[j].limit){
					goto override;
				}
			}
			limtemp[tnode.ilim++] = tnode.parent->limits[i];
			continue;
override:
			/*
			 * For integer limits, only allowed to override
			 * with smaller values.
			 */
			for(k=0;k < I2Number(limkeys);k++){
				/*
				 * Go to the next limkey unless it matches
				 * the current parent limit.
				 */
				if(tnode.parent->limits[i].limit !=
							limkeys[k].limit)
					continue;

				/*
				 * If this limit is not an Integer limit,
				 * we don't care, so break out.
				 */
				if((limkeys[k].ltype != LIMFIXEDINT) &&
					(limkeys[k].ltype != LIMINT))
					break;

				/*
				 * If this limit is Inf in the parent, then
				 * it is valid to limit it in the child,
				 * so break out.
				 */
				if(!tnode.parent->limits[i].value)
					break;

				/*
				 * If the parents limit is larger, then it
				 * is valid to further restrict in the
				 * child.
				 */
				if(tnode.parent->limits[i].value >
							limtemp[j].limit)
					break;
				BWLError(policy->ctx,BWLErrWARNING,
						BWLErrUNKNOWN,
		"WARNING: %s: Using parents more restrictive limits for %s.",
						cname,limkeys[k].lname);
				limtemp[j].limit =
					tnode.parent->limits[i].value;
			}
		}
	}
	/*
	 * No parent - if root has been set, this is invalid.
	 */
	else if(policy->root){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
			"\"parent\" must be specified for non-root node");
		return 1;
	}

	/*
	 * Now alloc memory and insert this node into the hash.
	 */
	if(!(node = malloc(sizeof(*node))) ||
			!(tnode.nodename = strdup(cname)) ||
			!(tnode.limits = calloc(maxlim,sizeof(BWLDLimRec))) ||
			!(tnode.used = calloc(maxlim,sizeof(BWLDLimRec)))){
		BWLError(policy->ctx,BWLErrFATAL,errno,"alloc(): %M");
		return 1;
	}
	memcpy(node,&tnode,sizeof(*node));
	if(tnode.ilim){
		memcpy(node->limits,limtemp,sizeof(BWLDLimRec)*tnode.ilim);
		memcpy(node->used,limtemp,sizeof(BWLDLimRec)*tnode.ilim);
		for(i=0;i<tnode.ilim;i++){
			node->used[i].value = 0;
		}
	}

	key.dptr = node->nodename;
	key.dsize = strlen(node->nodename);
	val.dptr = node;
	val.dsize = sizeof(*node);
	if(I2HashStore(policy->limits,key,val) != 0){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"Unable to store limit description!");
		return 1;
	}

	if(!policy->root){
		policy->root = node;
	}

	return 0;
}

static int
parseassignline(
	BWLDPolicy	policy,
	char		*line
	)
{
	BWLDPidRec	tpid;
	BWLDPid	pid;
	I2Datum		key,val;

	memset(&tpid,0,sizeof(tpid));

	/*
	 * Grab assign "type"
	 */
	if(!(line = strtok(line,I2WSPACESET))){
		return 1;
	}

	if(!strncasecmp(line,"default",8)){
		tpid.id_type = BWLDPidDefaultType;
		key.dptr = &tpid;
		key.dsize = sizeof(tpid);
		if(I2HashFetch(policy->idents,key,&val)){
			BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
				"Invalid multiple \"assign default\" lines.");
			return 1;
		}
	}
	else if(!strncasecmp(line,"net",4)){
		int		tint;
		char		*mask, *end;
		struct addrinfo	hints, *res;
		uint8_t	nbytes,nbits,*ptr;

		tpid.id_type = BWLDPidNetmaskType;
		/*
		 * Grab addr/mask
		 */
		if(!(line = strtok(NULL,I2WSPACESET))){
			BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
				"Invalid \"assign net\" argument.");
			return 1;
		}

		if((mask = strchr(line,'/'))){
			*mask++ = '\0';
			if(*mask == '\0'){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid address mask.");
				return 1;
			}
		}

		memset(&hints,0,sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype= SOCK_STREAM;
		res = NULL;

		if((tint = getaddrinfo(line,NULL,&hints,&res)) < 0){
			BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid address \"%s\": %s",line,
					gai_strerror(tint));
			return 1;
		}
		else if(!res){
			BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid address \"%s\".",line);
			return 1;
		}

		switch(res->ai_family){
			struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
			struct sockaddr_in6	*saddr6;

                    case AF_INET6:
                        saddr6 = (struct sockaddr_in6*)res->ai_addr;

                        /*
                         * If this is a v4 mapped address - save as v4 address.
                         */
                        if(IN6_IS_ADDR_V4MAPPED(&saddr6->sin6_addr)){
                            tpid.net.addrsize = 4;
                            memcpy(tpid.net.addrval,
                                    &saddr6->sin6_addr.s6_addr[12],4);
                        }
                        else{
                            tpid.net.addrsize = 16;
                            memcpy(tpid.net.addrval,
                                    saddr6->sin6_addr.s6_addr,16);
                        }
                        break;
#endif
		case AF_INET:
			saddr4 = (struct sockaddr_in*)res->ai_addr;
			tpid.net.addrsize = 4;
			memcpy(tpid.net.addrval,&saddr4->sin_addr.s_addr,4);
			break;

		default:
			freeaddrinfo(res);
			BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"Unknown address protocol family.");
			return 1;
			break;
		}
		freeaddrinfo(res);
		res = NULL;

		if(mask){
			unsigned long tlng;

			tlng = (int)strtoul(mask,&end,10);
			if((*end != '\0') || (tlng < 1) ||
					(tlng > (tpid.net.addrsize*8))){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
					"Invalid address mask \"%s\".",mask);
				return 1;
			}
			tpid.net.mask_len = tlng;
		}
		else{
			tpid.net.mask_len = tpid.net.addrsize*8;
		}

		/*
		 * ensure addr part of addr/mask doesn't set any bits.
		 */

		nbytes = tpid.net.mask_len/8;
		nbits = tpid.net.mask_len%8;
		ptr = &tpid.net.addrval[nbytes];

		/*
		 * Check bits in byte following last complete one.
		 */
		if(nbytes < tpid.net.addrsize){
			if(*ptr & ~(0xFF << (8-nbits))){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid address/mask combination.");
				return 1;
			}
		}

		/*
		 * Check remaining bytes following the partial one.
		 */
		nbytes++;
		ptr++;
		while(nbytes < tpid.net.addrsize){
			if(*ptr){
				BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid address/mask combination.");
				return 1;
			}
			nbytes++;
			ptr++;
		}
	}
	else if(!strncasecmp(line,"user",5)){
		/*
		 * Grab username
		 */
		if(!(line = strtok(NULL,I2WSPACESET))){
			return 1;
		}
		key.dptr = line;
		key.dsize = strlen(line);

		if((key.dsize >= sizeof(tpid.user.userid)) ||
					!I2HashFetch(policy->keys,key,&val)){
			BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
					"Invalid user \"%s\".",line);
			return 1;
		}

		tpid.id_type = BWLDPidUserType;
		strcpy(tpid.user.userid,line);
	}
	else{
		BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
				"Unknown \"assign\" specification.");
		return 1;
	}

	/*
	 * The Pid is valid - now parse and check for limits for
	 * the "classname".
	 */
	if(!(line = strtok(NULL,I2WSPACESET))){
		return 1;
	}

	key.dptr = line;
	key.dsize = strlen(line);
	if(!I2HashFetch(policy->limits,key,&val)){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
				"Unknown limitclass name \"%s\".",line);
		return 1;
	}

	if(!(pid = malloc(sizeof(*pid)))){
		BWLError(policy->ctx,BWLErrFATAL,errno,
				"malloc(BWLDPidRec): %M");
		return 1;
	}
	memcpy(pid,&tpid,sizeof(*pid));
	key.dptr = pid;
	key.dsize = sizeof(*pid);
	if(I2HashStore(policy->idents,key,val) != 0){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"Unable to store assign description!");
		return 1;
	}

	return 0;
}

static int
parselimits(
	BWLDPolicy	policy,
	FILE		*fp,
	char		**lbuf,
	size_t		*lbuf_max
	)
{
	int	rc = 0;
	size_t	i;
	size_t	maxlim = 0;
	char	*line;
	I2ErrHandle	eh = BWLContextGetErrHandle(policy->ctx);

	/*
	 * Count number of possible limit parameters
	 */
	for(i=0;i < I2Number(limkeys);i++){
		if(limkeys[i].ltype != LIMNOT){
			maxlim++;
		}
	}

	/*
	 * parse the file, one line at a time.
	 */
	while(fp && ((rc = I2GetConfLine(eh,fp,rc,lbuf,lbuf_max)) > 0)){
		line = *lbuf;

		/*
		 * parse limit lines. (These create the "user classes" and
		 * specify the "authorization" level of that authenticated
		 * "user class".
		 */
		if(!strncasecmp(line,"limit",5)){
			line += 5;
			while(isspace((int)*line)){
				line++;
			}

			if(parselimitline(policy,line,maxlim) != 0){
				return -rc;
			}
		}
		/*
		 * parse "assign" lines. These are used to determine the
		 * identity of a connection. i.e. authenticate a particular
		 * connection as a particular identity/user class.
		 */
		else if(!strncasecmp(line,"assign",6)){
			line += 6;
			while(isspace((int)*line)){
				line++;
			}

			if(parseassignline(policy,line) != 0){
				return -rc;
			}
		}
		else{
			rc = -rc;
			break;
		}
	}

	/*
	 * Add a "default" class if none was specified.
	 */
	if((rc == 0) && !policy->root){
		char	defline[] = "default with";

		BWLError(policy->ctx,BWLErrWARNING,BWLErrUNKNOWN,
					"WARNING: No limits specified.");

		line = *lbuf;
		if(sizeof(defline) > *lbuf_max){
			*lbuf_max += I2LINEBUFINC;
			*lbuf = realloc(line,sizeof(char) * *lbuf_max);
			if(!*lbuf){
				if(line){
					free(line);
				}
				BWLError(policy->ctx,BWLErrFATAL,errno,
						"realloc(%u): %M",*lbuf_max);
				return -1;
			}
			line = *lbuf;
		}
		strcpy(line,defline);
		if(parselimitline(policy,line,maxlim) != 0){
			BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"Unable to install default (open) limits");
			return -1;
		}
	}


	return rc;
}

/*
 * Function:	BWLDPolicyInstall
 *
 * Description:	
 * 	This function installs the functions defined in this file as
 * 	the "policy" hooks within the bwlib application.
 *
 * 	The main reason for defining the policy in the bwlib library
 * 	like this was that it made it possible to share the policy
 * 	code between client/server applications such as owping and
 * 	bwctld. Also, it is a good example of how this can be done for
 * 	custom appliations (such as powstream).
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 * 	This function does no clean-up of memory it allocates in the event
 * 	of failure. It is expected that the application will report
 * 	an error and exit if this function fails.
 *
 * 	TODO: I really should fix this - it is lazy, and makes looking for
 * 	memory leaks more difficult.
 */
BWLDPolicy
BWLDPolicyInstall(
	BWLContext	ctx,
	char		*datadir,
	char		*confdir,
	char		*tester,
	char		*testercmd,
	uint64_t	*bottleneckcapacity,
	int		*retn_on_intr,
	char		**lbuf,
	size_t		*lbuf_max
	)
{
	BWLDPolicy		policy;
	I2ErrHandle		eh;
	char			fname[MAXPATHLEN+1];
	int			len;
	FILE			*fp;
	int			rc;	/* row count */

	/*
	 * use variables for the func pointers so the compiler can give
	 * type-mismatch warnings.
	 */
	BWLGetAESKeyFunc		getaeskey = BWLDGetAESKey;
	BWLCheckControlPolicyFunc	checkcontrolfunc =
						BWLDCheckControlPolicy;
	BWLCheckTestPolicyFunc		checktestfunc =
						BWLDCheckTestPolicy;
	BWLTestCompleteFunc		testcompletefunc = BWLDTestComplete;


	eh = BWLContextGetErrHandle(ctx);

	/*
	 * Alloc main policy record
	 */
	if(!(policy = calloc(1,sizeof(*policy)))){
		BWLError(ctx,BWLErrFATAL,errno,"calloc(policy rec): %M");
		return NULL;
	}

	policy->ctx = ctx;
	policy->retn_on_intr = retn_on_intr;

	/*
	 * copy datadir
	 */
	if(!datadir){
		datadir = ".";
	}
	if(!(policy->datadir = strdup(datadir))){
		BWLError(ctx,BWLErrFATAL,errno,"strdup(datadir): %M");
		return NULL;
	}

	/*
	 * Alloc hashes.
	 */
	if(!(policy->limits = I2HashInit(eh,0,NULL,NULL)) ||
			!(policy->idents =
				I2HashInit(eh,0,NULL,NULL)) ||
			!(policy->keys = I2HashInit(eh,0,NULL,NULL))){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
			"BWLDPolicyInstall: Unable to allocate hashes");
		return NULL;
	}

	/*
	 * Open the keys file.
	 */
	fname[0] = '\0';
	len = strlen(BWL_KEY_FILE);
	if(len > MAXPATHLEN){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"strlen(BWL_KEY_FILE > MAXPATHLEN)");
		return NULL;
	}

	len += strlen(confdir) + strlen(BWL_PATH_SEPARATOR);
	if(len > MAXPATHLEN){
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"Path to %s > MAXPATHLEN",BWL_KEY_FILE);
		return NULL;
	}
	strcpy(fname,confdir);
	strcat(fname,BWL_PATH_SEPARATOR);
	strcat(fname,BWL_KEY_FILE);
	if(!(fp = fopen(fname,"r")) && (errno != ENOENT)){
		BWLError(ctx,BWLErrFATAL,errno,"Unable to open %s: %M",fname);
		return NULL;
	}

	/*
	 * lbuf is a char buffer that grows as needed in I2GetConfLine
	 * lbuf will be realloc'd repeatedly as needed. Once conf file
	 * parsing is complete - it is free'd from this function.
	 */
	if((rc = parsekeys(policy,fp,lbuf,lbuf_max)) < 0){
		goto BADLINE;
	}

	if(fp && (fclose(fp) != 0)){
		BWLError(ctx,BWLErrFATAL,errno,"fclose(%s): %M",fname);
		return NULL;
	}

	/*
	 * Open the limits file.
	 */
	fname[0] = '\0';
	len = strlen(BWL_LIMITS_FILE);
	if(len > MAXPATHLEN){
		BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"strlen(BWL_LIMITS_FILE > MAXPATHLEN)");
		return NULL;
	}

	len += strlen(confdir) + strlen(BWL_PATH_SEPARATOR);
	if(len > MAXPATHLEN){
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"Path to %s > MAXPATHLEN",BWL_LIMITS_FILE);
		return NULL;
	}
	strcpy(fname,confdir);
	strcat(fname,BWL_PATH_SEPARATOR);
	strcat(fname,BWL_LIMITS_FILE);

	if(!(fp = fopen(fname,"r"))){
		if(errno != ENOENT){
			BWLError(ctx,BWLErrFATAL,errno,"Unable to open %s: %M",
					fname);
			return NULL;
		}
	}

	rc = parselimits(policy,fp,lbuf,lbuf_max); 

BADLINE:

	if(rc < 0){
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"%s:%d Invalid file syntax",fname,-rc);
		return NULL;
	}

	/*
	 * Policy files were parsed and loaded ok. Now, install policy
	 * hook functions that will use it.
	 *
	 * Use func pointers to ensure we have functions of the correct
	 * type.
	 */

	if(!BWLContextConfigSet(ctx,BWLDPOLICY,policy)){
		return NULL;
	}

	if(tester && !strncasecmp(tester,"iperf",6)){
		if(!BWLContextConfigSet(ctx,BWLTester,"iperf")){
			return NULL;
		}
		if(testercmd && 
		   !BWLContextConfigSet(ctx,BWLIperfCmd,(void*)testercmd)){
			return NULL;
		}
	}
	else{
		/* Any value of the tester key different to iperf is
		   considered 'thrulay' */
		if(!BWLContextConfigSet(ctx,BWLTester,"thrulay")){
			return NULL;
		}
	}
	if(bottleneckcapacity && *bottleneckcapacity &&
			!BWLContextConfigSet(ctx,BWLBottleNeckCapacity,
				(void*)bottleneckcapacity)){
		return NULL;
	}
	if(!BWLContextConfigSet(ctx,BWLGetAESKey,(void*)getaeskey)){
		return NULL;
	}
	if(!BWLContextConfigSet(ctx,BWLCheckControlPolicy,(void*)checkcontrolfunc)){
		return NULL;
	}
	if(!BWLContextConfigSet(ctx,BWLCheckTestPolicy,(void*)checktestfunc)){
		return NULL;
	}
	if(!BWLContextConfigSet(ctx,BWLTestComplete,(void*)testcompletefunc)){
		return NULL;
	}

	return policy;
}

/*
 * Function:	BWLDGetAESKey
 *
 * Description:	
 * 	Fetch the 128 bit AES key for a given userid and return it.
 *
 * 	Returns True if successful.
 * 	If False is returned err_ret can be checked to determine if
 * 	the key store had a problem(ErrFATAL) or if the userid is
 * 	invalid(ErrOK).
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	T/F
 * Side Effect:	
 */
extern BWLBoolean
BWLDGetAESKey(
	BWLContext	ctx,
	const BWLUserID	userid,
	BWLKey		key_ret,
	BWLErrSeverity	*err_ret
	)
{
	BWLDPolicy	policy;
	I2Datum		key,val;

	*err_ret = BWLErrOK;

	if(!(policy = (BWLDPolicy)BWLContextConfigGet(ctx,BWLDPOLICY))){
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLDGetAESKey: BWLDPOLICY not set");
		*err_ret = BWLErrFATAL;
		return False;
	}

	key.dptr = (void*)userid;
	key.dsize = strlen(userid);
	if(!I2HashFetch(policy->keys,key,&val)){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrPOLICY,
				"userid \"%s\" unknown",userid);
		return False;
	}

	memcpy(key_ret,val.dptr,val.dsize);

	return True;
}

static BWLDPolicyNode
GetNodeDefault(
	BWLDPolicy	policy
	)
{
	BWLDPidRec	tpid;
	I2Datum		key,val;

	memset(&tpid,0,sizeof(tpid));

	tpid.id_type = BWLDPidDefaultType;
	key.dptr = &tpid;
	key.dsize = sizeof(tpid);
	if(I2HashFetch(policy->idents,key,&val)){
		return (BWLDPolicyNode)val.dptr;
	}

	return policy->root;
}

static BWLDPolicyNode
GetNodeFromUserID(
	BWLDPolicy	policy,
	const BWLUserID	userid		/* MUST POINT TO VALID MEMORY */
	)
{
	BWLDPidRec	pid;
	I2Datum		key,val;

	memset(&pid,0,sizeof(pid));

	pid.id_type = BWLDPidUserType;
	key.dptr = &pid;
	key.dsize = sizeof(pid);

	memcpy(pid.user.userid,userid,sizeof(pid.user.userid));

	if(I2HashFetch(policy->idents,key,&val)){
		return (BWLDPolicyNode)val.dptr;
	}

	return NULL;
}

static BWLDPolicyNode
GetNodeFromAddr(
	BWLDPolicy	policy,
	struct sockaddr	*remote_sa_addr
	)
{
	BWLDPidRec	pid;
	uint8_t	nbytes,nbits,*ptr;
	I2Datum		key,val;

	memset(&pid,0,sizeof(pid));

	pid.id_type = BWLDPidNetmaskType;
	key.dptr = &pid;
	key.dsize = sizeof(pid);

	switch(remote_sa_addr->sa_family){
		struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
		struct sockaddr_in6	*saddr6;

	case AF_INET6:
		saddr6 = (struct sockaddr_in6*)remote_sa_addr;
		/*
		 * If this is a v4 mapped address - match it as a v4 address.
		 */
		if(IN6_IS_ADDR_V4MAPPED(&saddr6->sin6_addr)){
			memcpy(pid.net.addrval,
					&saddr6->sin6_addr.s6_addr[12],4);
			pid.net.addrsize = 4;
		}
		else{
			memcpy(pid.net.addrval,saddr6->sin6_addr.s6_addr,16);
			pid.net.addrsize = 16;
		}
		break;
#endif
	case AF_INET:
		saddr4 = (struct sockaddr_in*)remote_sa_addr;
		memcpy(pid.net.addrval,&saddr4->sin_addr.s_addr,4);
		pid.net.addrsize = 4;
		break;

	default:
		BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
				"Unknown address protocol family.");
		return NULL;
		break;
	}

	/*
	 * Start with the max mask size (full address) and keep decreasing
	 * the mask size until all possible address masks have been checked
	 * for the given address.
	 */
	for(pid.net.mask_len=pid.net.addrsize*8;
				pid.net.mask_len > 0; pid.net.mask_len--){
		/*
		 * nbytes is number of complete bytes in "mask".
		 * nbits is number of bits in the following byte that
		 * are part of the "mask".
		 */
		nbytes = pid.net.mask_len/8;
		nbits = pid.net.mask_len%8;
		ptr = &pid.net.addrval[nbytes];

		/*
		 * Zero out one more bit each time through the loop.
		 * (The "if" skips the "max" case.)
		 */
		if(nbytes < pid.net.addrsize){
			*ptr &= (0xFF << (8-nbits));
		}

		if(I2HashFetch(policy->idents,key,&val)){
			return (BWLDPolicyNode)val.dptr;
		}
	}

	return GetNodeDefault(policy);
}

static BWLDLimitT
GetLimit(
	BWLDPolicyNode	node,
	BWLDMesgT	lim
	)
{
	size_t	i;

	for(i=0;i<node->ilim;i++){
		if(lim == node->limits[i].limit){
			return node->limits[i].value;
		}
	}

	return GetDefLimit(lim);
}

static BWLDLimitT
GetUsed(
	BWLDPolicyNode	node,
	BWLDMesgT	lim
	)
{
	size_t	i;

	for(i=0;i<node->ilim;i++){
		if(lim == node->limits[i].limit){
			return node->used[i].value;
		}
	}

	return 0;
}

static BWLBoolean
IntegerResourceDemand(
	BWLDPolicyNode	node,
	BWLDMesgT	query,
	BWLDLimRec	lim,
	enum limtype	limkind
	)
{
	float	fudge = 1.0;
	size_t	i;

	/*
	 * terminate recursion
	 */
	if(!node){
		return True;
	}

	for(i=0;i<node->ilim;i++){
		if(node->limits[i].limit == lim.limit){
			goto found;
		}
	}

	/*
	 * If there is not limit record, then the default must be 0 or the
	 * logic breaks.
	 */
	assert(!GetDefLimit(lim.limit));

	/*
	 * No reason to keep track if this resource is unlimited all the
	 * way up the tree - so just return true.
	 */
	return True;

found:
	/*
	 * Ok - found the resource limits
	 */

	/*
	 * If no limit at this level, go on to next.
	 */
	if(!node->limits[i].value){
		return IntegerResourceDemand(node->parent,query,lim,limkind);
	}

	/*
	 * Deal with resource releases.
	 */
	else if(query == BWLDMESGRELEASE){
		/*
		 * don't need to release fixed limits - so shortcut.
		 */
		if(limkind == LIMFIXEDINT)
			return True;

		if(lim.value > node->used[i].value){
			BWLError(node->policy->ctx,BWLErrFATAL,BWLErrPOLICY,
				"Request to release unallocated resouces: "
				"%s:%s (currently allocated = %u, "
				"release amount = %u)",node->nodename,
				GetLimName(lim.limit),node->used[i].value,
				lim.value);
			return False;
		}
		
		if(!IntegerResourceDemand(node->parent,query,lim,limkind)){
			return False;
		}

		node->used[i].value -= lim.value;

		return True;
	}

	/*
	 * The rest deals with resource requests.
	 */

	/*
	 * If this is a BWLDMESGCLAIM request - apply the fudge factor.
	 * TODO: This was used to increase the amount of disk *actually*
	 * used by the test, but may not be needed for iperf... I will
	 * leave the MESGCLAIM message as valid for now, and just report
	 * an invalid claim request so I can easily add fudged limits if
	 * needed.
	 */
	if(query == BWLDMESGCLAIM){
		switch(lim.limit){

			default:
			BWLError(node->policy->ctx,BWLErrFATAL,BWLErrPOLICY,
					"Invalid \"CLAIM\" request");
			return False;
		}
	}
	else if(query != BWLDMESGREQUEST){
		BWLError(node->policy->ctx,BWLErrFATAL,BWLErrPOLICY,
				"Unknown resource request type: %u",query);
		return False;
	}

	/*
	 * If this level doesn't have the resources available - return false.
	 * (If LIMFIXEDINT, then "used" value will be 0.)
	 */
	if((lim.value+node->used[i].value) >
				(node->limits[i].value * fudge)){
		return False;
	}

	/*
	 * Are the resource available the next level up?
	 */
	if(!IntegerResourceDemand(node->parent,query,lim,limkind)){
		return False;
	}

	if(limkind == LIMINT)
		node->used[i].value += lim.value;

	return True;
}

BWLBoolean
BWLDGetFixedLimit(
		BWLDPolicyNode	node,
		BWLDMesgT	limname,
		BWLDLimitT	*ret_val
		)
{
	size_t		maxdef = I2Number(limkeys);
	size_t		i;
	enum limtype	limkind = LIMNOT;

	for(i=0;i<maxdef;i++){
		if(limname == limkeys[i].limit){
			limkind = limkeys[i].ltype;
			break;
		}
	}

	if((limkind == LIMBOOL) || (limkind == LIMFIXEDINT)){
		*ret_val = GetLimit(node,limname);
		return True;
	}

	BWLError(node->policy->ctx,BWLErrFATAL,BWLErrINVALID,
			"BWLDResourceDemand: Invalid limit kind: "
			"node(%s),limname(%d),limkind(%d)",
			node->nodename,limname,limkind);
	return False;
}

BWLBoolean
BWLDResourceDemand(
	BWLDPolicyNode	node,
	BWLDMesgT	query,
	BWLDLimRec	lim
	)
{
	size_t		maxdef = I2Number(limkeys);
	size_t		i;
	enum limtype	limkind = LIMNOT;
	BWLDLimitT	val;
	BWLBoolean	ret;

	for(i=0;i<maxdef;i++){
		if(lim.limit == limkeys[i].limit){
			limkind = limkeys[i].ltype;
			break;
		}
	}

	if(limkind == LIMNOT){
		return False;
	}
	else if(limkind == LIMBOOL){
		if(query == BWLDMESGRELEASE){
			return True;
		}
		val = GetLimit(node,lim.limit);
		return (val == lim.value);
	}
	else if(limkind == LIMFIXEDINT){
		if(query == BWLDMESGRELEASE){
			return True;
		}
		/* fallthrough to IntegerResourceDemand */
	}
	else if(limkind != LIMINT){
		BWLError(node->policy->ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLDResourceDemand: Invalid limit kind.");
		return False;
	}

	ret = IntegerResourceDemand(node,query,lim,limkind);

	/*
	 * These messages are printed to DEBUG so they can be selected
	 * as non-interesting.
	 */
	for(;!ret && node;node = node->parent){
		BWLError(node->policy->ctx,BWLErrDEBUG,BWLErrPOLICY,
		"ResReq %s: %s:%s:%s = %llu (result = %llu, limit = %llu)",
		(ret)?"ALLOWED":"DENIED",
		node->nodename,
		(query == BWLDMESGRELEASE)?"release":"request",
		GetLimName(lim.limit),
		lim.value,
		GetUsed(node,lim.limit),
		GetLimit(node,lim.limit));
	}

	return ret;
}

/*
 * Function:	BWLDSendResponse
 *
 * Description:	
 * 	This function is called from the parent perspective.
 *
 * 	It is used to respond to a child request/release of resources.
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
BWLDSendResponse(
		int		fd,
		int		*retn_on_intr,
		BWLDMesgT	mesg
		)
{
	BWLDMesgT	buf[3];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	buf[0] = buf[2] = BWLDMESGMARK;
	buf[1] = mesg;

	if(I2Writeni(fd,&buf[0],12,intr) != 12){
		return 1;
	}

	return 0;
}

/*
 * Function:	BWLDReadResponse
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
static BWLDMesgT
BWLDReadResponse(
		int		fd,
		int		*retn_on_intr
		)
{
	BWLDMesgT	buf[3];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	if(I2Readni(fd,&buf[0],12,intr) != 12){
		return BWLDMESGINVALID;
	}

	if((buf[0] != BWLDMESGMARK) || (buf[2] != BWLDMESGMARK)){
		return BWLDMESGINVALID;
	}

	return buf[1];
}

/*
 * Function:	BWLDReadClass
 *
 * Description:	
 * 	This function is called from the parent perspective.
 *
 * 	It is used to read the initial message from a child to determine
 * 	the "user class" of the given connection.
 *
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
BWLDPolicyNode
BWLDReadClass(
	BWLDPolicy	policy,
	int		fd,
	int		*retn_on_intr,
	int		*err
	)
{
	ssize_t		i;
	const BWLDMesgT	mark=BWLDMESGMARK;
	const BWLDMesgT	mclass=BWLDMESGCLASS;
	uint8_t	buf[BWLDMAXCLASSLEN+1 + sizeof(BWLDMesgT)*3];
	I2Datum		key,val;
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	*err = 1;

	/*
	 * Read message header
	 */
	if((i = I2Readni(fd,&buf[0],8,intr)) != 8){
		if(i == 0){
			*err = 0;
		}
		return NULL;
	}

	if(memcmp(&buf[0],&mark,sizeof(BWLDMesgT)) ||
			memcmp(&buf[4],&mclass,sizeof(BWLDMesgT))){
		return NULL;
	}

	/*
	 * read classname
	 */
	for(i=0;i<= BWLDMAXCLASSLEN;i++){
		if(I2Readni(fd,&buf[i],1,intr) != 1){
			return NULL;
		}

		if(buf[i] == '\0'){
			break;
		}
	}

	if(i > BWLDMAXCLASSLEN){
		return NULL;
	}

	key.dptr = &buf[0];
	key.dsize = i;

	/*
	 * read message trailer.
	 */
	i++;
	if((I2Readni(fd,&buf[i],4,intr) != 4) ||
			memcmp(&buf[i],&mark,sizeof(BWLDMesgT))){
		return NULL;
	}

	if(I2HashFetch(policy->limits,key,&val)){
		if(BWLDSendResponse(fd,intr,BWLDMESGOK) != 0){
			return NULL;
		}
		*err = 0;
		return val.dptr;
	}

	(void)BWLDSendResponse(fd,intr,BWLDMESGDENIED);
	return NULL;
}

static BWLDMesgT
BWLDSendClass(
	BWLDPolicy	policy,
	BWLDPolicyNode	node
	)
{
	uint8_t	buf[BWLDMAXCLASSLEN+1 + sizeof(BWLDMesgT)*3];
	BWLDMesgT	mesg;
	ssize_t		len;
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(policy->retn_on_intr)
		intr = policy->retn_on_intr;

	mesg = BWLDMESGMARK;
	memcpy(&buf[0],&mesg,4);
	mesg = BWLDMESGCLASS;
	memcpy(&buf[4],&mesg,4);
	len = strlen(node->nodename);
	len++;
	strncpy((char*)&buf[8],node->nodename,len);
	len += 8;
	mesg = BWLDMESGMARK;
	memcpy(&buf[len],&mesg,4);
	len += 4;

	if(I2Writeni(policy->fd,buf,len,intr) != len){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
			"BWLDCheckControlPolicy: Unable to contact parent");
		return BWLDMESGINVALID;
	}

	return BWLDReadResponse(policy->fd,intr);
}

/*
 * return the request type, or 0.
 * err will be 0 for a 0 length read. (i.e. no error)
 */
int
BWLDReadReqType(
	int	fd,
	int	*retn_on_intr,
	int	*err
	)
{
	ssize_t		i;
	BWLDMesgT	buf[2];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	*err = 1;

	/*
	 * Read message header
	 */
	if((i = I2Readni(fd,&buf[0],8,intr)) != 8){
		if(i == 0){
			*err = 0;
		}
		return 0;
	}

	if(buf[0] != BWLDMESGMARK){
		return 0;
	}

	*err = 0;
	return buf[1];
}

/*
 * True if the request is read without error
 */
BWLBoolean
BWLDReadQuery(
	int		fd,
	int		*retn_on_intr,
	BWLDMesgT	*query,
	BWLDLimRec	*lim_ret,
	int		*err
	)
{
	ssize_t		i;
	BWLDMesgT	buf[5];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	*err = 1;

	/*
	 * Read message header
	 */
	if((i = I2Readni(fd,&buf[0],20,intr)) != 20)
		return False;

	if(buf[4] != BWLDMESGMARK)
		return False;

	switch(buf[0]){
		case BWLDMESGREQUEST:
		case BWLDMESGRELEASE:
		case BWLDMESGCLAIM:
			*query = buf[0];
			break;
		default:
			return False;
	}

	lim_ret->limit = buf[1];
	memcpy(&lim_ret->value,&buf[2],8);

	*err = 0;

	return True;
}

static BWLDMesgT
BWLDQuery(
	BWLDPolicy	policy,
	BWLDMesgT	mesg,	/* BWLDMESGREQUEST or BWLDMESGRELEASE	*/
	BWLDLimRec	lim
	)
{
	BWLDMesgT	buf[7];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(policy->retn_on_intr)
		intr = policy->retn_on_intr;

	buf[0] = buf[6] = BWLDMESGMARK;
	buf[1] = BWLDMESGRESOURCE;
	buf[2] = mesg;
	buf[3] = lim.limit;
	memcpy(&buf[4],&lim.value,8);

	if(I2Writeni(policy->fd,buf,28,intr) != 28){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
			"BWLDQuery: Unable to contact parent");
		return BWLDMESGINVALID;
	}

	return BWLDReadResponse(policy->fd,intr);
}

/*
 * True if the request is read without error
 */
BWLBoolean
BWLDReadReservationQuery(
	int		fd,
	int		*retn_on_intr,
	BWLSID		sid,
	BWLNum64	*req_time,
	BWLNum64	*fuzz_time,
	BWLNum64	*last_time,
	uint32_t	*duration,
	BWLNum64	*rtt_time,
	uint16_t	*recv_port,
	int		*err
	)
{
	ssize_t		i;
	BWLDMesgT	buf[15];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	*err = 1;

	/*
	 * Read message header
	 */
	if((i = I2Readni(fd,&buf[0],60,intr)) != 60)
		return False;

	if(buf[14] != BWLDMESGMARK)
		return False;

	memcpy(sid,&buf[0],16);
	memcpy(req_time,&buf[4],8);
	memcpy(fuzz_time,&buf[6],8);
	memcpy(last_time,&buf[8],8);
	memcpy(duration,&buf[10],4);
	memcpy(rtt_time,&buf[11],8);
	memcpy(recv_port,&buf[13],2);

	*err = 0;

	return True;
}

/*
 * Function:	BWLDSendReservationResponse
 *
 * Description:	
 * 	This function is called from the parent perspective.
 *
 * 	It is used to respond to a child request for reservation.
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
BWLDSendReservationResponse(
		int		fd,
		int		*retn_on_intr,
		BWLDMesgT	mesg,
		BWLNum64	reservation,
		uint16_t	port
		)
{
	BWLDMesgT	buf[6];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	buf[0] = buf[5] = BWLDMESGMARK;
	buf[1] = mesg;

	memcpy(&buf[2],&reservation,8);
	memcpy(&buf[4],&port,2);

	if(I2Writeni(fd,&buf[0],24,intr) != 24){
		return 1;
	}

	return 0;
}

static BWLDMesgT
BWLDReadReservationResponse(
		int		fd,
		int		*retn_on_intr,
		BWLNum64	*reservation_ret,
		uint16_t	*port_ret
		)
{
	ssize_t		i;
	BWLDMesgT	buf[6];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	/*
	 * Read message header
	 */
	if((i = I2Readni(fd,&buf[0],24,intr)) != 24)
		return False;

	if((buf[0] != BWLDMESGMARK) || (buf[5] != BWLDMESGMARK))
		return False;

	memcpy(reservation_ret,&buf[2],8);
	memcpy(port_ret,&buf[4],2);

	return buf[1];
}

static BWLDMesgT
BWLDReservationQuery(
	BWLDPolicy	policy,
	BWLSID		sid,
	BWLNum64	req_time,
	BWLNum64	fuzz_time,
	BWLNum64	last_time,
	uint32_t	duration,
	BWLNum64	rtt_time,
	BWLNum64	*reservation_ret,
	uint16_t	*port
	)
{
	BWLDMesgT	buf[17];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(policy->retn_on_intr)
		intr = policy->retn_on_intr;

	buf[0] = buf[16] = BWLDMESGMARK;
	buf[1] = BWLDMESGRESERVATION;
	memcpy(&buf[2],sid,16);
	memcpy(&buf[6],&req_time,8);
	memcpy(&buf[8],&fuzz_time,8);
	memcpy(&buf[10],&last_time,8);
	memcpy(&buf[12],&duration,4);
	memcpy(&buf[13],&rtt_time,8);
	memcpy(&buf[15],port,2);

	if(I2Writeni(policy->fd,buf,68,intr) != 68){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
			"BWLDQuery: Unable to contact parent");
		return BWLDMESGINVALID;
	}

	return BWLDReadReservationResponse(policy->fd,intr,reservation_ret,
			port);
}

/*
 * True if the request is read without error
 */
BWLBoolean
BWLDReadTestComplete(
	int		fd,
	int		*retn_on_intr,
	BWLSID		sid,
	BWLAcceptType	*aval,
	int		*err
	)
{
	ssize_t		i;
	BWLDMesgT	buf[6];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(retn_on_intr)
		intr = retn_on_intr;

	*err = 1;

	/*
	 * Read message header
	 */
	if((i = I2Readni(fd,&buf[0],24,intr)) != 24)
		return False;

	if(buf[5] != BWLDMESGMARK)
		return False;

	memcpy(sid,&buf[0],16);
	*aval = buf[4];

	*err = 0;

	return True;
}

static BWLDMesgT
BWLDSendTestComplete(
	BWLDPolicy	policy,
	BWLSID		sid,
	BWLAcceptType	aval
	)
{
	BWLDMesgT	buf[8];
	int		fail_on_intr=1;
	int		*intr = &fail_on_intr;

	if(policy->retn_on_intr)
		intr = policy->retn_on_intr;

	buf[0] = buf[7] = BWLDMESGMARK;
	buf[1] = BWLDMESGCOMPLETE;
	memcpy(&buf[2],sid,16);
	memcpy(&buf[6],&aval,4);

	if(I2Writeni(policy->fd,buf,32,intr) != 32){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrUNKNOWN,
			"BWLDQuery: Unable to contact parent");
		return BWLDMESGINVALID;
	}

	return BWLDReadResponse(policy->fd,intr);
}

/*
 * Function:	BWLDAllowOpenMode
 *
 * Description:	
 *	check if the given address is allowed to have open_mode communication.
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
BWLDAllowOpenMode(
	BWLDPolicy	policy,
	struct sockaddr	*remote_sa_addr,
	BWLErrSeverity	*err_ret	 /* error - return     	*/
	)
{
	BWLDPolicyNode	node;

	*err_ret = BWLErrOK;

	if(!(node = GetNodeFromAddr(policy,remote_sa_addr))){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLDAllowOpenMode: Invalid policy");
		*err_ret = BWLErrFATAL;
		return False;
	}

	return GetLimit(node,BWLDLimAllowOpenMode);
}

/*
 * Function:	BWLDCheckControlPolicy
 *
 * Description:	
 * 	Determines the "user class" of the given connection and
 * 	sends that information to the "parent" so the parent can
 * 	approve future resource requests.
 *
 * 	Returns False and sets err_ret if the "user class" cannot be
 * 	determined or if there is an error communicating with the parent.
 * 	(The parent communication is necessary to keep track of resource
 * 	allocations on a "global" basis instead of per-connection.)
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
BWLDCheckControlPolicy(
	BWLControl	cntrl,
	BWLSessionMode	mode,			/* requested mode	*/
	const BWLUserID	userid,			/* identity		*/
	struct sockaddr	*local_sa_addr __attribute__((unused)),
						/* local addr or NULL	*/
	struct sockaddr	*remote_sa_addr,	/* remote addr		*/
	BWLErrSeverity	*err_ret		/* error - return     	*/
)
{
	BWLContext	ctx;
	BWLDPolicy	policy;
	BWLDPolicyNode	node=NULL;
	BWLDMesgT	ret;

	*err_ret = BWLErrOK;

	ctx = BWLGetContext(cntrl);

	if(!(policy = (BWLDPolicy)BWLContextConfigGet(ctx,BWLDPOLICY))){
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLDCheckControlPolicy: BWLDPOLICY not set");
		*err_ret = BWLErrFATAL;
		return False;
	}

	/*
	 * Determine userclass and send that to the parent.
	 * (First try based on userid.)
	 */
	if(((mode & BWL_MODE_DOCIPHER) && userid) &&
			!(node = GetNodeFromUserID(policy,userid))){
		BWLError(policy->ctx,BWLErrDEBUG,BWLErrUNKNOWN,
				"BWLDCheckControlPolicy: No policy match for userid(%s) - using netmask match",userid);
	}

	/*
	 * If we don't get a userclass from the userid, then get one
	 * based on the address. (This returns the default if no
	 * address matched.)
	 */
	if(!node && !(node = GetNodeFromAddr(policy,remote_sa_addr))){
		BWLError(policy->ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLDCheckControlPolicy: Invalid policy");
		*err_ret = BWLErrFATAL;
		return False;
	}

	/*
	 * Initialize the communication with the parent resource broker
	 * process.
	 */
	if((ret = BWLDSendClass(policy,node)) == BWLDMESGOK){
		/*
		 * Success - now save the node in the control config
		 * for later hook functions to access.
		 */
		if(!BWLControlConfigSet(cntrl,BWLDPOLICY_NODE,node)){
			BWLError(ctx,BWLErrFATAL,BWLErrUNKNOWN,
	"BWLDCheckControlPolicy: Unable to save \"class\" for connection");
			*err_ret = BWLErrFATAL;
			return False;
		}

		return True;
	}

	/*
	 * If ret wasn't BWLDMESGDENIED - there was some kind of error.
	 */
	if(ret != BWLDMESGDENIED){
		*err_ret = BWLErrFATAL;
	}

	return False;
}

/*
 * This structure is returned in the "closure" pointer of the CheckTestPolicy
 * pointer - and provided to the Open/Close file functions as well as the
 * TestComplete function.
 */
typedef struct BWLDTestInfoRec{
	BWLDPolicyNode	node;
	BWLSID		sid;
	BWLDLimRec	res[1];	/* keep track of "consumable" resources
				 * resouces listed here will be "released"
				 * in TestComplete.
				 */
} BWLDTestInfoRec, *BWLDTestInfo;

BWLBoolean
BWLDCheckTestPolicy(
	BWLControl	cntrl,
	BWLSID		sid,
	BWLBoolean	local_sender __attribute__((unused)),
	struct sockaddr	*local_sa_addr	__attribute__((unused)),
	struct sockaddr	*remote_sa_addr __attribute__((unused)),
	socklen_t	sa_len	__attribute__((unused)),
	BWLTestSpec	*tspec,
	BWLNum64	fuzz_time,
	BWLNum64	*reservation_ret,
	uint16_t	*port_ret,
	void		**closure,
	BWLErrSeverity	*err_ret
)
{
	BWLContext	ctx = BWLGetContext(cntrl);
	BWLDPolicyNode	node;
	BWLDTestInfo	tinfo;
	BWLDMesgT	ret;
	BWLDLimRec	lim;
	BWLTesterAvailability allowed_testers;

	*err_ret = BWLErrOK;

	tinfo = (BWLDTestInfo)*closure;

	/*
	 * If this is just an update to the reservation...
	 */
	if(tinfo){
		node = tinfo->node;
		goto reservation;
	}
	/*
	 * this is an new request
	 */

	/*
	 * Fetch the "user class" for this connection.
	 */
	if(!(node = (BWLDPolicyNode)BWLControlConfigGet(cntrl,
						BWLDPOLICY_NODE))){
		BWLError(ctx,BWLErrFATAL,BWLErrINVALID,
				"BWLDCheckTestPolicy: BWLDPOLICY_NODE not set");
		*err_ret = BWLErrFATAL;
		return False;
	}


	if(!(tinfo = calloc(1,sizeof(BWLDTestInfoRec)))){
		BWLError(ctx,BWLErrFATAL,errno,"calloc(1,BWLDTestInfoRec): %M");
		*err_ret = BWLErrFATAL;
		return False;
	}

	tinfo->node = node;
	memcpy(tinfo->sid,sid,sizeof(sid));

	/* VAlIDATE THE REQUEST! */

	/*
	 * First check fixed limits that don't need to be communicated
	 * with the parent for global state.
	 */

	/* duration */
	lim.limit = BWLDLimDuration;
	lim.value = tspec->duration;
	if(!BWLDResourceDemand(node,BWLDMESGREQUEST,lim))
		goto done;

	/*
	 * Make sure the requested tester is allowed.
	 */
	/* TODO: really check this if the `tester' key or something
	   similar if finally kept. */
	allowed_testers = 0xffffffff;
	if(!(tspec->tester & allowed_testers))
		goto done;

	/*
	 * TCP/UDP
	 */
	if(tspec->udp){
		lim.limit = BWLDLimAllowUDP;
		lim.value = True;
		if(!BWLDResourceDemand(node,BWLDMESGREQUEST,lim))
			goto done;
		lim.limit = BWLDLimBandwidth;
		lim.value = tspec->bandwidth;
		if(!BWLDResourceDemand(node,BWLDMESGREQUEST,lim))
			goto done;
	}
	else{
		lim.limit = BWLDLimAllowTCP;
		lim.value = True;
		if(!BWLDResourceDemand(node,BWLDMESGREQUEST,lim))
			goto done;
	}

	/*
	 * Now request consumable resources
	 */
	tinfo->res[0].limit = BWLDLimPending;
	tinfo->res[0].value = 1;
	if((ret = BWLDQuery(node->policy,BWLDMESGREQUEST,tinfo->res[0]))
							!= BWLDMESGOK){
		goto done;
	}

reservation:

	/*
	 * Request a reservation.
	 */
	if( (ret = BWLDReservationQuery(node->policy,tinfo->sid,
					tspec->req_time.tstamp,fuzz_time,
					tspec->latest_time,tspec->duration,
					BWLGetRTTBound(cntrl),
					reservation_ret,port_ret))
			!= BWLDMESGOK){
		goto done;
	}
	*closure = tinfo;
	return True;
done:
	*closure = NULL;
	free(tinfo);
	return False;
}

extern void
BWLDTestComplete(
	BWLControl	cntrl __attribute__((unused)),
	void		*closure,	/* closure from CheckTestPolicy	*/
	BWLAcceptType	aval
	)
{
	BWLDTestInfo	tinfo = (BWLDTestInfo)closure;
	unsigned int	i,n;

	n = I2Number(tinfo->res);
	for(i=0;i<n;i++){
		if(!tinfo->res[i].limit){
			continue;
		}
		(void)BWLDQuery(tinfo->node->policy,BWLDMESGRELEASE,
								tinfo->res[i]);
	}

	(void)BWLDSendTestComplete(tinfo->node->policy,tinfo->sid,aval);

	free(tinfo);

	return;
}
