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
**      Default policy  functions used by IPCNTRL applications.
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
#include <fts.h>

#include <ipcntrl/ipcntrl.h>
#include "policy.h"
#include "conf.h"

/*
 * Function:	parsekeys
 *
 * Description:	
 * 	Read a single line from the keys file of the format:
 * 		"\s*username\s+key\n"
 * 	skipping blank lines, comment lines, trailing comments
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
	IPFDPolicy	policy,
	FILE		*fp,
	char		**lbuf,
	size_t		*lbuf_max
	)
{
	char		*line;
	int		rc;
	int		i;
	IPFUserID	username;
	const int	keylen=sizeof(IPFKey)*2; /* len hex-encoded key */
	char		*keystart;
	IPFKey		tkey;
	I2Datum		key,val;

	if(!fp){
		return 0;
	}

	while((rc = IPFDGetConfLine(policy->ctx,fp,rc,lbuf,lbuf_max)) > 0){

		line = *lbuf;

		i=0;
		while(i <= IPF_USERID_LEN){
			if(isspace(*line) || (*line == '\0')){
				break;
			}
			username[i++] = *line++;
		}

		if(i > IPF_USERID_LEN){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
							"Username too long");
			return -rc;
		}
		username[i] = '\0';

		/*
		 * Make sure the username is not already in the hash.
		 */
		key.dptr = username;
		key.dsize = strlen(username);
		if(I2HashFetch(policy->keys,key,&val)){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
					"username \"%s\" duplicated",username);
			return -rc;
		}

		/*
		 * grab hex-encoded key.
		 */
		while(isspace(*line)){
			line++;
		}

		keystart = line;
		i=0;
		while(*line != '\0'){
			if(isspace(*line)){
				break;
			}
			i++;
			line++;
		}
		/*
		 * terminate keystart
		 */
		*line++ = '\0';

		/*
		 * Make sure the only thing trailing the key is
		 * a comment or whitespace.
		 */
		while(*line != '\0'){
			if(*line == '#'){
				break;
			}
			if(!isspace(*line)){
				return -rc;
			}
			line++;
		}

		if(i != keylen){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
						"Invalid key: wrong length");
			return -rc;
		}
		if(!IPFHexDecode(keystart,tkey,sizeof(tkey))){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
						"Invalid key: not hex?");
			return -rc;
		}

		/*
		 * alloc memory for the username key.
		 */
		if(!(key.dptr = strdup(username))){
			IPFError(policy->ctx,IPFErrFATAL,errno,
						"strdup(username): %M");
			return -rc;
		}

		/*
		 * alloc memory for AESkey value.
		 */
		if(!(val.dptr = malloc(sizeof(tkey)))){
			free(key.dptr);
			IPFError(policy->ctx,IPFErrFATAL,errno,
						"malloc(AESKEY): %M");
			return -rc;
		}
		memcpy(val.dptr,tkey,sizeof(tkey));
		val.dsize = sizeof(tkey);

		if(I2HashStore(policy->keys,key,val) != 0){
			free(key.dptr);
			free(val.dptr);
			IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"Unable to store AESKey for %s",
					username);
			return -rc;
		}
	}

	return rc;
}

/*
 * Function:	str2num
 *
 * Description:	
 * 	This function converts a string representation of a number to
 * 	an unsigned 64 bit integer value. It understands SI unit extentions
 * 	to the numeric value. (There can be no whitespace between the number
 * 	and the "unit" or the "unit" charactor will not be found.)
 *
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 * 	This function is destructive to the passed in string.
 */
static int
str2num(
		IPFDLimitT	*limnum,
		char		*limstr
		)
{
	size_t		silen=0;
	size_t		len;
	char		*endptr;
	IPFDLimitT	ret, mult=1;

	while(isdigit(limstr[silen])){
		silen++;
	}
	len = strlen(limstr);

	if(len != silen){
		/*
		 * Ensure that there is at most one non-digit and that it
		 * is the last char.
		 */
		if((len - silen) > 1){
			return -1;
		}

		switch (tolower(limstr[silen])){
		case 'k':
			mult = 1000ULL;                            /* 1e3 */
			break;
		case 'm':
			mult = 1000000ULL;                         /* 1e6 */
			break;
		case 'g':
			mult = 1000000000ULL;                      /* 1e9 */
			break;
		case 't':
			mult = 1000000000000ULL;                   /* 1e12 */
			break;
		case 'p':
			mult = 1000000000000000ULL;                /* 1e15 */
			break;
		case 'e':
			mult = 1000000000000000000ULL;             /* 1e18 */
			break;
		case 'z':
			mult = 1000000000000000000000ULL;          /* 1e21 */
			break;
		default:
			return -1;
			/* UNREACHED */
		}
		limstr[silen] = '\0';
	}
	ret = strtoull(limstr, &endptr, 10);
	if(endptr != &limstr[silen]){
		return -1;
	}

	if(ret == 0){
		*limnum = 0;
		return 0;
	}

	/* Check for overflow. */
	*limnum = ret * mult;
	return (*limnum < ret || *limnum < mult)? (-1) : 0;
}

enum limtype{LIMINTVAL,LIMBOOLVAL,LIMNOT};
struct limdesc{
	IPFDMesgT	limit;
	char		*lname;
	enum limtype	ltype;
	IPFBoolean	release_on_exit;
	IPFDLimitT	def_value;
};

static struct limdesc	limkeys[] = {
{IPFDLimParent,		"parent",		LIMNOT,		0,	0},
{IPFDLimBandwidth,	"bandwidth",		LIMINTVAL,	1,	0},
{IPFDLimPending,	"pending",		LIMINTVAL,	1,	0},
{IPFDLimEventHorizon,	"event_horizon",	LIMINTVAL,	1,	0},
{IPFDLimDuration,	"duration",		LIMINTVAL,	1,	0},
{IPFDLimAllowOpenMode,	"allow_open_mode",	LIMBOOLVAL,	0,	1},
{IPFDLimAllowTCP,	"allow_tcp",		LIMBOOLVAL,	0,	1},
{IPFDLimAllowUDP,	"allow_udp",		LIMBOOLVAL,	0,	0}
};

static IPFDLimitT
GetDefLimit(
	IPFDMesgT	lim
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
	IPFDMesgT	lim
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
	IPFDPolicy	policy,
	char		*line,
	size_t		maxlim
	)
{
	size_t			i,j;
	char			*cname;
	IPFDLimRec		limtemp[I2Number(limkeys)];
	IPFDPolicyNodeRec	tnode;
	IPFDPolicyNode	node;
	I2Datum			key,val;

	/*
	 * Grab new classname
	 */
	if(!(line = strtok(line,IPFDWSPACESET))){
		return 1;
	}
	cname = line;

	/*
	 * verify classname has not been defined before.
	 */
	key.dptr = cname;
	key.dsize = strlen(cname);
	if(key.dsize > IPFDMAXCLASSLEN){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
			"classname \"%s\" too long - max length = %u",cname,
			IPFDMAXCLASSLEN);
		return 1;
	}
	if(I2HashFetch(policy->limits,key,&val)){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
			"classname \"%s\" duplicated",cname);
		return 1;
	}

	/*
	 * parse "with"
	 */
	if(!(line = strtok(NULL,IPFDWSPACESET))){
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
		IPFBoolean	found;

		if(tnode.ilim >= maxlim){
			IPFError(policy->ctx,IPFErrFATAL,
				IPFErrINVALID,
				"Too many limit declarations");
			return 1;
		}

		/*
		 * Grab the keyname off the front.
		 */
		while(isspace(*line)){line++;}
		limname = line;
		while(!isspace(*line) && (*line != '=')){
			line++;
		}
		*line++ = '\0';

		/*
		 * Grab the valname
		 */
		while(isspace(*line) || (*line == '=')){
			line++;
		}
		limval = line;
		while(!isspace(*line) && (*line != '\0')){
			line++;
		}
		*line = '\0';

		if(!strncasecmp(limname,"parent",7)){
			if(!policy->root){
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
					"\"parent\" specified for root node.");
				return 1;
			}
			if(tnode.parent){
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
						"multiple parents specified.");
				return 1;
			}

			/* validate and fetch parent */
			key.dptr = limval;
			key.dsize = strlen(limval);
			if(!I2HashFetch(policy->limits,key,&val)){
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
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
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
				"Unknown limit name \"%s\".",limname);
			return 1;
		}

		/* check for a multiple definition */
		for(j=0;j<tnode.ilim;j++){
			if(limtemp[j].limit == limkeys[i].limit){
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
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

		case LIMINTVAL:
			if(str2num(&limtemp[tnode.ilim].value,limval)){
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid value specified for \"%s\".",
					limname);
				return 1;
			}
			break;
		case LIMBOOLVAL:
			if(!strncasecmp(limval,"on",3)){
				limtemp[tnode.ilim].value = 1;
			}else if(strncasecmp(limval,"off",4)){
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid value specified for \"%s\".",
					limname);
				return 1;
			}
			break;
		default:
			/* NOTREACHED */
			IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
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
override:
			;
		}
	}
	/*
	 * No parent - if root has been set, this is invalid.
	 */
	else if(policy->root){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
			"\"parent\" must be specified for non-root node");
		return 1;
	}

	/*
	 * Now alloc memory and insert this node into the hash.
	 */
	if(!(node = malloc(sizeof(*node))) ||
			!(tnode.nodename = strdup(cname)) ||
			!(tnode.limits = calloc(maxlim,sizeof(IPFDLimRec))) ||
			!(tnode.used = calloc(maxlim,sizeof(IPFDLimRec)))){
		IPFError(policy->ctx,IPFErrFATAL,errno,"alloc(): %M");
		return 1;
	}
	memcpy(node,&tnode,sizeof(*node));
	if(tnode.ilim){
		memcpy(node->limits,limtemp,sizeof(IPFDLimRec)*tnode.ilim);
		memcpy(node->used,limtemp,sizeof(IPFDLimRec)*tnode.ilim);
		for(i=0;i<tnode.ilim;i++){
			node->used[i].value = 0;
		}
	}

	key.dptr = node->nodename;
	key.dsize = strlen(node->nodename);
	val.dptr = node;
	val.dsize = sizeof(*node);
	if(I2HashStore(policy->limits,key,val) != 0){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
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
	IPFDPolicy	policy,
	char		*line
	)
{
	IPFDPidRec	tpid;
	IPFDPid	pid;
	I2Datum		key,val;

	memset(&tpid,0,sizeof(tpid));

	/*
	 * Grab assign "type"
	 */
	if(!(line = strtok(line,IPFDWSPACESET))){
		return 1;
	}

	if(!strncasecmp(line,"default",8)){
		tpid.id_type = IPFDPidDefaultType;
		key.dptr = &tpid;
		key.dsize = sizeof(tpid);
		if(I2HashFetch(policy->idents,key,&val)){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid multiple \"assign default\" lines.");
			return 1;
		}
	}
	else if(!strncasecmp(line,"net",4)){
		int		tint;
		char		*mask, *end;
		struct addrinfo	hints, *res;
		u_int8_t	nbytes,nbits,*ptr;

		tpid.id_type = IPFDPidNetmaskType;
		/*
		 * Grab addr/mask
		 */
		if(!(line = strtok(NULL,IPFDWSPACESET))){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
				"Invalid \"assign net\" argument.");
			return 1;
		}

		if((mask = strchr(line,'/'))){
			*mask++ = '\0';
			if(*mask == '\0'){
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
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
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid address \"%s\": %s",line,
					gai_strerror(tint));
			return 1;
		}
		else if(!res){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid address \"%s\".",line);
			return 1;
		}

		switch(res->ai_family){
			struct sockaddr_in	*saddr4;
#ifdef	AF_INET6
			struct sockaddr_in6	*saddr6;

		case AF_INET6:
			saddr6 = (struct sockaddr_in6*)res->ai_addr;
			tpid.net.addrsize = 16;
			memcpy(tpid.net.addrval,saddr6->sin6_addr.s6_addr,16);
			break;
#endif
		case AF_INET:
			saddr4 = (struct sockaddr_in*)res->ai_addr;
			tpid.net.addrsize = 4;
			memcpy(tpid.net.addrval,&saddr4->sin_addr.s_addr,4);
			break;

		default:
			freeaddrinfo(res);
			IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
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
				IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
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
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
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
				IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
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
		if(!(line = strtok(NULL,IPFDWSPACESET))){
			return 1;
		}
		key.dptr = line;
		key.dsize = strlen(line);

		if((key.dsize >= sizeof(tpid.user.userid)) ||
					!I2HashFetch(policy->keys,key,&val)){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
					"Invalid user \"%s\".",line);
			return 1;
		}

		tpid.id_type = IPFDPidUserType;
		strcpy(tpid.user.userid,line);
	}
	else{
		IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
				"Unknown \"assign\" specification.");
		return 1;
	}

	/*
	 * The Pid is valid - now parse and check for limits for
	 * the "classname".
	 */
	if(!(line = strtok(NULL,IPFDWSPACESET))){
		return 1;
	}

	key.dptr = line;
	key.dsize = strlen(line);
	if(!I2HashFetch(policy->limits,key,&val)){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
				"Unknown limitclass name \"%s\".",line);
		return 1;
	}

	if(!(pid = malloc(sizeof(*pid)))){
		IPFError(policy->ctx,IPFErrFATAL,errno,
				"malloc(IPFDPidRec): %M");
		return 1;
	}
	memcpy(pid,&tpid,sizeof(*pid));
	key.dptr = pid;
	key.dsize = sizeof(*pid);
	if(I2HashStore(policy->idents,key,val) != 0){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Unable to store assign description!");
		return 1;
	}

	return 0;
}

static int
parselimits(
	IPFDPolicy	policy,
	FILE		*fp,
	char		**lbuf,
	size_t		*lbuf_max
	)
{
	int	rc = 0;
	size_t	i;
	size_t	maxlim = 0;
	char	*line;

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
	while(fp && ((rc = IPFDGetConfLine(policy->ctx,fp,rc,lbuf,lbuf_max)) > 0)){
		line = *lbuf;

		/*
		 * parse limit lines. (These create the "user classes" and
		 * specify the "authorization" level of that authenticated
		 * "user class".
		 */
		if(!strncasecmp(line,"limit",5)){
			line += 5;
			while(isspace(*line)){
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
			while(isspace(*line)){
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

		IPFError(policy->ctx,IPFErrWARNING,IPFErrUNKNOWN,
					"WARNING: No limits specified.");

		line = *lbuf;
		if(sizeof(defline) > *lbuf_max){
			*lbuf_max += IPFDLINEBUFINC;
			*lbuf = realloc(line,sizeof(char) * *lbuf_max);
			if(!*lbuf){
				if(line){
					free(line);
				}
				IPFError(policy->ctx,IPFErrFATAL,errno,
						"realloc(%u): %M",*lbuf_max);
				return -1;
			}
			line = *lbuf;
		}
		strcpy(line,defline);
		if(parselimitline(policy,line,maxlim) != 0){
			IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Unable to install default (open) limits");
			return -1;
		}
	}


	return rc;
}

/*
 * Function:	node_dir
 *
 * Description:	
 * 	This function creates a directory hierarchy based at datadir equivalent
 * 	to the "class" hierarchy reference by node. i.e. It traverses up
 * 	the "node" to determine all the parent nodes that should be above
 * 	it and uses the node names to create directory names.
 *
 * 	The "memory" record is PATH_MAX+1 bytes long - add_chars is used
 * 	to keep track of the number of bytes that are needed "after" this
 * 	node in the recursion to allow for graceful failure.
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
static char *
node_dir(
		IPFContext	ctx,
		IPFBoolean	make,
		char		*datadir,
		IPFDPolicyNode	node,
		unsigned int	add_chars,
		char		*memory
	      )
{
	char		*path;
	int		len;

	if(node){
		path = node_dir(ctx,make,datadir,node->parent,
				strlen(node->nodename) +
				IPF_PATH_SEPARATOR_LEN + add_chars, memory);
		if(!path)
			return NULL;
		strcat(path,IPF_PATH_SEPARATOR);
		strcat(path,node->nodename);
	} 
	else {
		len = strlen(datadir) + IPF_PATH_SEPARATOR_LEN
			+ strlen(IPF_HIER_DIR) + add_chars;
		if(len > PATH_MAX){
			IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Data file path length too long.");
			return NULL;
		}
		path = memory;
		
		strcpy(path,datadir);
		strcat(path,IPF_PATH_SEPARATOR);
		strcat(path, IPF_HIER_DIR);
	}
	
	if(make && (mkdir(path,0755) != 0) && (errno != EEXIST)){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"Unable to mkdir(%s): %M",path);
		return NULL;
	}

	return path;
}

/*
 * Function:	IPFDPolicyInstall
 *
 * Description:	
 * 	This function installs the functions defined in this file as
 * 	the "policy" hooks within the ipcntrl application.
 *
 * 	The main reason for defining the policy in the ipcntrl library
 * 	like this was that it made it possible to share the policy
 * 	code between client/server applications such as owping and
 * 	iperfcd. Also, it is a good example of how this can be done for
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
IPFDPolicy
IPFDPolicyInstall(
	IPFContext	ctx,
	char		*datadir,
	char		*confdir,
	char		**lbuf,
	size_t		*lbuf_max
	)
{
	IPFDPolicy		policy;
	I2ErrHandle		eh;
	char			fname[MAXPATHLEN+1];
	int			len;
	FILE			*fp;
	int			rc;	/* row count */

	/*
	 * use variables for the func pointers so the compiler can give
	 * type-mismatch warnings.
	 */
	IPFGetAESKeyFunc		getaeskey = IPFDGetAESKey;
	IPFCheckControlPolicyFunc	checkcontrolfunc =
						IPFDCheckControlPolicy;
	IPFCheckTestPolicyFunc		checktestfunc =
						IPFDCheckTestPolicy;
	IPFTestCompleteFunc		testcompletefunc = IPFDTestComplete;


	eh = IPFContextGetErrHandle(ctx);

	/*
	 * Alloc main policy record
	 */
	if(!(policy = calloc(1,sizeof(*policy)))){
		IPFError(ctx,IPFErrFATAL,errno,"calloc(policy rec): %M");
		return NULL;
	}

	policy->ctx = ctx;

	/*
	 * copy datadir
	 */
	if(!datadir){
		datadir = ".";
	}
	if(!(policy->datadir = strdup(datadir))){
		IPFError(ctx,IPFErrFATAL,errno,"strdup(datadir): %M");
		return NULL;
	}

	/*
	 * Alloc hashes.
	 */
	if(!(policy->limits = I2HashInit(eh,0,NULL,NULL)) ||
			!(policy->idents =
				I2HashInit(eh,0,NULL,NULL)) ||
			!(policy->keys = I2HashInit(eh,0,NULL,NULL))){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"IPFDPolicyInstall: Unable to allocate hashes");
		return NULL;
	}

	/*
	 * Open the keys file.
	 */
	fname[0] = '\0';
	len = strlen(IPF_KEY_FILE);
	if(len > MAXPATHLEN){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"strlen(IPF_KEY_FILE > MAXPATHLEN)");
		return NULL;
	}

	len += strlen(confdir) + strlen(IPF_PATH_SEPARATOR);
	if(len > MAXPATHLEN){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"Path to %s > MAXPATHLEN",IPF_KEY_FILE);
		return NULL;
	}
	strcpy(fname,confdir);
	strcat(fname,IPF_PATH_SEPARATOR);
	strcat(fname,IPF_KEY_FILE);
	if(!(fp = fopen(fname,"r")) && (errno != ENOENT)){
		IPFError(ctx,IPFErrFATAL,errno,"Unable to open %s: %M",fname);
		return NULL;
	}

	/*
	 * lbuf is a char buffer that grows as needed in IPFDGetConfLine
	 * lbuf will be realloc'd repeatedly as needed. Once conf file
	 * parsing is complete - it is free'd from this function.
	 */
	if((rc = parsekeys(policy,fp,lbuf,lbuf_max)) < 0){
		goto BADLINE;
	}

	if(fp && (fclose(fp) != 0)){
		IPFError(ctx,IPFErrFATAL,errno,"fclose(%s): %M",fname);
		return NULL;
	}

	/*
	 * Open the limits file.
	 */
	fname[0] = '\0';
	len = strlen(IPF_LIMITS_FILE);
	if(len > MAXPATHLEN){
		IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
				"strlen(IPF_LIMITS_FILE > MAXPATHLEN)");
		return NULL;
	}

	len += strlen(confdir) + strlen(IPF_PATH_SEPARATOR);
	if(len > MAXPATHLEN){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"Path to %s > MAXPATHLEN",IPF_LIMITS_FILE);
		return NULL;
	}
	strcpy(fname,confdir);
	strcat(fname,IPF_PATH_SEPARATOR);
	strcat(fname,IPF_LIMITS_FILE);

	if(!(fp = fopen(fname,"r"))){
		if(errno != ENOENT){
			IPFError(ctx,IPFErrFATAL,errno,"Unable to open %s: %M",
					fname);
			return NULL;
		}
	}

	rc = parselimits(policy,fp,lbuf,lbuf_max); 

BADLINE:

	if(rc < 0){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
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

	if(!IPFContextConfigSet(ctx,IPFDPOLICY,policy)){
		return NULL;
	}
	if(!IPFContextConfigSet(ctx,IPFGetAESKey,(void*)getaeskey)){
		return NULL;
	}
	if(!IPFContextConfigSet(ctx,IPFCheckControlPolicy,(void*)checkcontrolfunc)){
		return NULL;
	}
	if(!IPFContextConfigSet(ctx,IPFCheckTestPolicy,(void*)checktestfunc)){
		return NULL;
	}
	if(!IPFContextConfigSet(ctx,IPFTestComplete,(void*)testcompletefunc)){
		return NULL;
	}

	return policy;
}

/*
 * Function:	IPFDGetAESKey
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
extern IPFBoolean
IPFDGetAESKey(
	IPFContext	ctx,
	const IPFUserID	userid,
	IPFKey		key_ret,
	IPFErrSeverity	*err_ret
	)
{
	IPFDPolicy	policy;
	I2Datum		key,val;

	*err_ret = IPFErrOK;

	if(!(policy = (IPFDPolicy)IPFContextConfigGet(ctx,IPFDPOLICY))){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFDGetAESKey: IPFDPOLICY not set");
		*err_ret = IPFErrFATAL;
		return False;
	}

	key.dptr = (void*)userid;
	key.dsize = strlen(userid);
	if(!I2HashFetch(policy->keys,key,&val)){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrPOLICY,
				"userid \"%s\" unknown",userid);
		return False;
	}

	memcpy(key_ret,val.dptr,sizeof(key_ret));

	return True;
}

static IPFDPolicyNode
GetNodeDefault(
	IPFDPolicy	policy
	)
{
	IPFDPidRec	tpid;
	I2Datum		key,val;

	memset(&tpid,0,sizeof(tpid));

	tpid.id_type = IPFDPidDefaultType;
	key.dptr = &tpid;
	key.dsize = sizeof(tpid);
	if(I2HashFetch(policy->idents,key,&val)){
		return (IPFDPolicyNode)val.dptr;
	}

	return policy->root;
}

static IPFDPolicyNode
GetNodeFromAddr(
	IPFDPolicy	policy,
	struct sockaddr	*remote_sa_addr
	)
{
	IPFDPidRec	pid;
	u_int8_t	nbytes,nbits,*ptr;
	I2Datum		key,val;

	memset(&pid,0,sizeof(pid));

	pid.id_type = IPFDPidNetmaskType;
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
		IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
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
			return (IPFDPolicyNode)val.dptr;
		}
	}

	return GetNodeDefault(policy);
}

static IPFDLimitT
GetLimit(
	IPFDPolicyNode	node,
	IPFDMesgT	lim
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

static IPFDLimitT
GetUsed(
	IPFDPolicyNode	node,
	IPFDMesgT	lim
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

static IPFBoolean
IntegerResourceDemand(
	IPFDPolicyNode	node,
	IPFDMesgT	query,
	IPFDLimRec	lim
	)
{
	size_t	i;
	double	fudge = 1.0;

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
		return IntegerResourceDemand(node->parent,query,lim);
	}

	/*
	 * Deal with resource releases.
	 */
	else if(query == IPFDMESGRELEASE){
		if(lim.value > node->used[i].value){
			IPFError(node->policy->ctx,IPFErrFATAL,IPFErrPOLICY,
				"Request to release unallocated resouces: "
				"%s:%s (currently allocated = %u, "
				"release amount = %u)",node->nodename,
				GetLimName(lim.limit),node->used[i].value,
				lim.value);
			return False;
		}
		
		if(!IntegerResourceDemand(node->parent,query,lim)){
			return False;
		}

		node->used[i].value -= lim.value;

		return True;
	}

	/*
	 * The rest deals with resource requests.
	 */

	/*
	 * If this is a IPFDMESGCLAIM request - apply the fudge factor.
	 * TODO: This was used to increase the amount of disk *actually*
	 * used by the test, but may not be needed for iperf... I will
	 * leave the MESGCLAIM message as valid for now, and just report
	 * an invalid claim request so I can easily add fudged limits if
	 * needed.
	 */
	if(query == IPFDMESGCLAIM){
		switch(lim.limit){

			default:
			IPFError(node->policy->ctx,IPFErrFATAL,IPFErrPOLICY,
					"Invalid \"CLAIM\" request");
			return False;
		}
	}
	else if(query != IPFDMESGREQUEST){
		IPFError(node->policy->ctx,IPFErrFATAL,IPFErrPOLICY,
				"Unknown resource request type: %u",query);
		return False;
	}

	/*
	 * If this level doesn't have the resources available - return false.
	 */
	if((lim.value+node->used[i].value) > (node->limits[i].value * fudge)){
		return False;
	}

	/*
	 * Are the resource available the next level up?
	 */
	if(!IntegerResourceDemand(node->parent,query,lim)){
		return False;
	}

	node->used[i].value += lim.value;

	return True;
}

IPFBoolean
IPFDResourceDemand(
	IPFDPolicyNode	node,
	IPFDMesgT	query,
	IPFDLimRec	lim
	)
{
	size_t		maxdef = I2Number(limkeys);
	size_t		i;
	enum limtype	limkind = LIMNOT;
	IPFDLimitT	val;
	IPFBoolean	ret;

	for(i=0;i<maxdef;i++){
		if(lim.limit == limkeys[i].limit){
			limkind = limkeys[i].ltype;
			break;
		}
	}

	if(limkind == LIMNOT){
		return False;
	}

	if(limkind == LIMBOOLVAL){
		if(query == IPFDMESGRELEASE){
			return True;
		}
		val = GetLimit(node,lim.limit);
		return (val == lim.value);
	}

	ret = IntegerResourceDemand(node,query,lim);

	/*
	 * These messages are printed to INFO so they can be selected
	 * as non-interesting.
	 */
	IPFError(node->policy->ctx,IPFErrINFO,IPFErrPOLICY,
		"ResReq %s: %s:%s:%s = %llu (result = %llu, limit = %llu)",
		(ret)?"ALLOWED":"DENIED",
		node->nodename,
		(query == IPFDMESGRELEASE)?"release":"request",
		GetLimName(lim.limit),
		lim.value,
		GetUsed(node,lim.limit),
		GetLimit(node,lim.limit));
	for(node = node->parent;!ret && node;node = node->parent){
		IPFError(node->policy->ctx,IPFErrINFO,IPFErrPOLICY,
		"ResReq %s: %s:%s:%s = %llu (result = %llu, limit = %llu)",
		(ret)?"ALLOWED":"DENIED",
		node->nodename,
		(query == IPFDMESGRELEASE)?"release":"request",
		GetLimName(lim.limit),
		lim.value,
		GetUsed(node,lim.limit),
		GetLimit(node,lim.limit));
	}

	return ret;
}

/*
 * Function:	IPFDSendResponse
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
IPFDSendResponse(
		int		fd,
		IPFDMesgT	mesg
		)
{
	IPFDMesgT	buf[3];
	int		fail_on_intr=1;

	buf[0] = buf[2] = IPFDMESGMARK;
	buf[1] = mesg;

	if(I2Writeni(fd,&buf[0],12,&fail_on_intr) != 12){
		return 1;
	}

	return 0;
}

/*
 * Function:	IPFDReadResponse
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
static IPFDMesgT
IPFDReadResponse(
		int		fd
		)
{
	IPFDMesgT	buf[3];
	int		fail_on_intr=1;

	if(I2Readni(fd,&buf[0],12,&fail_on_intr) != 12){
		return IPFDMESGINVALID;
	}

	if((buf[0] != IPFDMESGMARK) || (buf[2] != IPFDMESGMARK)){
		return IPFDMESGINVALID;
	}

	return buf[1];
}

/*
 * Function:	IPFDReadClass
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
IPFDPolicyNode
IPFDReadClass(
	IPFDPolicy	policy,
	int		fd,
	int		*err
	)
{
	ssize_t		i;
	const IPFDMesgT	mark=IPFDMESGMARK;
	const IPFDMesgT	mclass=IPFDMESGCLASS;
	u_int8_t	buf[IPFDMAXCLASSLEN+1 + sizeof(IPFDMesgT)*3];
	I2Datum		key,val;
	int		fail_on_intr=1;

	*err = 1;

	/*
	 * Read message header
	 */
	if((i = I2Readni(fd,&buf[0],8,&fail_on_intr)) != 8){
		if(i == 0){
			*err = 0;
		}
		return NULL;
	}

	if(memcmp(&buf[0],&mark,sizeof(IPFDMesgT)) ||
			memcmp(&buf[4],&mclass,sizeof(IPFDMesgT))){
		return NULL;
	}

	/*
	 * read classname
	 */
	for(i=0;i<= IPFDMAXCLASSLEN;i++){
		if(I2Readni(fd,&buf[i],1,&fail_on_intr) != 1){
			return NULL;
		}

		if(buf[i] == '\0'){
			break;
		}
	}

	if(i > IPFDMAXCLASSLEN){
		return NULL;
	}

	key.dptr = &buf[0];
	key.dsize = i;

	/*
	 * read message trailer.
	 */
	i++;
	if((I2Readni(fd,&buf[i],4,&fail_on_intr) != 4) ||
			memcmp(&buf[i],&mark,sizeof(IPFDMesgT))){
		return NULL;
	}

	if(I2HashFetch(policy->limits,key,&val)){
		if(IPFDSendResponse(fd,IPFDMESGOK) != 0){
			return NULL;
		}
		*err = 0;
		return val.dptr;
	}

	(void)IPFDSendResponse(fd,IPFDMESGDENIED);
	return NULL;
}

static IPFDMesgT
IPFDSendClass(
	IPFDPolicy	policy,
	IPFDPolicyNode	node
	)
{
	u_int8_t	buf[IPFDMAXCLASSLEN+1 + sizeof(IPFDMesgT)*3];
	IPFDMesgT	mesg;
	ssize_t		len;
	int		fail_on_intr=1;

	mesg = IPFDMESGMARK;
	memcpy(&buf[0],&mesg,4);
	mesg = IPFDMESGCLASS;
	memcpy(&buf[4],&mesg,4);
	len = strlen(node->nodename);
	len++;
	strncpy((char*)&buf[8],node->nodename,len);
	len += 8;
	mesg = IPFDMESGMARK;
	memcpy(&buf[len],&mesg,4);
	len += 4;

	if(I2Writeni(policy->fd,buf,len,&fail_on_intr) != len){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"IPFDCheckControlPolicy: Unable to contact parent");
		return IPFDMESGINVALID;
	}

	return IPFDReadResponse(policy->fd);
}

/*
 * True if there is a request
 */
IPFBoolean
IPFDReadQuery(
	int		fd,
	IPFDMesgT	*query,
	IPFDLimRec	*lim_ret,
	int		*err
	)
{
	ssize_t		i;
	IPFDMesgT	buf[7];
	int		fail_on_intr=1;

	*err = 1;

	/*
	 * Read message header
	 */
	if((i = I2Readni(fd,&buf[0],28,&fail_on_intr)) != 28){
		if(i == 0){
			*err = 0;
		}
		return False;
	}

	if((buf[0] != IPFDMESGMARK) || (buf[6] != IPFDMESGMARK) ||
			(buf[1] != IPFDMESGRESOURCE)){
		return False;
	}

	switch(buf[2]){
		case IPFDMESGREQUEST:
		case IPFDMESGRELEASE:
			*query = buf[2];
			break;
		default:
			return False;
	}

	lim_ret->limit = buf[3];
	memcpy(&lim_ret->value,&buf[4],8);

	*err = 0;

	return True;
}

static IPFDMesgT
IPFDQuery(
	IPFDPolicy	policy,
	IPFDMesgT	mesg,	/* IPFDMESGREQUEST or IPFDMESGRELEASE	*/
	IPFDLimRec	lim
	)
{
	IPFDMesgT	buf[7];
	int		fail_on_intr=1;

	buf[0] = buf[6] = IPFDMESGMARK;
	buf[1] = IPFDMESGRESOURCE;
	buf[2] = mesg;
	buf[3] = lim.limit;
	memcpy(&buf[4],&lim.value,8);

	if(I2Writeni(policy->fd,buf,28,&fail_on_intr) != 28){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrUNKNOWN,
			"IPFDQuery: Unable to contact parent");
		return IPFDMESGINVALID;
	}

	return IPFDReadResponse(policy->fd);
}

/*
 * Function:	IPFDAllowOpenMode
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
IPFBoolean
IPFDAllowOpenMode(
	IPFDPolicy	policy,
	struct sockaddr	*remote_sa_addr,
	IPFErrSeverity	*err_ret	 /* error - return     	*/
	)
{
	IPFDPolicyNode	node;

	*err_ret = IPFErrOK;

	if(!(node = GetNodeFromAddr(policy,remote_sa_addr))){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFDAllowOpenMode: Invalid policy");
		*err_ret = IPFErrFATAL;
		return False;
	}

	return GetLimit(node,IPFDLimAllowOpenMode);
}

/*
 * Function:	IPFDCheckControlPolicy
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
IPFBoolean
IPFDCheckControlPolicy(
	IPFControl	cntrl,
	IPFSessionMode	mode,			/* requested mode	*/
	const IPFUserID	userid,			/* identity		*/
	struct sockaddr	*local_sa_addr __attribute__((unused)),
						/* local addr or NULL	*/
	struct sockaddr	*remote_sa_addr,	/* remote addr		*/
	IPFErrSeverity	*err_ret		/* error - return     	*/
)
{
	IPFContext	ctx;
	IPFDPolicy	policy;
	IPFDPolicyNode	node=NULL;
	I2Datum		key,val;
	IPFDMesgT	ret;

	*err_ret = IPFErrOK;

	ctx = IPFGetContext(cntrl);

	if(!(policy = (IPFDPolicy)IPFContextConfigGet(ctx,IPFDPOLICY))){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFDCheckControlPolicy: IPFDPOLICY not set");
		*err_ret = IPFErrFATAL;
		return False;
	}

	/*
	 * Determine userclass and send that to the parent.
	 * (First try based on userid.)
	 */
	if((mode & IPF_MODE_DOCIPHER) && userid){
		key.dptr = (void*)userid;
		key.dsize = strlen(userid);

		if(I2HashFetch(policy->limits,key,&val)){
			node = val.dptr;
		}
	}

	/*
	 * If we don't have a userclass from the userid, then get one
	 * based on the address. (This returns the default if no
	 * address matched.)
	 */
	if(!node && !(node = GetNodeFromAddr(policy,remote_sa_addr))){
		IPFError(policy->ctx,IPFErrFATAL,IPFErrINVALID,
				"IPFDCheckControlPolicy: Invalid policy");
		*err_ret = IPFErrFATAL;
		return False;
	}

	/*
	 * Initialize the communication with the parent resource broker
	 * process.
	 */
	if((ret = IPFDSendClass(policy,node)) == IPFDMESGOK){
		/*
		 * Success - now save the node in the control config
		 * for later hook functions to access.
		 */
		if(!IPFControlConfigSet(cntrl,IPFDPOLICY_NODE,node)){
			IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
	"IPFDCheckControlPolicy: Unable to save \"class\" for connection");
			*err_ret = IPFErrFATAL;
			return False;
		}

		return True;
	}

	/*
	 * If ret wasn't IPFDMESGDENIED - there was some kind of error.
	 */
	if(ret != IPFDMESGDENIED){
		*err_ret = IPFErrFATAL;
	}

	return False;
}

/*
 * This structure is used to keep track of the path information used by
 * a fp allocated by the IPFDOpenFile function.
 * This macro is the prefix for a given finfo in the cntrl Config table. The
 * fd number is concatenated to this string (in ascii) to get a key for
 * adding and removing a finfo record to the Config table.
 */
#define	IPFDPOLICY_KEYLEN	64
#define	IPFDPOLICY_FILEINFO	"IPFDPOLICY_FILEINFO"
typedef struct IPFDFileInfoRec{
	FILE			*fp;
	char			filepath[PATH_MAX+1];
	char			linkpath[PATH_MAX+1];
	IPFDPolicyNode	node;
} IPFDFileInfoRec, *IPFDFileInfo;

/*
 * This structure is returned in the "closure" pointer of the CheckTestPolicy
 * pointer - and provided to the Open/Close file functions as well as the
 * TestComplete function.
 */
typedef struct IPFDTestInfoRec{
	IPFDPolicyNode	node;
	IPFDFileInfo	finfo;
	IPFDLimRec	res[2];	/* 0=bandwidth,1=disk */
} IPFDTestInfoRec, *IPFDTestInfo;

IPFBoolean
IPFDCheckTestPolicy(
	IPFControl	cntrl,
	IPFBoolean	local_sender,
	struct sockaddr	*local_sa_addr	__attribute__((unused)),
	struct sockaddr	*remote_sa_addr,
	socklen_t	sa_len	__attribute__((unused)),
	IPFTestSpec	*test_spec,
	void		**closure,
	IPFErrSeverity	*err_ret
)
{
	IPFContext	ctx = IPFGetContext(cntrl);
	IPFDPolicyNode	node;
	IPFDTestInfo	tinfo;
	IPFDMesgT	ret;

	*err_ret = IPFErrOK;

	/*
	 * Fetch the "user class" for this connection.
	 */
	if(!(node = (IPFDPolicyNode)IPFControlConfigGet(cntrl,
						IPFDPOLICY_NODE))){
		IPFError(ctx,IPFErrFATAL,IPFErrINVALID,
			"IPFDCheckTestPolicy: IPFDPOLICY_NODE not set");
		*err_ret = IPFErrFATAL;
		return False;
	}


	if(!(tinfo = calloc(1,sizeof(IPFDTestInfoRec)))){
		IPFError(ctx,IPFErrFATAL,errno,"calloc(1,IPFDTestInfoRec): %M");
		*err_ret = IPFErrFATAL;
		return False;
	}

	tinfo->node = node;

	/* TODO: VAlIDATE THE REQUEST! */
#if	TODO
	/*
	 * Check bandwidth
	 */
	tinfo->res[0].limit = IPFDLimBandwidth;
	tinfo->res[0].value = IPFTestPacketBandwidth(ctx,
			remote_sa_addr->sa_family,IPFGetMode(cntrl),test_spec);
	if((ret = IPFDQuery(node->policy,IPFDMESGREQUEST,tinfo->res[0]))
							== IPFDMESGDENIED){
		goto done;
	}
	if(ret == IPFDMESGINVALID){
		*err_ret = IPFErrFATAL;
		goto done;
	}


	/*
	 * If we are receiver - check disk-space.
	 */
	if(!local_sender){
		/*
		 * Request 10% more than our estimate to cover duplicates.
		 * reality will be adjusted in CloseFile.
		 */
		tinfo->res[1].limit = IPFDLimDisk;
		tinfo->res[1].value = IPFTestDiskspace(test_spec);

		if((ret = IPFDQuery(node->policy,IPFDMESGREQUEST,tinfo->res[1]))
							== IPFDMESGDENIED){
			IPFDQuery(node->policy,IPFDMESGRELEASE,tinfo->res[0]);
			goto done;
		}
		if(ret == IPFDMESGINVALID){
			*err_ret = IPFErrFATAL;
			goto done;
		}
	}
#endif

	*closure = tinfo;
	return True;
done:
	free(tinfo);
	return False;
}

extern void
IPFDTestComplete(
	IPFControl	cntrl __attribute__((unused)),
	void		*closure,	/* closure from CheckTestPolicy	*/
	IPFAcceptType	aval __attribute__((unused))
	)
{
	IPFDTestInfo	tinfo = (IPFDTestInfo)closure;
	int		i;

	for(i=0;i<2;i++){
		if(!tinfo->res[i].limit){
			continue;
		}
		(void)IPFDQuery(tinfo->node->policy,IPFDMESGRELEASE,
								tinfo->res[i]);
	}

	free(tinfo);

	return;
}
