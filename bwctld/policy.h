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
 *	File:		policy.h
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep 16 14:29:07 MDT 2003
 *
 *	Description:	
 *			This file declares the types needed by applications
 *			to use the "default" 
 *
 */
#ifndef	_IPF_DEFAULTS_H
#define	_IPF_DEFAULTS_H

#include <I2util/util.h>
#include <ipcntrl/ipcntrl.h>

#ifndef	IPF_KEY_FILE
#define	IPF_KEY_FILE		"iperfcd.keys"
#endif

#ifndef	IPF_LIMITS_FILE
#define	IPF_LIMITS_FILE		"iperfcd.limits"
#endif

/*
 * Defines for path elements of the server datastore:
 * 	datadir/
 * 		catalog/
 * 			(symlinks named by SID pointing to real files
 * 			in datadir/nodes.)
 * 		nodes/
 * 			(dir hier based on user classification hier.)
 * 			This allows filesystem based limits to be used
 * 			by mounting a particular filesystem into this
 * 			hierarchy.
 */
#ifndef	IPF_CATALOG_DIR
#define	IPF_CATALOG_DIR         "catalog"
#endif
#ifndef	IPF_HIER_DIR
#define	IPF_HIER_DIR            "hierarchy"
#endif

/*
 * Holds the policy record that was parsed and contains all the "limits"
 * and identity information.
 *
 * type: (owp_policy_data*) - defined in access.h
 * location: Context Config
 */
#define IPFDPOLICY	"IPFDPOLICY"

/*
 * Holds the identifying "node" from the policy tree that contains the
 * class and limits information for the given control connection.
 *
 * type: (owp_tree_node_ptr) - defined in access.h
 * location: Control Config
 */
#define IPFDPOLICY_NODE	"IPFDPOLICY_NODE"

/*
 * Types used by policy functions
 */
#define IPFDMAXCLASSLEN	(80)

typedef struct IPFDPolicyRec IPFDPolicyRec, *IPFDPolicy;
typedef struct IPFDPolicyNodeRec IPFDPolicyNodeRec, *IPFDPolicyNode;
typedef struct IPFDPolicyKeyRec IPFDPolicyKeyRec, *IPFDPolicyKey;

struct IPFDPolicyRec{
	IPFContext		ctx;

	double			diskfudge;

	int			fd;	/* socket to parent. */
	char			*datadir;

	IPFDPolicyNode		root;

	/* limits:
	 * 	key = char* (classname from "limit" lines)
	 * 	val = IPFDPolicyNode
	 */
	I2Table			limits;
	/* idents:
	 * 	key = IPFDPid
	 * 	val = IPFDPolicyNode
	 */
	I2Table			idents;
	/* keys:
	 * 	key = u_int8_t[16]	(username from ipcntrl protocol)
	 * 	val = IPFKey
	 */
	I2Table			keys;

};

typedef u_int64_t	IPFDLimitT;		/* values */
typedef u_int32_t	IPFDMesgT;

typedef struct IPFDLimRec{
	IPFDMesgT	limit;
	IPFDLimitT	value;
} IPFDLimRec;

/* parent		cname		*/
/* bandwidth		uint (bits/sec)*/
/* delete_on_fetch	on/(off)	*/
/* allow_open_mode	(on)/off	*/

#define	IPFDLimParent		0
#define	IPFDLimBandwidth	1
#define	IPFDLimPending		2
#define	IPFDLimEventHorizon	3
#define	IPFDLimDuration		4
#define	IPFDLimAllowOpenMode	5
#define	IPFDLimAllowTCP		6
#define	IPFDLimAllowUDP		7

struct IPFDPolicyNodeRec{
	IPFDPolicy		policy;
	char			*nodename;
	IPFDPolicyNode		parent;
	size_t			ilim;
	IPFDLimRec		*limits;
	IPFDLimRec		*used;
	off_t			initdisk;
};

typedef enum{
	IPFDPidInvalid=0,
	IPFDPidDefaultType,
	IPFDPidNetmaskType,
	IPFDPidUserType
} IPFDPidType;

typedef struct{
	IPFDPidType	id_type;
	u_int8_t	mask_len;
	size_t		addrsize;
	u_int8_t	addrval[16];
} IPFDPidNetmask;

typedef struct{
	IPFDPidType	id_type;
	IPFUserID	userid;
} IPFDPidUser;

typedef union IPFDPidUnion{
	IPFDPidType	id_type;
	IPFDPidNetmask	net;
	IPFDPidUser	user;
} IPFDPidRec, *IPFDPid;

/*
 * The following section defines the message tags used to communicate
 * from the children processes to the parent to request/release
 * resources on a global basis.
 *
 * All message "type" defines will be of type IPFDMesgT.
 */
#define	IPFDMESGMARK		0xfefefefe
#define	IPFDMESGCLASS		0xcdef
#define	IPFDMESGRESOURCE	0xbeef
#define	IPFDMESGREQUEST		0xfeed
#define	IPFDMESGRELEASE		0xdead
#define	IPFDMESGCLAIM		0x1feed1

/*
 * "parent" response messages will be one of:
 */
#define IPFDMESGINVALID	0x0
#define IPFDMESGOK	0x1
#define IPFDMESGDENIED	0x2

/*
 * After forking, the new "server" process (called "child" in the following)
 * should determine the "usage class" the given connection should belong to.
 * The first message to the "parent" master process should communicate this
 * information so that all further resource requests/releases are relative
 * to that "usage class". The format of this message should be as follows:
 *
 * (All integers are in host order since this is expected to be ipc
 * communication on a single host. It could be a future enhancement to
 * allow a "single" distributed iperfcd IPCNTRL-Control server to manage
 * multiple test  endpoints at which time it might be worth the overhead
 * to deal with byte ordering issues.)
 *
 * Initial child->parent message:
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                      IPFDMESGMARK                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                      IPFDMESGCLASS                            |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	            [nul terminated ascii string of classname]
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                      IPFDMESGMARK                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * There is one other child message format. This message is used to either
 * request or release resources. (The parent should release all "temporary"
 * resources (i.e. bandwidth) on exit of the child if the child does not
 * explicitly release the resource. More "permenent" resources should only
 * be released explicitly (i.e. disk-space).
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                      IPFDMESGMARK                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                     IPFDMESGRESOURCE                          |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                IPFDMESGWANT|IPFDMESGRELEASE                   |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	12|                      IPFDMesgT(limit name)                    |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	16|                        IPFDLimitT                             |
 *	20|                                                               |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	24|                      IPFDMESGMARK                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Parent responses are all of the format:
 *
 * 	   0                   1                   2                   3
 * 	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	00|                      IPFDMESGMARK                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	04|                IPFDMESGOK|IPFDMESGDENIED                      |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *	08|                      IPFDMESGMARK                             |
 *	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/*
 * The following api convienence functions are defined to make the child/parent
 * communication easier. (These are the functions needed by the parent in
 * the master iperfcd "resource broker" process.)
 */

extern IPFDPolicyNode
IPFDReadClass(
	IPFDPolicy	policy,
	int		fd,
	int		*err
	);

/*
 * returns True on success - query/lim_ret will contain request
 * err will be non-zero on error. 0 on empty read.
 */
extern IPFBoolean
IPFDReadQuery(
	int		fd,
	IPFDMesgT	*query,
	IPFDLimRec	*lim_ret,
	int		*err
	);

extern int
IPFDSendResponse(
	int		fd,
	IPFDMesgT	mesg
	);

/*
 * This function is used to add/subtract resource allocations from the
 * current tree of resource usage. It is only used in the resource
 * broker process.
 */
extern IPFBoolean
IPFDResourceDemand(
		IPFDPolicyNode	node,
		IPFDMesgT	query,
		IPFDLimRec	lim
		);
/*
 * Functions called directly from iperfcd regarding "policy" decisions
 * (If false, check err_ret to determine if it is an "error" condition,
 * or if open_mode is simply denied.)
 */
extern IPFBoolean
IPFDAllowOpenMode(
	IPFDPolicy	policy,
	struct sockaddr	*peer_addr,
	IPFErrSeverity	*err_ret
	);

/*
 * Functions actually used to install policy hooks into libipcntrl.
 */
extern IPFBoolean
IPFDGetAESKey(
	IPFContext	ctx,
	const IPFUserID	userid,
	u_int8_t	*key_ret,
	IPFErrSeverity	*err_ret
	);

extern IPFBoolean
IPFDCheckControlPolicy(
	IPFControl	cntrl,
	IPFSessionMode	mode,
	const IPFUserID	userid,
	struct sockaddr	*local_saddr,
	struct sockaddr	*remote_saddr,
	IPFErrSeverity	*err_ret
	);

extern IPFBoolean
IPFDCheckTestPolicy(
	IPFControl	cntrl,
	IPFBoolean	local_sender,
	struct sockaddr	*local_saddr,
	struct sockaddr	*remote_saddr,
	socklen_t	sa_len,
	IPFTestSpec	*test_spec,
	void		**closure,
	IPFErrSeverity	*err_ret
	);

extern void
IPFDTestComplete(
	IPFControl	cntrl,
	void		*closure,
	IPFAcceptType	aval
	);

extern IPFDPolicy
IPFDPolicyInstall(
	IPFContext	ctx,
	char		*datadir,	/* root dir for datafiles	*/
	char		*confdir,	/* conf dir for policy		*/
	char		**lbuf,
	size_t		*lbuf_max
	);

#endif	/*	_IPF_DEFAULTS_H	*/
