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
 *	File:		iperfc.c
 *
 *	Authors:	Jeff Boote
 *			Internet2
 *
 *	Date:		Fri Sep 12 13:36:28 MDT 2003
 *
 *	Description:	
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <I2util/util.h>
#include <ipcntrl/ipcntrl.h>

#include "./iperfcP.h"

/*
 * The iperfc context
 */
static ip_cntrl_trec	ip_ctx;
static I2ErrHandle	eh;

#define IPF_TMPFILE "/tmp/ipcntrl.XXXXXX"

#ifdef	NOT
static int
IPFingErrFunc(
	void		*app_data,
	IPFErrSeverity	severity	__attribute__((unused)),
	IPFErrType	etype,
	const char	*errmsg
)
{
	ip_cntrl_t		pctx = (ip_cntrl_t)app_data;

	/*
	 * If not debugging - only print messages of warning or worse.
	 * (unless of course verbose is specified...
	 */
#ifdef	NDEBUG
	if(!pctx->opt.verbose && (severity > IPFErrWARNING))
		return 0;
#endif

	I2ErrLogP(pctx->eh,etype,errmsg);

	return 0;
}
#endif
	
static void
print_conn_args()
{
	fprintf(stderr, "%s\n\n%s\n%s\n%s\n%s\n",
		"              [Connection Args]",
"   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen",
"   -k keyfile     AES keyfile to use with Authenticated/Encrypted modes",
"   -u username    username to use with Authenticated/Encrypted modes",
"   -S srcaddr     use this as a local address for control connection and tests");
}

static void
print_test_args()
{
	fprintf(stderr, "%s\n\n%s\n%s\n%s\n%s\n%s\n%s\n",
		"              [Test Args]",
"   -f | -F file   perform one-way test from testhost [and save results to file]",
"   -t | -T file   perform one-way test to testhost [and save results to file]",
"   -c count       number of test packets",
"   -i wait        mean average time between packets (seconds)",
"   -L timeout     maximum time to wait for a packet before declaring it lost",
"   -s padding     size of the padding added to each packet (bytes)");
}

static void
print_output_args()
{
	fprintf(stderr, "%s\n\n%s\n%s\n%s\n%s\n",
"              [Output Args]",
"   -h             print this message and exit",
"   -Q             run the test and exit without reporting statistics",
"   -R             print RAW data: \"SEQNO STIME SS SERR RTIME RS RERR\\n\"",
"   [-v|-V]        print out individual delays, or full timestamps",
"   -a alpha       report an additional percentile level for the delays"
		);
}

static void
usage(const char *progname, const char *msg)
{
	if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
	if (!strcmp(progname, "iperfc")) {
		fprintf(stderr,
			"usage: %s %s\n%s\n", 
			progname, "[arguments] testaddr [servaddr]",
			"[arguments] are as follows: "
			);
		fprintf(stderr, "\n");
		print_conn_args();
		
		fprintf(stderr, "\n");
		print_test_args();
		
		fprintf(stderr, "\n");
		print_output_args();
		
	} else if (!strcmp(progname, "owstats")) {
		fprintf(stderr,
			"usage: %s %s\n%s\n",
			progname, "[arguments] sessionfile",
			"[arguments] are as follows: "
			);
		fprintf(stderr, "\n");
		print_output_args();
	} else if (!strcmp(progname, "owfetch")) {
		fprintf(stderr,
			"usage: %s %s\n%s\n",
			progname, "[arguments] servaddr [SID savefile]+",
			"[arguments] are as follows: "
			);
		fprintf(stderr, "\n");
		print_conn_args();
		fprintf(stderr, "\n");
		print_output_args();
	}
	else{
		fprintf(stderr,
			"usage: %s is not a known name for this program.\n",progname);
	}

	return;
}

static void
FailSession(
	IPFControl	control_handle	__attribute__((unused))
	   )
{
	/*
	 * Session denied - report error, close connection, and exit.
	 */
	I2ErrLog(eh, "Session Failed!");
	fflush(stderr);

	/* TODO: determine "reason" for denial and report */
	(void)IPFControlClose(ip_ctx.cntrl);
	exit(1);
}

#define THOUSAND 1000.0

/* Width of Fetch receiver window. */
#define IPF_WIN_WIDTH   64

#define IPF_MAX_N           100  /* N-reordering statistics parameter */

/*
** Generic state to be maintained by client during Fetch.
*/
typedef struct fetch_state {
	FILE*        fp;               /* stream to report records           */
	IPFDataRec window[IPF_WIN_WIDTH]; /* window of read records    */
	IPFDataRec last_out; /* last processed record            */
	int          cur_win_size;     /* number of records in the window    */
	double       tmin;             /* min delay                          */
	double       tmax;             /* max delay                          */
	u_int32_t    num_received;     /* number of good received packets    */
	u_int32_t    dup_packets;      /* number of duplicate packets        */
	int          order_disrupted;  /* flag                               */
	u_int32_t    max_seqno;        /* max sequence number seen           */
	u_int32_t    *buckets;         /* array of buckets of counts         */
	char         *from;            /* Endpoints in printable format      */
	char         *to;
	u_int32_t    count_out;        /* number of printed packets          */

	/*
	 * Worst error for all packets in test.
	 */
	double		errest;
	int          sync;           /* flag set if never saw unsync packets */

	/* N-reodering state variables. */
	u_int32_t        m[IPF_MAX_N];       /* We have m[j-1] == number of
						j-reordered packets.         */
        u_int32_t        ring[IPF_MAX_N];    /* Last sequence numbers seen.  */
        u_int32_t        r;                  /* Ring pointer for next write. */
        u_int32_t        l;                  /* Number of seq numbers read.  */

} fetch_state;

#define IPF_CMP(a,b) ((a) < (b))? -1 : (((a) == (b))? 0 : 1)

/*
** The function returns -1. 0 or 1 if the first record's sequence
** number is respectively less than, equal to, or greater than that 
** of the second.
*/
int
ipf_seqno_cmp(
	IPFDataRec	*a,
	IPFDataRec	*b
	)
{
	assert(a); assert(b);
	return IPF_CMP(a->seq_no, b->seq_no);
}

/*
** Find the right spot in the window to insert the new record <rec>
** Return max {i| 0 <= i <= cur_win_size-1 and <rec> is later than the i_th
** record in the state window}, or -1 if no such index is found.
*/
int
look_for_spot(
	fetch_state	*state,
	IPFDataRec	*rec
	)
{
	int i;
	assert(state->cur_win_size);

	for (i = state->cur_win_size - 1; i >= 0; i--) {
		if (ipf_seqno_cmp(&state->window[i], rec) < 0)
			return i;
	}
	
	return -1;
}


/*
** Generic function to output timestamp record <rec> in given format
** as encoded in <state>.
*/
void
ipf_record_out(
	fetch_state	*state,
	IPFDataRec	*rec
	)
{
	double delay;

	assert(rec);
	assert(state);

	if (!ip_ctx.opt.records)
		return;

	assert(state->fp);

	if (!(state->count_out++ & 31))
	       fprintf(state->fp,"--- iperfc test session from %s to %s ---\n",
		       (state->from)? state->from : "***", 
		       (state->to)?  state->to : "***");

	delay = IPFDelay(&rec->send, &rec->recv);
	if (ip_ctx.opt.full) {
		char		sendbuf[IPF_TSTAMPCHARS+1];
		char		recvbuf[IPF_TSTAMPCHARS+1];

		snprintf(sendbuf,sizeof(sendbuf),IPF_TSTAMPFMT,
							rec->send.ipftime);
		snprintf(recvbuf,sizeof(recvbuf),IPF_TSTAMPFMT,
							rec->recv.ipftime);
		fprintf(state->fp, 
				"#%-10u send=%s %c%.5g     recv=%s %c%.5g\n",
				rec->seq_no,
				sendbuf,(rec->send.sync)? 'S' : 'U', 
				(float)IPFGetTimeStampError(&rec->send),
				recvbuf,(rec->recv.sync)? 'S' : 'U',
				(float)IPFGetTimeStampError(&rec->recv)
				);
		return;
	}

	if (!IPFIsLostRecord(rec)) {
		if (rec->send.sync && rec->recv.sync) {
			double prec = IPFGetTimeStampError(&rec->send) +
				IPFGetTimeStampError(&rec->recv);
			fprintf(state->fp, 
	       "seq_no=%-10u delay=%.3f ms       (sync, precision %.3f ms)\n", 
				rec->seq_no, delay*THOUSAND, 
				prec*THOUSAND);
		} else
			fprintf(state->fp, 
				"seq_no=%u delay=%.3f ms (unsync)\n",
				rec->seq_no, delay*THOUSAND);
		return;
	}

	fprintf(state->fp, "seq_no=%-10u *LOST*\n", rec->seq_no);

	return;
}

#define IPF_MAX_BUCKET  (IPF_NUM_LOW + IPF_NUM_MID + IPF_NUM_HIGH - 1)

#define IPF_NUM_LOW         50000
#define IPF_NUM_MID         100000
#define IPF_NUM_HIGH        49900

#define IPF_CUTOFF_A        (double)(-50.0)
#define IPF_CUTOFF_B        (double)0.0
#define IPF_CUTOFF_C        (double)0.1
#define IPF_CUTOFF_D        (double)50.0

const double mesh_low = (IPF_CUTOFF_B - IPF_CUTOFF_A)/IPF_NUM_LOW;
const double mesh_mid = (IPF_CUTOFF_C - IPF_CUTOFF_B)/IPF_NUM_MID;
const double mesh_high = (IPF_CUTOFF_D - IPF_CUTOFF_C)/IPF_NUM_HIGH;

int
ipf_bucket(double delay)
{
	if (delay < IPF_CUTOFF_A)
		return 0;

	if (delay < IPF_CUTOFF_B)
		return IPF_NUM_LOW + (int)(delay/mesh_low);

	if (delay < IPF_CUTOFF_C)
		return IPF_NUM_LOW +  (int)(delay/mesh_mid);

	if (delay < IPF_CUTOFF_D)
		return IPF_NUM_LOW + IPF_NUM_MID 
			+ (int)((delay - IPF_CUTOFF_C)/mesh_high);
	
	return IPF_MAX_BUCKET;
}

void
ipf_update_stats(
	fetch_state	*state,
	IPFDataRec	*rec
	)
{
	double delay;  
	double errest;
	int bucket;

	assert(state); assert(rec);

	if (state->num_received && !ipf_seqno_cmp(rec, &state->last_out)){
		state->dup_packets++;
		state->num_received++;
		return;
	}

	if (rec->seq_no > state->max_seqno)
		state->max_seqno = rec->seq_no;
	if (IPFIsLostRecord(rec))
		return;
	state->num_received++;

	delay =  IPFDelay(&rec->send, &rec->recv);

	errest = IPFGetTimeStampError(&rec->send);
	errest += IPFGetTimeStampError(&rec->recv);

	if(errest > state->errest){
		state->errest = errest;
	}

	if (!rec->send.sync || !rec->send.sync)
		state->sync = 0;

	bucket = ipf_bucket(delay);
	
	assert((0 <= bucket) && (bucket <= IPF_MAX_BUCKET));
	state->buckets[bucket]++;

	if (delay < state->tmin)
		state->tmin = delay;
	if (delay > state->tmax)
		state->tmax = delay;
	

	memcpy(&state->last_out, rec, sizeof(*rec));
}

/*
** Given a number <alpha> in [0, 1], compute
** min {x: F(x) >= alpha}
** where F is the empirical distribution function (in our case,
** with a fuzz factor due to use of buckets.
*/
double
ipf_get_percentile(fetch_state *state, double alpha)
{
	int i;
	double sum = 0;
	u_int32_t unique = state->num_received - state->dup_packets;

	assert((0.0 <= alpha) && (alpha <= 1.0));
	
	for (i = 0; (i <= IPF_MAX_BUCKET) && (sum < alpha*unique); i++)
		sum += state->buckets[i];

	if (i <= IPF_NUM_LOW)
		return IPF_CUTOFF_A + i*mesh_low;
	if (i <= IPF_NUM_LOW + IPF_NUM_MID)
		return IPF_CUTOFF_B + (i - IPF_NUM_LOW)*mesh_mid;
	return IPF_CUTOFF_C + (i - (IPF_NUM_LOW+IPF_NUM_MID))*mesh_high;

	return 0.0;
}

/*
** Processs a single record, updating statistics and internal state.
** Return 0 on success, or -1 on failure, 1 to stop parsing data.
*/
#define IPF_LOOP(x)         ((x) >= 0? (x): (x) + IPF_MAX_N)

static int
do_single_record(
	IPFDataRec	*rec,
	void		*calldata
	) 
{
	int i;
	fetch_state *state = (fetch_state*)calldata;
	u_int32_t j;

	assert(state);

	ipf_record_out(state, rec); /* Output is done in all cases. */

	if(IPFIsLostRecord(rec)) {
		ipf_update_stats(state, rec);
		return 0;       /* May do something better later. */
	}

	/* If ordering is important - handle it here. */
	if(state->order_disrupted)
		return 0;
	
	/* Update N-reordering state. */
	for(j = 0; j < MIN(state->l, IPF_MAX_N); j++) { 
		 if(rec->seq_no 
		       >= state->ring[IPF_LOOP((int)(state->r - j - 1))])
			 break;
		 state->m[j]++;
	}
	state->ring[state->r] = rec->seq_no;
	state->l++;
	state->r = (state->r + 1) % IPF_MAX_N;

	if(state->cur_win_size < IPF_WIN_WIDTH){/* insert - no stats updates*/
		if(state->cur_win_size) { /* Grow window. */
			int num_records_to_move;
			i = look_for_spot(state, rec);
			num_records_to_move = state->cur_win_size - i - 1;

			/* Cut and paste if needed - then insert. */
			if(num_records_to_move) 
				memmove(&state->window[i+2], 
					&state->window[i+1], 
					num_records_to_move*sizeof(*rec));
			memcpy(&state->window[i+1], rec, sizeof(*rec)); 
		}
		else{
			/* Initialize window. */
			memmove(&state->window[0], rec, sizeof(*rec));
		}
		state->cur_win_size++;
	}
	else{
		/* rotate - update state*/
		IPFDataRec	*out_rec = rec;		
		if(state->num_received &&
				(rec->seq_no < state->last_out.seq_no)) {
			state->order_disrupted = 1;
			/* terminate parsing */
			return 1; 
		}

		i = look_for_spot(state, rec);

		if (i != -1)
			out_rec = &state->window[0];
		ipf_update_stats(state, out_rec);

		/* Update the window.*/
		if (i != -1) {  /* Shift if needed - then insert.*/
			if (i) 
				memmove(&state->window[0],
					&state->window[1], i*sizeof(*rec));
			memcpy(&state->window[i], rec, sizeof(*rec));
		} 
	}
	
	return 0;
}

/*
** Print out summary results, ping-like style. sent + dup == lost +recv.
*/
int
ipf_do_summary(fetch_state *state)
{
	double min = ((double)(state->tmin)) * THOUSAND;    /* msec */
	u_int32_t sent = state->max_seqno + 1;
	u_int32_t lost = state->dup_packets + sent - state->num_received; 
	double percent_lost = (100.0*(double)lost)/(double)sent;
	int j;

	assert(state); assert(state->fp);

	fprintf(state->fp, "\n--- iperfc statistics from %s to %s ---\n",
		       (state->from)? state->from : "***", 
		       (state->to)?  state->to : "***");
	if (state->dup_packets)
		fprintf(state->fp, 
 "%u packets transmitted, %u packets lost (%.1f%% loss), %u duplicates\n",
			sent, lost, percent_lost, state->dup_packets);
	else	
		fprintf(state->fp, 
		     "%u packets transmitted, %u packets lost (%.1f%% loss)\n",
			sent ,lost, percent_lost);
	if (!state->num_received)
		goto done;

	if (state->sync)
		fprintf(state->fp, 
	     "one-way delay min/median = %.3f/%.3f ms  (precision %.5g s)\n", 
		min, ipf_get_percentile(state, 0.5)*THOUSAND,
		state->errest);
	else
		fprintf(state->fp, 
	     "one-way delay min/median = %.3f/%.3f ms  (unsync)\n", 
			min, ipf_get_percentile(state, 0.5)*THOUSAND);

	for (j = 0; j < IPF_MAX_N && state->m[j]; j++)
                fprintf(state->fp,
			"%d-reordering = %f%%\n", j+1, 
			100.0*state->m[j]/(state->l - j - 1));
        if (j == 0) 
		fprintf(state->fp, "no reordering\n");
        else 
		if (j < IPF_MAX_N) 
			fprintf(state->fp, "no %d-reordering\n", j + 1);
        else 
		fprintf(state->fp, 
			"only up to %d-reordering is handled\n", IPF_MAX_N);

	if ((ip_ctx.opt.percentile - 50.0) > 0.000001
	    || (ip_ctx.opt.percentile - 50.0) < -0.000001) {
		float x = ip_ctx.opt.percentile/100.0;
		fprintf(state->fp, 
			"%.2f percentile of one-way delays: %.3f ms\n",
			ip_ctx.opt.percentile,
			ipf_get_percentile(state, x) * THOUSAND);
	}
 done:	
	fprintf(state->fp, "\n");

	return 0;
}

/*
 * RAW ascii format is:
 * "SEQ STIME SS SERR RTIME RS RERR\n"
 * name		desc			type
 * SEQ		sequence number		unsigned long
 * STIME	sendtime		ipftimestamp (%020llu)
 * RTIME	recvtime		ipftimestamp (%020llu)
 * SS		send synchronized	boolean unsigned
 * RS		recv synchronized	boolean unsigned
 * SERR		send err estimate	float (%g)
 * RERR		recv err estimate	float (%g)
 */
#define RAWFMT "%lu %020llu %u %g %020llu %u %g\n"
static int
printraw(
	IPFDataRec	*rec,
	void		*udata
	)
{
	FILE		*out = (FILE*)udata;

	fprintf(out,RAWFMT,rec->seq_no,
			rec->send.ipftime,rec->send.sync,
				IPFGetTimeStampError(&rec->send),
			rec->recv.ipftime,rec->recv.sync,
				IPFGetTimeStampError(&rec->recv));
	return 0;
}

/*
** Master output function - reads the records from the disk
** and prints them to <out> in a style specified by <type>.
** Its value is interpreted as follows:
** 0 - print out send and recv timestamsps for each record in machine-readable
** format;
** 1 - print one-way delay in msec for each record, and final summary
**     (original ping style: max/avg/min/stdev) at the end.
*/
int
do_records_all(
		IPFContext	ctx,
		FILE		*output,
		FILE		*fp,
		char		*from,
		char		*to
		)
{
	int			i, num_buckets;
	u_int32_t		num_rec;
	IPFSessionHeaderRec	hdr;
	off_t			hdr_len;
	fetch_state		state;
	char			frombuf[NI_MAXHOST+1];
	char			tobuf[NI_MAXHOST+1];

	if(!(num_rec = IPFReadDataHeader(ctx,fp,&hdr_len,&hdr))){
		I2ErrLog(eh, "IPFReadDataHeader:Empty file?");
		return -1;
	}

	if(ip_ctx.opt.raw){
		if(IPFParseRecords(ctx,fp,num_rec,hdr.version,printraw,output)
							< IPFErrWARNING){
			I2ErrLog(eh,"IPFParseRecords(): %M");
			return -1;
		}
		return 0;
	}

	memset(&state,0,sizeof(state));
	/*
	 * Get pretty names...
	 */
	if(from){
		state.from = from;
	}
	else{
		if(!hdr.header || getnameinfo(
					(struct sockaddr*)&hdr.addr_sender,
					hdr.addr_len,
					frombuf,sizeof(frombuf),
					NULL,0,0)){
			strcpy(frombuf,"***");
		}

		state.from = frombuf;
	}

	if(to){
		state.to = to;
	}
	else{
		if(!hdr.header || getnameinfo(
					(struct sockaddr*)&hdr.addr_receiver,
					hdr.addr_len,
					tobuf,sizeof(tobuf),
					NULL,0,0)){
			strcpy(tobuf,"***");
		}

		state.to = tobuf;
	}

	/*
	 * Initialize fields of state to keep track of.
	 */
	state.fp = output;
	state.cur_win_size = 0;
	state.tmin = 9999.999;
	state.tmax = 0.0;
	state.num_received = state.dup_packets = state.max_seqno = 0;

	state.order_disrupted = 0;

	state.count_out = 0;

	state.errest = 0.0;
	state.sync = 1;

	/* N-reodering fields/ */
	state.r = state.l = 0;
	for (i = 0; i < IPF_MAX_N; i++) 
		state.m[i] = 0;

	num_buckets = IPF_NUM_LOW + IPF_NUM_MID + IPF_NUM_HIGH;

	state.buckets 
		= (u_int32_t *)malloc(num_buckets*sizeof(*(state.buckets)));
	if (!state.buckets) {
		I2ErrLog(eh, "FATAL: main: malloc(%d) failed: %M",num_buckets);
		exit(1);
	}
	for (i = 0; i <= IPF_MAX_BUCKET; i++)
		state.buckets[i] = 0;

	
	if(IPFParseRecords(ctx,fp,num_rec,hdr.version,do_single_record,&state)
							< IPFErrWARNING){
		I2ErrLog(eh,"IPFParseRecords():%M");
		return -1;
	}
	
	/* Stats are requested and failed to keep records sorted - redo */
	if (state.order_disrupted) {
		I2ErrLog(eh, "Severe out-of-order condition observed.");
		I2ErrLog(eh, 
	     "Producing statistics for this case is currently unimplemented.");
		return 0;
	}

	/* Incorporate remaining records left in the window. */
	for (i = 0; i < state.cur_win_size; i++)
		ipf_update_stats(&state, &state.window[i]);

	ipf_do_summary(&state);
	free(state.buckets);
	return 0;
}

/*
** Fetch a session with the given <sid> from the remote server.
** It is assumed that control connection has been opened already.
*/
FILE *
ipf_fetch_sid(
	char		*savefile,
	IPFControl	cntrl,
	IPFSID		sid
	      )
{
	char		*path;
	FILE		*fp;
	u_int32_t	num_rec;
	IPFErrSeverity	rc=IPFErrOK;

	/*
	 * Prepare paths for datafiles. Unlink if not keeping data.
	 */
	if(savefile){
		path = savefile;
		if( !(fp = fopen(path,"wb+"))){
			I2ErrLog(eh,"ipf_fetch_sid:fopen(%s):%M",path);
			return NULL;
		}
	}
	else{
		/*
		 * Using fd/mkstemp/fdopen to avoid race condition that
		 * would exist if we used mktemp/fopen.
		 */
		int	fd;

		path = strdup(IPF_TMPFILE);
		if(!path){
			I2ErrLog(eh,"ipf_fetch_sid:strdup(%s):%M",IPF_TMPFILE);
			exit(1);
		}
		if((fd = mkstemp(path)) < 0){
			I2ErrLog(eh,"ipf_fetch_sid:mkstemp(%s):%M",path);
			exit(1);
		}
		if(!(fp = fdopen(fd,"wb+"))){
			I2ErrLog(eh,"ipf_fetch_sid:fdopen():%M");
			exit(1);
		}
		if (unlink(path) < 0) {
			I2ErrLog(eh,"ipf_fetch_sid:unlink(%s):%M",path);
		}
		free(path);
		path = NULL;
	}

	/*
	 * Ask for complete session 
	 */
	num_rec = IPFFetchSession(cntrl,fp,0,(u_int32_t)0xFFFFFFFF,sid,&rc);
	if(!num_rec){
		if(path)
			(void)unlink(path);
		if(rc < IPFErrWARNING){
			I2ErrLog(eh,"ipf_fetch_sid:IPFFetchSession error?");
			return NULL;
		}
		/*
		 * server denied request...
		 */
		I2ErrLog(eh,
		"ipf_fetch_sid:Server denied request for to session data");
		return NULL;
	}

	return fp;
}

/*
** Initialize authentication and policy data (used by iperfc and owfetch)
*/
void
ipf_set_auth(ip_cntrl_trec *pctx, 
	     char *progname,
	     IPFContext ctx)
{
#if	NOT
	IPFErrSeverity err_ret;

	/*
	 * TODO: fix policy.
	 */
	if(pctx->opt.identity){
		/*
		 * Eventually need to modify the policy init for the
		 * client to deal with a pass-phrase instead of/ or in
		 * addition to the passwd file.
		 */
		*policy = IPFPolicyInit(ctx, NULL, NULL, pctx->opt.passwd, 
				       &err_ret);
		if (err_ret == IPFErrFATAL){
			I2ErrLog(eh, "PolicyInit failed. Exiting...");
			exit(1);
		};
	}
#endif


	/*
	 * Verify/decode auth options.
	 */
	if(pctx->opt.authmode){
		char	*s = ip_ctx.opt.authmode;
		pctx->auth_mode = 0;
		while(*s != '\0'){
			switch (toupper(*s)){
				case 'O':
				pctx->auth_mode |= IPF_MODE_OPEN;
				break;
				case 'A':
				pctx->auth_mode |= IPF_MODE_AUTHENTICATED;
				break;
				case 'E':
				pctx->auth_mode |= IPF_MODE_ENCRYPTED;
				break;
				default:
				I2ErrLogP(eh,EINVAL,"Invalid -authmode %c",*s);
				usage(progname, NULL);
				exit(1);
			}
			s++;
		}
	}else{
		/*
		 * Default to all modes.
		 * If identity not set - library will ignore A/E.
		 */
		pctx->auth_mode = IPF_MODE_OPEN|IPF_MODE_AUTHENTICATED|
							IPF_MODE_ENCRYPTED;
	}
}

/*
 * TODO: Find real max padding sizes based upon size of headers
 */
#define	MAX_PADDING_SIZE	65000

int
main(
	int	argc,
	char	**argv
) {
	char			*progname;
	IPFErrSeverity		err_ret = IPFErrOK;
	I2LogImmediateAttr	ia;
	IPFContext		ctx;
	IPFTimeStamp		start_time;
	IPFTestSpec		tspec;
	IPFSlot			slot;
	IPFNum64		rtt_bound;
	IPFSID			tosid, fromsid;
	IPFAcceptType		acceptval;
	IPFErrSeverity		err;
	FILE			*fromfp=NULL;
	char			localbuf[NI_MAXHOST+1+NI_MAXSERV+1];
	char			remotebuf[NI_MAXHOST+1+NI_MAXSERV+1];
	char                    *local, *remote;

	int			ch;
	char                    *endptr = NULL;
	char                    optstring[128];
	static char		*conn_opts = "A:S:k:u:";
	static char		*test_opts = "fF:tT:c:i:s:L:";
	static char		*out_opts = "a:vVQR";
	static char		*gen_opts = "h";
#ifndef	NDEBUG
	static char		*debug_opts = "w";
#endif

	ia.line_info = (I2NAME | I2MSG);
#ifndef	NDEBUG
	ia.line_info |= (I2LINE | I2FILE);
#endif
	ia.fp = stderr;

	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;

	/*
	* Start an error logging session for reporing errors to the
	* standard error
	*/
	eh = I2ErrOpen(progname, I2ErrLogImmediate, &ia, NULL, NULL);
	if(! eh) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(ip_ctx.lib_ctx = IPFContextCreate(eh))){
		I2ErrLog(eh, "Unable to initialize IPF library.");
		exit(1);
	}
	ctx = ip_ctx.lib_ctx;

	/* Set default options. */
	ip_ctx.opt.records = ip_ctx.opt.full = ip_ctx.opt.childwait 
            = ip_ctx.opt.from = ip_ctx.opt.to = ip_ctx.opt.quiet
	    = ip_ctx.opt.raw = False;
	ip_ctx.opt.save_from_test = ip_ctx.opt.save_to_test 
		= ip_ctx.opt.identity = ip_ctx.opt.passwd 
		= ip_ctx.opt.srcaddr = ip_ctx.opt.authmode = NULL;
	ip_ctx.opt.numPackets = 100;
	ip_ctx.opt.lossThreshold = 0.0;
	ip_ctx.opt.percentile = 50.0;
	ip_ctx.opt.mean_wait = (float)0.1;
	ip_ctx.opt.padding = 0;

	/* Create options strings for this program. */
	if (!strcmp(progname, "iperfc")) {
		strcpy(optstring, conn_opts);
		strcat(optstring, test_opts);
		strcat(optstring, out_opts);
	} else if (!strcmp(progname, "owstats")) {
		strcpy(optstring, out_opts);
	} else if (!strcmp(progname, "owfetch")) {
		strcpy(optstring, conn_opts);
		strcat(optstring, out_opts);
	}
	else{
	     usage(progname, "Invalid program name.");
	     exit(1);
	}

	strcat(optstring, gen_opts);
#ifndef	NDEBUG
	strcat(optstring,debug_opts);
#endif
		
	while ((ch = getopt(argc, argv, optstring)) != -1)
             switch (ch) {
		     /* Connection options. */
             case 'A':
		     if (!(ip_ctx.opt.authmode = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;
             case 'S':
		     if (!(ip_ctx.opt.srcaddr = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;
             case 'u':
		     if (!(ip_ctx.opt.identity = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;
	     case 'k':
		     if (!(ip_ctx.opt.passwd = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
                     break;

		     /* Test options. */
  	     case 'F':
		     if (!(ip_ctx.opt.save_from_test = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }     
		     /* fall through */
             case 'f':
		     ip_ctx.opt.from = True;
                     break;
	     case 'T':
		     if (!(ip_ctx.opt.save_to_test = strdup(optarg))) {
			     I2ErrLog(eh,"malloc:%M");
			     exit(1);
		     }
		     /* fall through */
             case 't':
		     ip_ctx.opt.to = True;
                     break;
             case 'c':
		     ip_ctx.opt.numPackets = strtoul(optarg, &endptr, 10);
		     if (*endptr != '\0') {
			     usage(progname, 
				   "Invalid value. Positive integer expected");
			     exit(1);
		     }
                     break;
             case 'i':
		     ip_ctx.opt.mean_wait = (float)strtod(optarg, &endptr);
		     if (*endptr != '\0') {
			     usage(progname, 
			   "Invalid value. Positive floating number expected");
			     exit(1);
		     }
                     break;
             case 's':
		     ip_ctx.opt.padding = strtoul(optarg, &endptr, 10);
		     if (*endptr != '\0') {
			     usage(progname, 
				   "Invalid value. Positive integer expected");
			     exit(1);
		     }
                     break;
             case 'L':
		     ip_ctx.opt.lossThreshold = strtod(optarg,&endptr);
		     if((*endptr != '\0') ||
				    	 (ip_ctx.opt.lossThreshold < 0.0)){
			     usage(progname, 
			   "Invalid \'-L\' value. Positive float expected");
			     exit(1);
		     }
                     break;


		     /* Output options */
             case 'V':
		     ip_ctx.opt.full = True;
		     /* fall-through */
             case 'v':
		     ip_ctx.opt.records = True;
                     break;
             case 'Q':
		     ip_ctx.opt.quiet = True;
                     break;

		case 'R':
		     ip_ctx.opt.raw = True;
		     break;

             case 'a':
		     ip_ctx.opt.percentile =(float)(strtod(optarg, &endptr));
		     if ((*endptr != '\0')
			 || (ip_ctx.opt.percentile < 0.0) 
			 || (ip_ctx.opt.percentile > 100.0)){
			     usage(progname, 
	     "Invalid value. Floating number between 0.0 and 100.0 expected");
			     exit(1);
		     }
		     break;
#ifndef	NDEBUG
	     case 'w':
		     ip_ctx.opt.childwait = True;
                     break;
#endif

		     /* Generic options.*/
             case 'h':
             case '?':
             default:
                     usage(progname, "");
		     exit(0);
		     /* UNREACHED */
             }
	argc -= optind;
	argv += optind;

	/*
	 * Handle 3 possible cases (iperfc, owfetch, owstats) one by one.
	 */
	if (!strcmp(progname, "iperfc")){

		if((argc < 1) || (argc > 2)){
			usage(progname, NULL);
			exit(1);
		}

		if(!ip_ctx.opt.to && !ip_ctx.opt.from)
			ip_ctx.opt.to = ip_ctx.opt.from = True;

		ip_ctx.remote_test = argv[0];
		if(argc > 1)
			ip_ctx.remote_serv = argv[1];
		else
			ip_ctx.remote_serv = ip_ctx.remote_test;

		/*
		 * This is in reality dependent upon the actual protocol used
		 * (ipv4/ipv6) - it is also dependent upon the auth mode since
		 * authentication implies 128bit block sizes.
		 */
		if(ip_ctx.opt.padding > MAX_PADDING_SIZE)
			ip_ctx.opt.padding = MAX_PADDING_SIZE;


		if ((ip_ctx.opt.percentile < 0.0) 
		    || (ip_ctx.opt.percentile > 100.0)) {
			usage(progname, "alpha must be between 0.0 and 100.0");
			exit(0);
		}

		/*
		 * TODO: fix policy
		 */
		ipf_set_auth(&ip_ctx, progname, ctx); 


		/*
		 * Setup debugging of child processes.
		 */
		if(ip_ctx.opt.childwait &&
				!IPFContextConfigSet(ctx,
					IPFChildWait,
					(void*)ip_ctx.opt.childwait)){
			     I2ErrLog(eh,
			"IPFContextConfigSet(): Unable to set IPFChildWait?!");
		}
		
		/*
		 * Open connection to iperfcd.
		 */
		
		ip_ctx.cntrl = IPFControlOpen(ctx, 
			IPFAddrByNode(ctx, ip_ctx.opt.srcaddr),
			IPFAddrByNode(ctx, ip_ctx.remote_serv),
			ip_ctx.auth_mode,ip_ctx.opt.identity,
			NULL,&err_ret);
		if (!ip_ctx.cntrl){
			I2ErrLog(eh, "Unable to open control connection.");
			exit(1);
		}

		rtt_bound = IPFGetRTTBound(ip_ctx.cntrl);
		/*
		 * Set the loss threshold to 2 seconds longer then the
		 * rtt delay estimate. 2 is just a guess for a good number
		 * based upon how impatient this command-line user gets for
		 * results. Caveat: For the results to have any statistical
		 * relevance the lossThreshold should be specified on the
		 * command line. (You have to wait until this long after
		 * the end of a test to declare the test over in order to
		 * be confident that you have accepted all "duplicates"
		 * that could come in during the test.)
		 */
		if(ip_ctx.opt.lossThreshold <= 0.0){
			ip_ctx.opt.lossThreshold =
					IPFNum64ToDouble(rtt_bound) + 2.0;
		}

		/*
		 * TODO: create a "start" option?
		 *
		 * For now estimate a start time that allows both sides to
		 * setup the session before that time:
		 * 	~3 rtt + 1sec from now
		 * 		2 session requests, 1 startsessions command,
		 *		then one second extra to allow for setup
		 *		delay.
		 */
		if(!IPFGetTimeOfDay(&start_time)){
			I2ErrLogP(eh,errno,"Unable to get current time:%M");
			exit(1);
		}
		tspec.start_time = IPFNum64Add(start_time.ipftime,
					IPFNum64Add(
						IPFNum64Mult(rtt_bound,
							IPFULongToNum64(3)),
						IPFULongToNum64(1)));

		tspec.loss_timeout =
				IPFDoubleToNum64(ip_ctx.opt.lossThreshold);

		tspec.typeP = 0;
		tspec.packet_size_padding = ip_ctx.opt.padding;
		tspec.npackets = ip_ctx.opt.numPackets;
		
		/*
		 * TODO: Generalize commandline to allow multiple
		 * slots. For now, use one rand exp slot.
		 */
		tspec.nslots = 1;
		slot.slot_type = IPFSlotRandExpType;
		slot.rand_exp.mean = IPFDoubleToNum64(ip_ctx.opt.mean_wait);
		tspec.slots = &slot;

		/*
		 * Prepare paths for datafiles. Unlink if not keeping data.
		 */
		if(ip_ctx.opt.to) {
			if (!IPFSessionRequest(ip_ctx.cntrl, NULL, False,
				       IPFAddrByNode(ctx,ip_ctx.remote_test),
				       True,(IPFTestSpec*)&tspec,
				       NULL,tosid,&err_ret))
			FailSession(ip_ctx.cntrl);
		}

		if(ip_ctx.opt.from) {

			if (ip_ctx.opt.save_from_test) {
				fromfp = fopen(ip_ctx.opt.save_from_test,
									"wb+");
				if(!fromfp){
					I2ErrLog(eh,"fopen(%s):%M", 
						ip_ctx.opt.save_from_test);
					exit(1);
				}
			} else {
				int	fd;
				char *path = strdup(IPF_TMPFILE);
				if(!path){
					I2ErrLog(eh,"strdup():%M");
					exit(1);
				}
				if((fd = mkstemp(path)) < 0){
					I2ErrLog(eh,"mkstemp(%s):%M",path);
					exit(1);
				}
				if(!(fromfp = fdopen(fd,"wb+"))){
					I2ErrLog(eh,"fdopen():%M");
					exit(1);
				}
				if(unlink(path) < 0){
					I2ErrLog(eh,"unlink(%s):%M",path);
				}
				free(path);
			}

			if (!IPFSessionRequest(ip_ctx.cntrl,
				       IPFAddrByNode(ctx,ip_ctx.remote_test),
				       True, NULL, False,(IPFTestSpec*)&tspec,
				       fromfp,fromsid,&err_ret))
				FailSession(ip_ctx.cntrl);
		}
		

		if(IPFStartSessions(ip_ctx.cntrl) < IPFErrINFO)
			FailSession(ip_ctx.cntrl);

		/*
		 * TODO install sig handler for keyboard interupt - to send 
		 * stop sessions. (Currently SIGINT causes everything to be 
		 * killed and lost - might be reasonable to keep it that
		 * way...)
		 */
		if(IPFStopSessionsWait(ip_ctx.cntrl,NULL,NULL,&acceptval,
									&err)){
			exit(1);
		}

		if (acceptval != 0) {
			I2ErrLog(eh, "Test session(s) Questionable...");
		}

		/*
		 * Get "local" and "remote" names for pretty printing
		 * if we need them.
		 */
		local = remote = NULL;
		if(!ip_ctx.opt.quiet && !ip_ctx.opt.raw){
			IPFAddr	laddr;
			size_t	lsize;

			/*
			 * First determine local address.
			 */
			if(ip_ctx.opt.srcaddr){
				laddr = IPFAddrByNode(ctx,
						ip_ctx.opt.srcaddr);
			}
			else{
				laddr = IPFAddrByLocalControl(
							ip_ctx.cntrl);
			}
			lsize = sizeof(localbuf);
			IPFAddrNodeName(laddr,localbuf,&lsize);
			if(lsize > 0){
				local = localbuf;
			}
			IPFAddrFree(laddr);

			/*
			 * Now determine remote address.
			 */
			laddr = IPFAddrByNode(ctx,ip_ctx.remote_test);
			lsize = sizeof(remotebuf);
			IPFAddrNodeName(laddr,remotebuf,&lsize);
			if(lsize > 0){
				remote = remotebuf;
			}
			IPFAddrFree(laddr);
		}
		
		if(ip_ctx.opt.to && (ip_ctx.opt.save_to_test ||
							 !ip_ctx.opt.quiet)){
			FILE	*tofp;

			tofp = ipf_fetch_sid(ip_ctx.opt.save_to_test,
					ip_ctx.cntrl,tosid);
			if(tofp && !ip_ctx.opt.quiet &&
					(do_records_all(ctx,stdout,tofp,
							local,remote) < 0)){
				I2ErrLog(eh,
					"do_records_all(\"to\" session): %M");
			}
			if(tofp && fclose(tofp)){
				I2ErrLog(eh,"close(): %M");
			}
		}

		if(fromfp && !ip_ctx.opt.quiet){
			if(do_records_all(ctx,stdout,fromfp,remote,local)
									< 0){
				I2ErrLog(eh,
					"do_records_all(\"from\" session): %M");
			}
		}

		if(fromfp && fclose(fromfp)){
			I2ErrLog(eh,"close(): %M");
		}
		
		exit(0);

	}

	if (!strcmp(progname, "owstats")) {
		FILE		*fp;

		if(!(fp = fopen(argv[0],"rb"))){
			I2ErrLog(eh,"fopen(%s):%M",argv[0]);
			exit(1);
		}

		if (do_records_all(ctx,stdout,fp,NULL,NULL) < 0){
			I2ErrLog(eh,"do_records_all() failed.");
			exit(1);
		}

		fclose(fp);

		exit(0);
	}
	
	if (!strcmp(progname, "owfetch")) {
		int i;
		if((argc%2 == 0) || (argc < 3)){
			usage(progname, NULL);
			exit(1);
		}

		ip_ctx.remote_serv = argv[0];
		argv++;
		argc--;

		/*
		 * TODO: fix policy
		 */
		ipf_set_auth(&ip_ctx, progname, ctx); 
#if	NOT
		conndata.policy = policy;
#endif

		/*
		 * Open connection to iperfcd.
		 */
		ip_ctx.cntrl = IPFControlOpen(ctx, 
			IPFAddrByNode(ctx, ip_ctx.opt.srcaddr),
			IPFAddrByNode(ctx, ip_ctx.remote_serv),
			ip_ctx.auth_mode,ip_ctx.opt.identity,
			NULL,&err_ret);
		if (!ip_ctx.cntrl){
			I2ErrLog(eh, "Unable to open control connection.");
			exit(1);
		}

		for (i = 0; i < argc/2; i++) {
			IPFSID	sid;
			FILE	*fp;
			char	*sname;
			char	*fname;

			sname = *argv++;
			fname = *argv++;
			IPFHexDecode(sname, sid, 16);
			if(!(fp = ipf_fetch_sid(fname,ip_ctx.cntrl,sid))){
				I2ErrLog(eh,"Unable to fetch sid(%s)",sname);
			}
			else if(!ip_ctx.opt.quiet &&
					do_records_all(ctx,stdout,fp,NULL,NULL)
									< 0){
				I2ErrLog(eh,"do_records_all() failed.");
			}
			else if(fclose(fp)){
				I2ErrLog(eh,"fclose(): %M");
			}
		}

		exit(0);
	}

	exit(0);
}
