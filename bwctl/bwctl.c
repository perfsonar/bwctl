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
 *	Date:		Mon Sep 15 10:54:30 MDT 2003
 *
 *	Description:	
 *
 *	Initial implementation of iperfc commandline application. This
 *	application will measure active one-way udp latencies. And it will
 *	set up perpetual tests and keep them going until this application
 *	is killed.
 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <assert.h>
#include <syslog.h>
#include <math.h>

#include <ipcntrl/ipcntrl.h>


#if defined HAVE_DECL_OPTRESET && !HAVE_DECL_OPTRESET
int optreset;
#endif

#include "./iperfcP.h"

/*
 * The iperfc context
 */
static	ipapp_trec		app;
static	I2ErrHandle		eh;
static	u_int32_t		file_offset,ext_offset;
static	int			ip_intr = 0;
static	int			ip_reset = 0;
static	int			ip_exit = 0;
static	int			ip_error = SIGCONT;
static	IPFContext		ctx;
static	ipsess_trec		local;
static	ipsess_trec		remote;
static	IPFNum64		zero64;
static	IPFNum64		fuzz64;
static	IPFSID			sid;
static	u_int16_t		recv_port;
static	ipsess_t		s[2];	/* receiver == 0, sender == 1 */

static void
print_conn_args()
{
	fprintf(stderr,"              [Connection Args]\n\n"
"   -A authmode    requested modes: [A]uthenticated, [E]ncrypted, [O]pen\n"
"   -k keyfile     AES keyfile to use with Authenticated/Encrypted modes\n"
"   -U username    username to use with Authenticated/Encrypted modes\n"
"   -B srcaddr     use this as a local address for control connection and tests\n"
	);
}

static void
print_test_args()
{
	fprintf(stderr,
"              [Test Args]\n\n"
"   -i interval    report interval (seconds)\n"
"   -l len         length of read/write buffers (bytes)\n"
"   -u             UDP test\n"
"   -w window      TCP window size (bytes)\n"
"   -P nThreads    number of concurrent connections (ENOTSUPPORTED)\n"
"   -S TOS         type-of-service for outgoing packets (ENOTSUPPORTED)\n"
"   -b bandwidth   bandwidth to use for UDP test (bits/sec KM) (Default: 1Mb)\n"
"   -t time        duration of test (seconds) (Default: 10)\n"
"   -c             local sender \"client in iperf speak\" (TAKES NO ARG)\n"
"   -s             local receiver \"server in iperf speak\" (TAKES NO ARG)\n"
"              [MUST SPECIFY EXACTLY ONE OF -c/-s]"
	);
}

static void
print_output_args()
{
	fprintf(stderr,
"              [Output Args]\n\n"
"   -d dir         directory to save session file in (only if -p)\n"
"   -I Interval    time between IPF test sessions(seconds)\n"
"   -n nIntervals  number of tests to perform (default: continuous)\n"
"   -L LatestDelay latest time into an interval to run test(seconds)\n"
"   -p             print completed filenames to stdout - not session data\n"
"   -h             print this message and exit\n"
"   -e             syslog facility to log to\n"
"   -r             send syslog to stderr\n"
		);
}

static void
usage(const char *progname, const char *msg)
{
	if(msg) fprintf(stderr, "%s: %s\n", progname, msg);
	fprintf(stderr,"usage: %s %s\n", 
			progname,
			 "[arguments] remotehost"
			);
	fprintf(stderr, "\n");
	print_conn_args();
		
	fprintf(stderr, "\n");
	print_test_args();
		
	fprintf(stderr, "\n");
	print_output_args();

	return;
}

/*
** Initialize authentication and policy data (used by owping and owfetch)
*/
void
ip_set_auth(
	ipapp_trec	*pctx, 
	char		*progname,
	IPFContext	ctx __attribute__((unused))
	)
{
#if	NOT
#ifndef	NDEBUG
	somestate.childwait = app.opt.childwait;
#endif
#endif
#if	NOT
	IPFErrSeverity err_ret;

	if(pctx->opt.identity){
		/*
		 * Eventually need to modify the policy init for the
		 * client to deal with a pass-phrase instead of/ or in
		 * addition to the keyfile file.
		 */
		*policy = IPFPolicyInit(ctx, NULL, NULL, pctx->opt.keyfile, 
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
		char	*s = app.opt.authmode;
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

static void
CloseSessions()
{
	/* TODO: Handle clearing other state. Canceling tests nicely? */

	if(remote.cntrl){
		IPFControlClose(remote.cntrl);
		remote.cntrl = NULL;
		remote.sockfd = 0;
		remote.tspec.req_time.ipftime = zero64;
	}
	if(local.cntrl){
		IPFControlClose(local.cntrl);
		local.cntrl = NULL;
		local.sockfd = 0;
		local.tspec.req_time.ipftime = zero64;
	}

	return;
}

static void
sig_catch(
		int	signo
		)
{
	switch(signo){
		case SIGINT:
		case SIGTERM:
			ip_exit++;
			break;
		case SIGHUP:
			ip_reset++;
			break;
		default:
			ip_error = signo;
			break;
	}

	ip_intr++;

	return;
}

static int
sig_check()
{
	if(ip_error != SIGCONT){
		I2ErrLog(eh,"sig_catch(%d):UNEXPECTED SIGNAL NUMBER",ip_error);
		exit(1);
	}

	if(ip_exit || ip_reset){
		CloseSessions();
	}

	if(ip_exit){
		I2ErrLog(eh,"SIGTERM/SIGINT: Exiting.");
		exit(0);
	}

	ip_intr = 0;

	if(ip_reset){
		ip_reset = 0;
		return 1;
	}

	return 0;
}

static int
str2num(
		u_int32_t	*num_ret,
		char		*str
		)
{
	size_t		silen = 0;
	size_t		len;
	char		*endptr;
	u_int32_t	npart, mult=1;

	while(isdigit(str[silen])){
		silen++;
	}

	len = strlen(str);

	if(len != silen){
		/*
		 * Only one non-digit is allowed and it must be the last char
		 */
		if((len - silen) > 0){
			return -1;
		}

		switch(tolower(str[silen])){
#if	NOT
			/*
			 * Don't need these until we use something larger
			 * than u_int32_t to hold the value!
			 */
			case 'z':
				mult *= 1000;
			case 'e':
				mult *= 1000;
			case 'p':
				mult *= 1000;
			case 't':
				mult *= 1000;
#endif
			case 'g':
				mult *= 1000;
			case 'm':
				mult *= 1000;
			case 'k':
				mult *= 1000;
				break;
			default:
				return -1;
		}
		str[silen] = '\0';
	}

	npart = strtoul(str,&endptr,10);
	if(endptr != &str[silen]){
		return -1;
	}

	if(npart == 0){
		*num_ret = 0;
		return 0;
	}

	/*
	 * check for overflow
	 */
	*num_ret = npart * mult;
	return ((*num_ret < npart) || (*num_ret < mult))? (-1): 0;
}

static int
str2bytenum(
		u_int32_t	*num_ret,
		char		*str
		)
{
	size_t		silen = 0;
	size_t		len;
	char		*endptr;
	u_int32_t	npart, mult=1;

	while(isdigit(str[silen])){
		silen++;
	}

	len = strlen(str);

	if(len != silen){
		/*
		 * Only one non-digit is allowed and it must be the last char
		 */
		if((len - silen) > 0){
			return -1;
		}

		switch(tolower(str[silen])){
#if	NOT
			/*
			 * Don't need these until we use something larger
			 * than u_int32_t to hold the value!
			 */
			case 'z':
				mult <<= 10;
			case 'e':
				mult <<= 10;
			case 'p':
				mult <<= 10;
			case 't':
				mult <<= 10;
#endif
			case 'g':
				mult <<= 10;
			case 'm':
				mult <<= 10;
			case 'k':
				mult <<= 10;
				break;
			default:
				return -1;
		}
		str[silen] = '\0';
	}

	npart = strtoul(str,&endptr,10);
	if(endptr != &str[silen]){
		return -1;
	}

	if(npart == 0){
		*num_ret = 0;
		return 0;
	}

	/*
	 * check for overflow
	 */
	*num_ret = npart * mult;
	return ((*num_ret < npart) || (*num_ret < mult))? (-1): 0;
}

int
main(
	int	argc,
	char	**argv
)
{
	char			*progname;
	int			lockfd;
	char			lockpath[PATH_MAX];
	int			rc;
	IPFErrSeverity		err_ret = IPFErrOK;
	I2ErrLogSyslogAttr	syslogattr;

	int			fname_len;
	int			ch;
	char                    *endptr = NULL;
	char                    optstring[128];
	static char		*conn_opts = "A:B:k:U:";
	static char		*out_opts = "d:I:n:L:pe:rv";
	static char		*test_opts = "i:l:uw:P:S:b:t:cs";
	static char		*gen_opts = "hWY";

	char			dirpath[PATH_MAX];
	struct flock		flk;
	struct sigaction	act;
	IPFNum64		latest64;
	u_int32_t		p,q;
	I2RandomSource		rsrc;
	IPFScheduleContext	sctx;
	IPFTimeStamp		wake;

	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;

	/* Create options strings for this program. */
	strcpy(optstring, conn_opts);
	strcat(optstring, test_opts);
	strcat(optstring, out_opts);
	strcat(optstring, gen_opts);
		

	syslogattr.ident = progname;
	syslogattr.logopt = LOG_PID;
	syslogattr.facility = LOG_USER;
	syslogattr.priority = LOG_ERR;
	syslogattr.line_info = I2MSG;
#ifndef	NDEBUG
	syslogattr.line_info |= I2FILE | I2LINE;
#endif

	opterr = 0;
	while((ch = getopt(argc, argv, optstring)) != -1){
		if(ch == 'e'){
			int fac;
			if((fac = I2ErrLogSyslogFacility(optarg)) == -1){
				fprintf(stderr,
				"Invalid -e: Syslog facility \"%s\" unknown\n",
				optarg);
				exit(1);
			}
			syslogattr.facility = fac;
		}
		else if(ch == 'r'){
			syslogattr.logopt |= LOG_PERROR;
		}
	}
	opterr = optreset = optind = 1;

	/*
	* Start an error logging session for reporing errors to the
	* standard error
	*/
	eh = I2ErrOpen(progname, I2ErrLogSyslog, &syslogattr, NULL, NULL);
	if(! eh) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}

	/* Set default options. */
	memset(&app,0,sizeof(app));
	app.opt.timeDuration = 10;

	while ((ch = getopt(argc, argv, optstring)) != -1)
		switch (ch) {
		/* Connection options. */
		case 'A':
			if (!(app.opt.authmode = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;
		case 'B':
			if (!(app.opt.srcaddr = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;
		case 'U':
			if (!(app.opt.identity = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;
		case 'k':
			if (!(app.opt.keyfile = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;

		/* OUTPUT OPTIONS */
		case 'd':
			if (!(app.opt.savedir = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;
		case 'I':
			app.opt.seriesInterval =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'n':
			app.opt.nIntervals =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'L':
			app.opt.seriesWindow = strtoul(optarg,&endptr,10);
			if(*endptr != '\0'){
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'p':
			app.opt.printfiles = True;
			break;
		case 'e':
		case 'r':
			/* handled in prior getopt call... */
			break;
		case 'v':
			app.opt.version = True;
			I2ErrLog(eh,"Version: $Revision$");
			exit(0);

		/* TEST OPTIONS */
		case 'c':
			app.opt.send = True;
			break;
		case 's':
			app.opt.recv = True;
			break;
		case 'i':
			app.opt.reportInterval =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'l':
			if(str2bytenum(&app.opt.lenBuffer,optarg) != 0){
				usage(progname, 
			"Invalid value. (-l) positive integer expected");
				exit(1);
			}
			break;
		case 'u':
			app.opt.udpTest = True;
			break;
		case 'w':
			if(str2bytenum(&app.opt.windowSize,optarg) != 0){
				usage(progname, 
			"Invalid value. (-w) positive integer expected");
				exit(1);
			}
			break;
		case 'P':
			app.opt.parallel =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			I2ErrLog(eh,"-P option not currently supported");
			exit(1);
			break;
		case 'S':
			app.opt.tos =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			I2ErrLog(eh,"-S option not currently supported");
			exit(1);
			break;
		case 'b':
			if(str2num(&app.opt.bandWidth,optarg) != 0){
				usage(progname, 
			"Invalid value. (-b) Positive integer expected");
				exit(1);
			}
			break;
		case 't':
			app.opt.timeDuration = strtoul(optarg, &endptr, 10);
			if((*endptr != '\0') || (app.opt.timeDuration == 0)){
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'Y':
			app.opt.allowunsync = True;
			break;
#ifndef	NDEBUG
		case 'W':
			app.opt.childwait = True;
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

	if(argc != 1){
		usage(progname, NULL);
		exit(1);
	}
	app.remote_test = argv[0];

	if(app.opt.recv == app.opt.send){
		usage(progname,"Exactly one of -s or -c must be specified.");
		exit(1);
	}

	/*
	 * Useful constant
	 */
	zero64 = IPFULongToNum64(0);

	/*
	 * Check savedir option. Make sure it will not make fnames
	 * exceed PATH_MAX even with the nul byte.
	 * Also set file_offset and ext_offset to the lengths needed.
	 */
	fname_len = TSTAMPCHARS + strlen(IPF_FILE_EXT) + strlen(SUMMARY_EXT);
	assert((fname_len+1)<PATH_MAX);
	if(app.opt.savedir){
		if((strlen(app.opt.savedir) + strlen(IPF_PATH_SEPARATOR)+
						fname_len + 1) > PATH_MAX){
			usage(progname,"-d: pathname too long.");
			exit(1);
		}
		strcpy(dirpath,app.opt.savedir);
		strcat(dirpath,IPF_PATH_SEPARATOR);
	}else
		dirpath[0] = '\0';

	if(!app.opt.timeDuration){
		app.opt.timeDuration = 10; /* 10 second default */
	}

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(ctx = IPFContextCreate(eh,app.opt.allowunsync))){
		I2ErrLog(eh, "Unable to initialize IPF library.");
		exit(1);
	}

	/*
	 * If seriesInterval is in use, verify the args and pick a
	 * resonable default for seriesWindow if needed.
	 */
	if(app.opt.seriesInterval){
		u_int8_t	seed[16];

		if(app.opt.seriesInterval <
				(app.opt.timeDuration + SETUP_ESTIMATE)){
			usage(progname,"-I: interval too small relative to -t");
			exit(1);
		}

		if( !(rsrc = I2RandomSourceInit(eh,I2RAND_DEV,NULL))){
			I2ErrLog(eh,"Failed to initialize Random Numbers");
			exit(1);
		}
		if(I2RandomBytes(rsrc,seed,16) != 0){
			exit(1);
		}

		/*
		 * Setup the pseudoPoisson generator...
		 */
		if( !(sctx = IPFScheduleContextCreate(ctx,seed,
				(double)app.opt.seriesInterval))){
			exit(1);
		}

		/*
		 * If nIntervals not set, continuous tests are requested.
		 */
		if(!app.opt.nIntervals){
			app.opt.continuous = True;
		}
		/*
		 * Make sure tests start before 50% of the 'interval' is
		 * gone.
		 */
		if(!app.opt.seriesWindow){
			app.opt.seriesWindow = MIN(
			app.opt.seriesInterval-app.opt.timeDuration,
			app.opt.seriesInterval * 0.5);
		}
	}
	else{
		/*
		 * Make sure tests start within 2 test durations.
		 */
		if(!app.opt.seriesWindow){
			app.opt.seriesWindow = app.opt.timeDuration * 2;
		}
		/*
		 * If nIntervals not set, and seriesInterval not set
		 * a single test is requested.
		 */
		if(!app.opt.nIntervals){
			app.opt.nIntervals = 1;
		}
	}
	latest64 = IPFULongToNum64(app.opt.seriesWindow);

	if(app.opt.udpTest && !app.opt.bandWidth){
		app.opt.bandWidth = DEF_UDP_RATE;
	}

	if(app.opt.bandWidth && !app.opt.udpTest){
		usage(progname,"-b: only valid with -u");
		exit(1);
	}

	/*
	 * Lock the directory for iperfc if it is in printfiles mode.
	 */
	if(app.opt.printfiles){
		strcpy(lockpath,dirpath);
		strcat(lockpath,IPLOCK);
		lockfd = open(lockpath,O_RDWR|O_CREAT,
					S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		if(lockfd < 0){
		     I2ErrLog(eh,"open(%s):%M",lockpath);
		     exit(1);
		}

		flk.l_start = 0;
		flk.l_len = 0;
		flk.l_type = F_WRLCK;
		flk.l_whence = SEEK_SET;
		while((rc = fcntl(lockfd,F_SETLK,&flk)) < 0 && errno == EINTR);
		if(rc < 0){
			I2ErrLog(eh,"Unable to lock file %s:%M",lockpath);
			if(I2Readn(lockfd,&ch,sizeof(ch)) == sizeof(ch)){
				I2ErrLog(eh,"Possibly locked by pid(%d)",ch);
			}
			exit(1);
		}

		ch = getpid();
		if(I2Writen(lockfd,&ch,sizeof(ch)) != sizeof(ch)){
			I2ErrLog(eh,"Unable to write to lockfile:%M");
			exit(1);
		}
	}
	file_offset = strlen(dirpath);
	ext_offset = file_offset + TSTAMPCHARS;

	/*
	 * Initialize session records
	 */
	memset(&local,0,sizeof(local));
	/* skip req_time/latest_time - set per/test */
	local.tspec.duration = app.opt.timeDuration;
	local.tspec.udp = app.opt.udpTest;
	if(local.tspec.udp){
		local.tspec.bandwidth = app.opt.bandWidth;
	}
	local.tspec.window_size = app.opt.windowSize;
	local.tspec.len_buffer = app.opt.lenBuffer;
	local.tspec.report_interval = app.opt.reportInterval;

	/*
	 * copy local tspec to remote record.
	 */
	memcpy(&remote,&local,sizeof(local));


	/* s[0] == reciever, s[1] == sender */
	s[0] = (app.opt.send)? &remote: &local;
	s[1] = (!app.opt.send)? &remote: &local;
	s[1]->send = True;

	/*
	 * TODO: Fix this.
	 * Setup policy stuff - this currently sucks.
	 */
	ip_set_auth(&app,progname,ctx); 

	/*
	 * setup sighandlers
	 */
	ip_reset = ip_exit = 0;
	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if(		(sigaction(SIGTERM,&act,NULL) != 0) ||
			(sigaction(SIGINT,&act,NULL) != 0) ||
			(sigaction(SIGHUP,&act,NULL) != 0)){
		I2ErrLog(eh,"sigaction(): %M");
		exit(1);
	}

	/*
	 * Initialize wake time to current time. If this is a single test,
	 * this will indicate an immediate test. If seriesInterval is set,
	 * this time will be adjusted to spread start times out.
	 */
	if(!IPFGetTimeStamp(ctx,&wake)){
		I2ErrLogP(eh,errno,"IPFGetTimeOfDay: %M");
		exit(1);
	}

	if(app.opt.seriesInterval){
		/*
		 * sleep for rand([0,1])*sessionInterval
		 * (spread out start time)
		 * Use a random 32 bit integer and normalize.
		 */
		u_int32_t	r;

		if(I2RandomBytes(rsrc,(u_int8_t*)&r,4) != 0){
			exit(1);
		}

		wake.ipftime = IPFNum64Add(wake.ipftime,
			IPFDoubleToNum64((double)app.opt.seriesInterval*
				r/0xffffffff));
	}

	do{
		IPFTimeStamp	req_time;
		IPFTimeStamp	currtime;
		IPFNum64	endtime;
		u_int16_t	dataport;
		IPFBoolean	stop;

AGAIN:
		if(sig_check()) exit(1);

		/* Open remote connection */
		if(!remote.cntrl){
			remote.cntrl = IPFControlOpen(ctx,
				IPFAddrByNode(ctx,app.opt.srcaddr),
				IPFAddrByNode(ctx,app.remote_test),
				app.auth_mode,app.opt.identity,
				NULL,&err_ret);
			/* TODO: deal with temporary failures */
			if(sig_check()) exit(1);
			if(!remote.cntrl){
				I2ErrLog(eh,"Unable to connect to remote server, will try again next period: %M");
				goto next_test;
			}
			remote.sockfd = IPFControlFD(remote.cntrl);

			/*
			 * Setup addresses of test endpoints.
			 * (Must have initialized remote communication first.)
			 */
			if(!local.tspec.sender){
				local.tspec.sender = (app.opt.send)?
					IPFAddrByLocalControl(remote.cntrl):
						IPFAddrByControl(remote.cntrl);
				if(!local.tspec.sender){
					I2ErrLog(eh,
					"Unable to determine send address: %M");
					exit(1);
				}
				remote.tspec.sender = local.tspec.sender;
			}

			if(!local.tspec.receiver){
				local.tspec.receiver = (!app.opt.send)?
					IPFAddrByLocalControl(remote.cntrl):
						IPFAddrByControl(remote.cntrl);
				if(!local.tspec.receiver){
					I2ErrLog(eh,
					"Unable to determine recv address: %M");
					exit(1);
				}
				remote.tspec.receiver = local.tspec.receiver;
			}
		}
		/* Open local connection */
		if(!local.cntrl){
			local.cntrl = IPFControlOpen(ctx,
				NULL,
				IPFAddrByLocalControl(remote.cntrl),
				app.auth_mode,app.opt.identity,
				NULL,&err_ret);
			/* TODO: deal with temporary failures */
			if(sig_check()) exit(1);
			if(!local.cntrl){
				I2ErrLog(eh,"Unable to connect to remote server, will try again next period: %M");
				goto next_test;
			}
			local.sockfd = IPFControlFD(remote.cntrl);
		}

		/*
		 * Now caluculate how far into the future the test
		 * request should be made for.
		 */
		/* initialize */
		req_time.ipftime = zero64;

		/*
		 * Query remote time error and update round-trip bound.
		 * (The time will be over-written later, we really only
		 * care about the errest portion of the timestamp.)
		 */
		if(IPFControlTimeCheck(remote.cntrl,&local.tspec.req_time) !=
								IPFErrOK){
			I2ErrLogP(eh,errno,"IPFControlTimeCheck: %M");
			exit(1);
		}
		if(sig_check()) exit(1);
		/*
		 * req_time.ipftime += (3*round-trip-bound)
		 * (3) -- 1 test_req, 1 start session, 1 for server-2-server
		 * connection.
		 */
		remote.rttbound = IPFGetRTTBound(remote.cntrl);
		req_time.ipftime = IPFNum64Add(req_time.ipftime,
			IPFNum64Mult(remote.rttbound,IPFULongToNum64(2)));

		/*
		 * Query local time error and update round-trip bound.
		 * (The time will be over-written later, we really only
		 * care about the errest portion of the timestamp.)
		 */
		if(IPFControlTimeCheck(local.cntrl,&remote.tspec.req_time) !=
								IPFErrOK){
			I2ErrLogP(eh,errno,"IPFControlTimeCheck: %M");
			goto next_test;
		}
		if(sig_check()) exit(1);

		/*
		 * Get current time.
		 */
		if(!IPFGetTimeStamp(ctx,&currtime)){
			I2ErrLogP(eh,errno,"IPFGetTimeOfDay: %M");
			exit(1);
		}

		/*
		 * Check if the test should run yet...
		 */
		if(IPFNum64Cmp(wake.ipftime,currtime.ipftime) > 0){
			struct timespec	tspec;
			IPFNum64	rel;

			rel = IPFNum64Sub(currtime.ipftime,wake.ipftime);
			IPFNum64ToTimespec(&tspec,rel);
			if((nanosleep(&tspec,NULL) == 0) ||
					(errno == EINTR)){
				goto AGAIN;
			}

			IPFError(ctx,IPFErrFATAL,IPFErrUNKNOWN,
					"nanosleep(): %M");
			exit(1);
		}

		/*
		 * req_time.ipftime += (3*round-trip-bound)
		 * (3) -- 1 test_req, 1 start session, 1 for server-2-server
		 * connection.
		 */
		local.rttbound = IPFGetRTTBound(local.cntrl);
		req_time.ipftime = IPFNum64Add(req_time.ipftime,
			IPFNum64Mult(local.rttbound,IPFULongToNum64(3)));

		/*
		 * Add a small constant value to this... Will need to experiment
		 * to find the right number. All the previous values were
		 * basically estimates for how long it would take to make
		 * the request. This is roughly the time into the future we
		 * want to make the request for above and beyond the amount
		 * of time it takes to actually make the request. It should
		 * be short enough to not be annoying for interactive use, but
		 * long enough to account for most random delays.
		 * (The larger this value is, the more likely the two servers
		 * will be able to accomidate the request initially - the
		 * smaller, the more TestRequests will probably need to be made.
		 * )
		 */
		req_time.ipftime = IPFNum64Add(req_time.ipftime,
						IPFULongToNum64(1));

		/*
		 * Wait this long after a test should be complete before
		 * poking the servers. It should be long enough to allow
		 * the servers to declare the session complete before the
		 * client does.
		 * (Again 2 seconds is just a guess - I'm making a lot of
		 * guesses due to time constrants. If these values cause
		 * problems they can be revisited.)
		 */
		fuzz64 = IPFNum64Add(IPFULongToNum64(2),
				IPFNum64Max(local.rttbound,remote.rttbound));

		/*
		 * req_time currently holds a reasonable relative amount of
		 * time from 'now' that a test could be held. Get the current
		 * time and add to make that an 'absolute' value.
		 */
		req_time.ipftime = IPFNum64Add(req_time.ipftime,
							currtime.ipftime);
		/*
		 * Get a reservation:
		 * 	s[0] == receiver
		 * 	s[1] == sender
		 * 	initialize req_time/latest_time
		 * 	keep querying each server in turn until satisfied,
		 * 	or denied.
		 */
		s[0]->tspec.latest_time = s[1]->tspec.latest_time =
					IPFNum64Add(req_time.ipftime, latest64);
		s[1]->tspec.req_time.ipftime = zero64;
		memset(sid,0,sizeof(sid));
		recv_port = 0;

		p=0;q=0;
		while(1){

			/*
			 * p is the current connection we are talking to,
			 * q is the "other" one.
			 * (Logic is started so the first time through this loop
			 * we are talking to the "receiver". That is required
			 * to initialize the sid and recv_port.)
			 */
			p = q++;
			q %= 2;

			s[p]->tspec.req_time.ipftime = req_time.ipftime;

			/* TODO: do something with return values.
			 */
			if(!IPFSessionRequest(s[p]->cntrl,s[p]->send,
					&s[p]->tspec,&req_time,&recv_port,
					sid,&err_ret)){
				if((err_ret == IPFErrOK) &&
						(IPFNum64Cmp(req_time.ipftime,
							     zero64) != 0)){
					/*
					 * Request is ok, but server is too
					 * busy. Skip this test and proceed
					 * to next session interval.
					 */
					CloseSessions();
					I2ErrLog(eh,
						"SessionRequest: Server busy.");
					goto next_test;
				}
				/*
				 * TODO: Differentiate failure from not allowed.
				 * (? Does it make a difference ?)
				 */
				CloseSessions();
				I2ErrLog(eh,
					"SessionRequest failure. Skipping.");
				goto next_test;
			}
			if(sig_check()) exit(1);
			
			if(IPFNum64Cmp(req_time.ipftime,
						s[p]->tspec.latest_time) > 0){
				I2ErrLog(eh,
					"SessionRequest: returned bad time!");
				/*
				 * TODO: Send SessionRequest of time==0
				 * 	to clear current reservation instead
				 * 	of closing sockets.
				 */
				CloseSessions();
				goto next_test;
			}

			/* save new time for res */
			s[p]->tspec.req_time.ipftime = req_time.ipftime;

			/*
			 * Do we have a meeting?
			 */
			if(IPFNum64Cmp(s[p]->tspec.req_time.ipftime,
					s[q]->tspec.req_time.ipftime) == 0){
				break;
			}
		}

		/* Start receiver */
		if(IPFStartSession(s[0]->cntrl,&dataport) < IPFErrINFO){
			I2ErrLog(eh,"IPFStartSessions: Failed");
			CloseSessions();
			goto next_test;
		}
		if(sig_check()) exit(1);

		/* Start sender */
		if(IPFStartSession(s[1]->cntrl,&dataport) < IPFErrINFO){
			I2ErrLog(eh,"IPFStartSessions: Failed");
			CloseSessions();
			goto next_test;
		}
		if(sig_check()) exit(1);

		endtime = local.tspec.req_time.ipftime;
		endtime = IPFNum64Add(endtime,
				IPFULongToNum64(local.tspec.duration));
		endtime = IPFNum64Add(endtime,fuzz64);
		stop = False;

		/*
		 * 	WaitForStopSessions
		 */
		while(1){
			struct timeval	reltime;
			int		rc;
			fd_set		readfds,exceptfds;

			if(!IPFGetTimeStamp(ctx,&currtime)){
				I2ErrLogP(eh,errno,"IPFGetTimeOfDay: %M");
				exit(1);
			}
			if(stop || (IPFNum64Cmp(currtime.ipftime,endtime) > 0)){
				/*
				 * Send TerminateSession
				 */
				/* sender session to 'null' */
				if( (err_ret = IPFEndSession(s[1]->cntrl,
							&ip_intr,NULL))
							< IPFErrWARNING){
					CloseSessions();
					goto next_test;
				}
				if(sig_check()) exit(1);
				/* receiver session to STDOUT (for now) */
				if( (err_ret =IPFEndSession(s[0]->cntrl,
							&ip_intr,stdout))
							< IPFErrWARNING){
					CloseSessions();
					goto next_test;
				}
				if(sig_check()) exit(1);
				break;
			}

			IPFNum64ToTimeval(&reltime,
					IPFNum64Sub(endtime,currtime.ipftime));
			FD_ZERO(&readfds);
			FD_SET(local.sockfd,&readfds);
			FD_SET(remote.sockfd,&readfds);
			exceptfds = readfds;

			/*
			 * Wait until endtime, or until one of the sockets
			 * is readable.
			 */
			rc = select(MAX(local.sockfd,remote.sockfd)+1,
					&readfds,NULL,&exceptfds,&reltime);

			if(rc > 0){
				/*
				 * One of the sockets is readable. Don't
				 * really care which one. Set stop so
				 * EndSessions happens above.
				 * (Basically, any i/o on either of these
				 * sockets indicates it is time to terminate
				 * the test.)
				 */
				stop = True;
			}
			if(sig_check()) exit(1);
		}

		/*
		 * Skip to here on failure for now. Will perhaps add
		 * intermediate retries until some threshold of the
		 * current period.
		 */
next_test:
		;

		if(sig_check()) exit(1);

	}while(app.opt.continuous || --app.opt.nIntervals);


	exit(0);
}
