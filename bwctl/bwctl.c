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
static	ipapp_trec		appctx;
static	I2ErrHandle		eh;
static	IPFTestSpec		tspec;
static	u_int32_t		sessionTime;
static	u_int32_t		file_offset,ext_offset;
static	int			ip_reset = 0;
static	int			ip_exit = 0;
static	double			inf_delay;
static	IPFContext		ctx;
static	IPFControl		lcntrl;
static	IPFControl		rcntrl;

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
	somestate.childwait = appctx.opt.childwait;
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
		char	*s = appctx.opt.authmode;
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
	IPFContext		ctx;

	int			fname_len;
	int			ch;
	char                    *endptr = NULL;
	char                    optstring[128];
	static char		*conn_opts = "A:B:k:U:";
	static char		*out_opts = "d:I:pe:rv";
	static char		*test_opts = "i:l:uw:P:S:b:t:cs";
	static char		*gen_opts = "hW";

	char			dirpath[PATH_MAX];
	struct flock		flk;
	struct sigaction	act;

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
	memset(&appctx,0,sizeof(appctx));
	appctx.opt.timeDuration = 10;

	while ((ch = getopt(argc, argv, optstring)) != -1)
		switch (ch) {
		/* Connection options. */
		case 'A':
			if (!(appctx.opt.authmode = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;
		case 'B':
			if (!(appctx.opt.srcaddr = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;
		case 'U':
			if (!(appctx.opt.identity = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;
		case 'k':
			if (!(appctx.opt.keyfile = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;

		/* OUTPUT OPTIONS */
		case 'd':
			if (!(appctx.opt.savedir = strdup(optarg))) {
				I2ErrLog(eh,"malloc:%M");
				exit(1);
			}
			break;
		case 'I':
			appctx.opt.seriesInterval =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'p':
			appctx.opt.printfiles = True;
			break;
		case 'e':
		case 'r':
			/* handled in prior getopt call... */
			break;
		case 'v':
			appctx.opt.version = True;
			I2ErrLog(eh,"Version: $Revision$");
			exit(0);

		/* TEST OPTIONS */
		case 'c':
			appctx.opt.send = True;
			break;
		case 's':
			appctx.opt.recv = True;
			break;
		case 'i':
			appctx.opt.reportInterval =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'l':
			appctx.opt.lenBuffer =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'u':
			appctx.opt.udpTest = True;
			break;
		case 'w':
			appctx.opt.windowSize =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 'P':
			appctx.opt.parallel =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			I2ErrLog(eh,"-P option not currently supported");
			exit(1);
			break;
		case 'S':
			appctx.opt.tos =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			I2ErrLog(eh,"-S option not currently supported");
			exit(1);
			break;
		case 'b':
			appctx.opt.bandWidth =strtoul(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
		case 't':
			appctx.opt.timeDuration = strtoul(optarg, &endptr, 10);
			if((*endptr != '\0') || (appctx.opt.timeDuration == 0)){
				usage(progname, 
				"Invalid value. Positive integer expected");
				exit(1);
			}
			break;
#ifndef	NDEBUG
		case 'W':
			appctx.opt.childwait = True;
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

	appctx.remote_test = argv[0];
	if(argc > 1)
		appctx.remote_serv = argv[1];
	else
		appctx.remote_serv = appctx.remote_test;

	if(appctx.opt.recv == appctx.opt.send){
		usage(progname,"Exactly one of -s or -c must be specified.");
		exit(1);
	}

	/*
	 * Check savedir option. Make sure it will not make fnames
	 * exceed PATH_MAX even with the nul byte.
	 * Also set file_offset and ext_offset to the lengths needed.
	 */
	fname_len = TSTAMPCHARS + strlen(IPF_FILE_EXT) + strlen(SUMMARY_EXT);
	assert((fname_len+1)<PATH_MAX);
	if(appctx.opt.savedir){
		if((strlen(appctx.opt.savedir) + strlen(IPF_PATH_SEPARATOR)+
						fname_len + 1) > PATH_MAX){
			usage(progname,"-d: pathname too long.");
			exit(1);
		}
		strcpy(dirpath,appctx.opt.savedir);
		strcat(dirpath,IPF_PATH_SEPARATOR);
	}else
		dirpath[0] = '\0';

	if(!appctx.opt.timeDuration){
		appctx.opt.timeDuration = 10; /* 10 second default */
	}

	if(appctx.opt.seriesInterval <
				(appctx.opt.timeDuration + SETUP_ESTIMATE)){
		usage(progname,"-I: interval too small relative to -t");
		exit(1);
	}

	if(appctx.opt.udpTest && !appctx.opt.bandWidth){
		appctx.opt.bandWidth = DEF_UDP_RATE;
	}

	if(appctx.opt.bandWidth && !appctx.opt.udpTest){
		usage(progname,"-b: only valid with -u");
		exit(1);
	}

	/*
	 * Lock the directory for iperfc if it is in printfiles mode.
	 */
	if(appctx.opt.printfiles){
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
	 * Setup Test Session record.
	 */
	/* skip req_time/latest_time - set per/test */
	memset(&tspec,0,sizeof(tspec));
	tspec.duration = appctx.opt.timeDuration;
	tspec.udp = appctx.opt.udpTest;
	if(tspec.udp){
		tspec.bandwidth = appctx.opt.bandWidth;
	}
	tspec.window_size = appctx.opt.windowSize;
	tspec.len_buffer = appctx.opt.lenBuffer;
	tspec.report_interval = appctx.opt.reportInterval;

	/*
	 * TODO: Fix this.
	 * Setup policy stuff - this currently sucks.
	 */
	ip_set_auth(&appctx,progname,ctx); 

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(ctx = IPFContextCreate(eh))){
		I2ErrLog(eh, "Unable to initialize IPF library.");
		exit(1);
	}

	/*
	 * TODO
	 * If doing sessionInterval:
	 * 	create a pseudo-poisson context
	 * 	sleep for rand([0,1])*sessionInterval (spread out start time)
	 * 	create loop for the remainder of main() that sets up a test
	 * 	every sessionInterval*pseudo-poisson
	 */
	IPFTimeStamp	reqtime;
	IPFTimeStamp	curtime;
	IPFNum64	tval;

	do{
		memset(&reqtime,0,sizeof(reqtime));

		/* Open remote connection */
		/* get socknam to get addr for local */

		/* Get TimeErrEst and round-trip-bound */
		if(IPFControlTimeCheck(rcntrl,NULL) != IPFErrOK){
			I2ErrLogP(eh,errno,"IPFControlTimeCheck: %M");
			exit(1);
		}
		tval = IPFGetRTTBound(rcntrl);
		/* reqtime.ipftime += (2*round-trip-bound) */
		reqtime.ipftime = IPFNum64Add(reqtime.ipftime,
					IPFNum64Mult(tval,IPFULongToNum64(2)));


		/* Open local connection */

		/* Get TimeErrEst and round-trip-bound */
		if(IPFControlTimeCheck(lcntrl,NULL) != IPFErrOK){
			I2ErrLogP(eh,errno,"IPFControlTimeCheck: %M");
			exit(1);
		}
		tval = IPFGetRTTBound(lcntrl);
		/* reqtime.ipftime += (2*round-trip-bound) */
		reqtime.ipftime = IPFNum64Add(reqtime.ipftime,
					IPFNum64Mult(tval,IPFULongToNum64(2)));

		/*
		 * reqtime currently holds a reasonable relative amount of
		 * time from 'now' that a test could be held. Get the current
		 * time and add to make that an 'absolute' value.
		 */
		if(!IPFGetTimeOfDay(&curtime)){
			I2ErrLogP(eh,errno,"IPFGetTimeOfDay: %M");
			exit(1);
		}
		reqtime.ipftime = IPFNum64Add(reqtime.ipftime,curtime.ipftime);

		/*
		 * Get a reservation
		 */
		STime = RTime = 0;
		do{
			/* recver*/
			/* sender*/
		}while(STime != RTime);

		/* TODO: Add sighandler for SIGINT that sends StopSessions */

	}while(0); /* TODO: test for "next" interval time */


	exit(0);
}
