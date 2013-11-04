/*
 *      $Id$
 */
/*
 *	File:		bwctldP.h
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Sep  9 16:07:42 MDT 2003
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
#ifndef	_BWCTLDP_H_
#define	_BWCTLDP_H_

#ifndef	BWCTLD_CONF_FILE
#define	BWCTLD_CONF_FILE	"bwctld.conf"
#endif

#define	BWCTLD_IPERF_DEF_TESTPORT	(5001)
#define	BWCTLD_THRULAYD_DEF_TESTPORT	(5003)

#include <sys/queue.h>

#include "policy.h"

/*
 * Types
 */
typedef struct {
    I2Boolean	    help;

    char	    cwd[MAXPATHLEN];
    char	    *confdir;
    char	    *vardir;

    char	    *authmode;
    uint32_t	    auth_mode;	/* cooked version of authmode */
    char	    *srcnode;

    char	    *user;
    char	    *group;
    I2Boolean       allowRoot;

    uint32_t	    dieby;
    uint32_t	    controltimeout;
    I2Boolean	    daemon;

    char            **posthook;
    int             posthook_count;
} bwctld_opts;

typedef struct ReservationRec ReservationRec, *Reservation;
struct ReservationRec{
    BWLToolType tool;
    BWLSID      sid;
    BWLNum64    restime;
    BWLNum64    start;    /* fuzz applied */
    BWLNum64    end;    /* fuzz applied */
    BWLNum64    fuzz;
    uint32_t    duration;
    uint16_t    toolport;
    Reservation next;
};

typedef struct ChldStateRec ChldStateRec, *ChldState;
struct ChldStateRec{
    BWLDPolicy      policy;
    pid_t           pid;
    int             fd;
    BWLDPolicyNode  node;
    Reservation     res;
};

typedef enum { SLOT_ANY, SLOT_BANDWIDTH, SLOT_LATENCY } time_slot_types;

typedef struct TimeSlotRec *TimeSlot;
struct TimeSlotRec {
    TAILQ_ENTRY(TimeSlotRec) entries;

    time_slot_types type;
    BWLNum64        start;
    BWLNum64        end;
    int             num_reservations;
    int             max_reservations;
};

static void DisplayTimeSlots();

#endif	/*	_BWCTLDP_H_	*/
