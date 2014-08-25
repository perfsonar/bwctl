/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabls-mode: nil -*-
 *      $Id$
 */
/*
 *    File:         scheduler.c
 *
 *    Author:       Aaron Brown
 *                  Internet2
 *
 *    Description:    
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
#include <stdlib.h>
#include <string.h>

#if defined(HAVE_SYS_QUEUE_H)
#include <sys/queue.h>
#else
#include "missing_queue.h"
#endif

#include "scheduler.h"
#include "time_slot.h"

/* Global variable - the total number of allowed Control connections. */
static TAILQ_HEAD(timeslots_head, TimeSlotRec) time_slots = TAILQ_HEAD_INITIALIZER(time_slots);

struct timeslots_head *time_slots_head;

static void reservation_display_status(BWLContext ctx, Reservation res, const char *action);
static void display_time_slots(BWLContext ctx);

BWLBoolean scheduler_remove_reservation(BWLContext ctx, Reservation res) {
    TimeSlot slot;
    TimeSlot slot_temp;
    int i;

    for(slot = TAILQ_FIRST(&time_slots); slot; slot = slot_temp ) {
        i++;
        slot_temp = TAILQ_NEXT(slot, entries);

        if (time_slot_has_reservation(ctx, slot, res) == False)
            continue;

        time_slot_remove_reservation(ctx, slot, res);

        if (slot->num_reservations == 0) {
            TAILQ_REMOVE(&time_slots, slot, entries);
            time_slot_free(slot);
        }
    }

    res->scheduled = False;

    return True;
}

void scheduler_delete_reservation(BWLContext ctx, Reservation res, char *action) {
    reservation_display_status(ctx, res, action);

    scheduler_remove_reservation(ctx, res);
    reservation_free(ctx, res);

    return;
}

static void reservation_display_status(BWLContext ctx, Reservation res, const char *action) {
    BWLTimeStamp    currtime;

    if(!BWLGetTimeStamp(ctx,&currtime)){
        BWLError(ctx,BWLErrINVALID,errno,
                "reservation_display_status: BWLGetTimeStamp: %M");
        return;
    }

    BWLError(ctx,BWLErrDEBUG, BWLErrUNKNOWN, "Reservation Status: %X -> %X", res->sender, res->receiver);

    BWLError(ctx,BWLErrDEBUG, BWLErrUNKNOWN,
            "Reservation Status: time=%lu action=%s sender=%s receiver=%s tool=%s res_start=%lu res_end=%lu test_start=%lu",
            BWLNum64ToTimestamp(currtime.tstamp),
            action,
            res->sender,
            res->receiver,
            BWLToolGetNameByID(ctx,res->tool),
            BWLNum64ToTimestamp(res->start),
            BWLNum64ToTimestamp(res->end),
            BWLNum64ToTimestamp(res->restime));

    return;
}

BWLBoolean scheduler_add_reservation(
        BWLContext  ctx,
        Reservation res,
        BWLNum64    rtime,
        BWLNum64    fuzz,
        BWLNum64    ltime,
        uint32_t    duration,
        BWLNum64    rtttime,
        uint16_t    *toolport,
        BWLNum64    *restime)
{
    BWLTimeStamp    currtime;
    TimeSlot        prev_slot;
    BWLNum64        dtime;    /* duration with fuzz applied */
    BWLNum64        minstart;
    TimeSlot        slot;
    int             added;
    TimeSlot        new_slot;
    char            *action = "new";

    /*
     * Invoke 'tool' initialization phase to set the tool port
     */
    if( BWLErrOK != BWLToolInitTest(ctx,res->tool,toolport) ){
        BWLError(ctx,BWLErrFATAL,errno,
                "scheduler_add_reservation: Tool initialization failed");
        return False;
    }

    res->toolport = *toolport;

    if(!BWLGetTimeStamp(ctx,&currtime)){
        BWLError(ctx,BWLErrFATAL,errno,
                "scheduler_add_reservation: BWLGetTimeStamp: %M");
        return False;
    }

    /*
     * Determine earliest time the test can happen.
     * This is the max of the earliest time the deamon is willing
     * to have a test and the requested time.
     * The algorithm being used to determine the "earliest time
     * the daemon" is willing to have a test is:
     *
     *    2 X rtt(client) + fuzztime(otherserver)
     *
     * The actual message time is:
     *    server            client
     *    request response ->
     *            <-    start sessions
     *    start response    ->
     *    (This is only 1.5 rtt, but rouding up to 2 rtt seems prudent)
     *
     * The reservation is defined by the following vars:
     * res->restime == time of reservation
     * res->start == fuzz applied to beginning of that
     * res->end == fuzz applied to res->restime + duration
     * The time period from res->start to res->end is completely
     * allocated to this test.
     */
    res->start = BWLNum64Sub(rtime,fuzz);
    minstart =BWLNum64Add(currtime.tstamp,
            BWLNum64Add(fuzz,
                BWLNum64Mult(rtttime,BWLULongToNum64(2))));
    /*
     * If the start time is less than the minimum start time, then
     * reset the start time to one second past the minimum start time.
     * minstart should take into account rtt times. The one second is
     * simply a small buffer space so that rounding error and random
     * extra delay to the other server will still allow a reservation.
     */
    if(BWLNum64Cmp(res->start,minstart) < 0){
        res->start = BWLNum64Add(minstart,BWLULongToNum64(1));
    }
    res->restime = BWLNum64Add(res->start,fuzz);

    dtime = BWLNum64Add(BWLULongToNum64(duration),fuzz);
    res->end = BWLNum64Add(res->restime,dtime);
    res->fuzz = fuzz;
    res->duration = duration;

    /*
     * Open slot too late
     */
    if(ltime && (BWLNum64Cmp(res->restime,ltime) > 0)){
        *restime = res->restime;
        goto denied;
    }

    /********************************
     * Find an open slot        *
     ********************************/
    added = 0;
    prev_slot = NULL;

    TAILQ_FOREACH(slot, &time_slots, entries) {
        time_t res_start;
        time_t res_end;

        /*
         * Make sure the reservation time, and end time matches what's expected
         * based on its start time
         */
        if (BWLNum64Cmp(res->end, res->start) <= 0) {
            res->restime = BWLNum64Add(res->start,res->fuzz);
            res->end = BWLNum64Add(res->restime,dtime); 
            BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,"Reservation Time Set: %lu",
                    BWLNum64ToTimestamp(res->restime));

        }

        /*
         * Check if the open slot too late
         */
        if(ltime && (BWLNum64Cmp(res->restime,ltime) > 0)) {
            *restime = res->restime;
            goto denied;
        }

        /*
         * Convert the res start/end to a 'second' instead of the sub-second
         * resolution. The slots are all on second 'granularity'.
         */
        res_start = BWLNum64ToTimestamp(res->start);
        res_end   = BWLNum64ToTimestamp(res->end) + 1;

        /*
         * Skip ahead trying to find a slot that might overlap this reservation
         */
        if (difftime(slot->end, res_start) < 0) {
            prev_slot = slot;
            continue;
        }

        /*
         * If this slot starts after our reservation ends, we just add a new
         * time slot covering this reservation since it doesn't overlap any
         * reservations.
         */
        if ((!prev_slot || difftime(prev_slot->end, res_start) < 0) && difftime(res_end, slot->start) < 0) {
            // There is enough time between the end of the previous slot, and
            // the beginning of the next one to make a new slot.
            TimeSlot new_slot = time_slot_create(ctx, res, res_start, res_end);

            TAILQ_INSERT_BEFORE(slot, new_slot, entries);

            added = 1;

            break;
        }

        /*
         * Skip this slot if it's already full
         */
        if (time_slot_reservation_usable(ctx, res, slot) == False) {
            prev_slot = slot;
            res->start = BWLTimestampToNum64(slot->end + 1);
            res->restime = BWLNum64Add(res->start,res->fuzz);
            res->end = BWLNum64Add(res->restime,dtime); 
            continue;
        }
        else {
            /*
             * Using the current slot as a starting point, check whether it's
             * possible to run the test by going through all the slots that
             * overlap the reservation, and make sure they're all copacetic
             * with this test before performed as well.
             */
            TimeSlot first_slot = slot;
            TimeSlot last_slot = slot;
            TimeSlot conflicting_slot = NULL;

            /*
             * By the end of this loop, first_slot will be the first slot that
             * overlaps the reservation, and last_slot will be the last slot
             * that overlaps the reservation.
             */
            while (difftime(last_slot->end, res_end) <= 0) {
                TimeSlot next_slot = TAILQ_NEXT(last_slot, entries);

                if (!next_slot)
                    break;

                if (difftime(res_end, next_slot->start) < 0)
                    break;

                if (time_slot_reservation_usable(ctx, res, next_slot) == False) {
                    conflicting_slot = next_slot;
                    break;
                }

                last_slot = next_slot;
            }

            if (conflicting_slot) {
                // might as well skip ahead to the end of the conflicting slot
                res->start = BWLTimestampToNum64(conflicting_slot->end + 1);
                res->restime = BWLNum64Add(res->start,res->fuzz);
                res->end = BWLNum64Add(res->restime,dtime); 
            }
            else {
                TimeSlot temp_slot;

                if (difftime(first_slot->start, res_start) < 0) {
                    // Our reservation partially overlaps this slot, so we need
                    // to split the existing slot to divide into two new slots:
                    // one that handles the time period up until the new
                    // reservation starts, and one that handles the time period
                    // after.
                    TimeSlot new_slot = time_slot_split(ctx, first_slot, res_start);

                    TAILQ_INSERT_AFTER(&time_slots, first_slot, new_slot, entries);

                    // first_slot is meant to refer to the first slot that
                    // overlaps the reservation. The time_slot_split function
                    // will return the timeslot after the split point, i.e.
                    // it's the first slot that overlaps our reservation. Also,
                    // since we're changing the first slot, we might be
                    // changing the last slot as well.
                    if (last_slot == first_slot)
                        last_slot = new_slot;

                    first_slot = new_slot;
                }
                else if (difftime(res_start, first_slot->start) < 0) {
                    // We need to create an additional slot to handle
                    // res->start to first_slot->start.
                    TimeSlot new_slot = time_slot_create(ctx, res, res_start, first_slot->start - 1);

                    TAILQ_INSERT_BEFORE(first_slot, new_slot, entries);
                }

                if (difftime(res_end, last_slot->end) < 0) {
                    // Our reservation partially overlaps this slot, so we need
                    // to split the existing slot to divide into two new slots:
                    // the slot up to when our reservation ends, and the slot
                    // after our reservation ends.
                    TimeSlot new_slot = time_slot_split(ctx, last_slot, res_end + 1);

                    TAILQ_INSERT_AFTER(&time_slots, last_slot, new_slot, entries);
                }
                else if (difftime(last_slot->end, res_end) < 0) {
                    // We need to create an additional slot to handle
                    // last_slot->end to res->end.
                    TimeSlot new_slot = time_slot_create(ctx, res, last_slot->end + 1, res_end);

                    TAILQ_INSERT_AFTER(&time_slots, last_slot, new_slot, entries);
                }

                temp_slot = first_slot;
                while (temp_slot) {
                    time_slot_add_reservation(ctx, temp_slot, res);

                    if (temp_slot == last_slot)
                        temp_slot = NULL;
                    else
                        temp_slot = TAILQ_NEXT(temp_slot, entries);
                }

                added = 1;
                break;
            }
        }
    }

    if (!added) {
        time_t res_start;
        time_t res_end;

        // Error out if the new reservation time is too late
        if(ltime && (BWLNum64Cmp(res->restime,ltime) > 0)){
            *restime = res->restime;
            goto denied;
        }

        /*
         * Convert the res start/end to a 'second' instead of the sub-second
         * resolution. The slots are all on second 'granularity'.
         */
        res_start = BWLNum64ToTimestamp(res->start);
        res_end   = BWLNum64ToTimestamp(res->end) + 1;

        new_slot = time_slot_create(ctx, res, res_start, res_end);

        /*
         * Two reasons it wasn't added: nothing in the list, or its start time
         * is later than everything in the list.
         */
        if (TAILQ_EMPTY(&time_slots)) {
            TAILQ_INSERT_HEAD(&time_slots, new_slot, entries);
        }
        else {
            TAILQ_INSERT_TAIL(&time_slots, new_slot, entries);
        }
    }

    BWLError(ctx, BWLErrDEBUG, BWLErrUNKNOWN,
            "Test Reservation Information: Current Time: %lu, Fuzz: %f, Reservation Start: %lu, Reservation End: %lu, Test Start Time: %lu",
            BWLNum64ToTimestamp(currtime.tstamp),
            BWLNum64ToDouble(fuzz),
            BWLNum64ToTimestamp(res->start),
            BWLNum64ToTimestamp(res->end) + 1,
            BWLNum64ToTimestamp(res->restime));

    reservation_display_status(ctx, res, action);

    display_time_slots(ctx);

    res->scheduled = True;

    *restime = res->restime;
    *toolport = res->toolport;

    return True;

denied:
    res->scheduled = False;

    BWLError(ctx, BWLErrDEBUG, BWLErrUNKNOWN,
            "Unable to find reservation before \"last time\"");
    return False;
}

static void
display_time_slots(BWLContext ctx)
{
    TimeSlot slot;
    int i;

    BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN, "Time Slots");

    i = 1;

    TAILQ_FOREACH(slot, &time_slots, entries) {
        BWLError(ctx,BWLErrDEBUG,BWLErrUNKNOWN,
                  "Time Slot %d: %lu to %lu: %d reservations\n",
                  i, slot->start,
                  slot->end, slot->num_reservations);
        i++;
    }
}
