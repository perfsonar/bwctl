#include <stdlib.h>

#include "time_slot.h"
#include "reservation.h"

TimeSlot time_slot_create(BWLContext ctx, Reservation res, time_t start, time_t end) {
    TimeSlot new_slot = calloc(1, sizeof(struct TimeSlotRec));
    if (!new_slot)
        return NULL;

    new_slot->type  = SLOT_ANY;
    new_slot->start = start;
    new_slot->end   = end;
    new_slot->num_reservations = 0;
    new_slot->max_reservations = 30;

    time_slot_add_reservation(ctx, new_slot, res);

    return new_slot;
}

TimeSlot time_slot_split(BWLContext ctx, TimeSlot slot, time_t time) {
    TimeSlot new_slot = calloc(1, sizeof(struct TimeSlotRec));
    if (!new_slot)
        return NULL;

    new_slot->start = time;
    new_slot->end = slot->end;
    new_slot->num_reservations = slot->num_reservations;
    new_slot->max_reservations = slot->max_reservations;

    slot->end = time - 1;

    return new_slot;
}

void time_slot_free(TimeSlot slot) {
    free(slot);
}

BWLBoolean time_slot_has_reservation(BWLContext ctx, TimeSlot slot, Reservation res) {
    time_t res_start;
    time_t res_end;

    /*
     * Convert the res start/end to a 'second' instead of the sub-second
     * resolution. The slots are all on second 'granularity'.
     */
    res_start = BWLNum64ToTimestamp(res->start);
    res_end   = BWLNum64ToTimestamp(res->end) + 1;


    if (difftime(slot->start, res_end) > 0)
        return False;

    if (difftime(slot->end, res_start) < 0)
        return False;

    return True;
}

BWLBoolean time_slot_add_reservation(BWLContext ctx, TimeSlot slot, Reservation res) {
    BWLTestType test_type = BWLToolGetTestTypesByID(ctx,res->tool);

    if (test_type == BWL_TEST_THROUGHPUT) {
        slot->type = SLOT_BANDWIDTH;
    }
    else if (test_type == BWL_TEST_LATENCY) {
        slot->type = SLOT_LATENCY;
    }

    slot->num_reservations++;

    return True;
}

BWLBoolean time_slot_remove_reservation(BWLContext ctx, TimeSlot slot, Reservation res) {
    slot->num_reservations--;

    return True;
}

BWLBoolean time_slot_reservation_usable(BWLContext ctx, Reservation res, TimeSlot slot) {
    BWLTestType test_type = BWLToolGetTestTypesByID(ctx,res->tool);

    if (test_type == BWL_TEST_THROUGHPUT) {
        // There is already a throughput test here.
        if (slot->type == SLOT_BANDWIDTH) {
            return False;
        }
        else if (slot->type == SLOT_LATENCY) {
            return False;
        }
    }
    else if (test_type == BWL_TEST_LATENCY) {
        // There is already a throughput test here.
        if (slot->type == SLOT_BANDWIDTH) {
            return False;
        }
    }

    if (slot->num_reservations == slot->max_reservations) {
       return False;
    }

   return True;
}



