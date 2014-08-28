#ifndef TIME_SLOT_H
#define TIME_SLOT_H

#include "bwctldP.h"

typedef enum { SLOT_ANY, SLOT_BANDWIDTH, SLOT_LATENCY } time_slot_types;

typedef struct TimeSlotRec *TimeSlot;
struct TimeSlotRec {
    TAILQ_ENTRY(TimeSlotRec) entries;

    time_slot_types type;
    time_t          start;
    time_t          end;
    int             num_reservations;
    int             max_reservations;
};

TimeSlot time_slot_create(BWLContext ctx, Reservation res, time_t start, time_t end);
TimeSlot time_slot_split(BWLContext ctx, TimeSlot slot, time_t time);
BWLBoolean time_slot_add_reservation(BWLContext ctx, TimeSlot slot, Reservation res);
BWLBoolean time_slot_has_reservation(BWLContext ctx, TimeSlot slot, Reservation res);
BWLBoolean time_slot_remove_reservation(BWLContext ctx, TimeSlot slot, Reservation res);

#endif
