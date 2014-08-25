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

#ifndef RESERVATION_H
#define RESERVATION_H

#include <bwlib.h>

typedef struct ReservationRec *Reservation;
struct ReservationRec {
    BWLToolType tool;
    BWLSID      sid;
    BWLNum64    restime;
    BWLNum64    start;    /* fuzz applied */
    BWLNum64    end;    /* fuzz applied */
    BWLNum64    fuzz;
    char        *sender;
    char        *receiver;
    uint32_t    duration;
    uint16_t    toolport;

    BWLBoolean  scheduled;
};

Reservation reservation_create(
        BWLContext  ctx,
        BWLSID      sid,
        BWLToolType tool_id,
        const char  *sender,
        const char  *receiver
        );

void reservation_free(BWLContext ctx, Reservation res);

#endif
