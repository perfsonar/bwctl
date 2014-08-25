/*
 * ex: set tabstop=4 ai expandtab softtabstop=4 shiftwidth=4:
 * -*- mode: c-basic-indent: 4; tab-width: 4; indent-tabls-mode: nil -*-
 *      $Id$
 */
/*
 *    File:         reservation.c
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

#include "scheduler.h"
#include "time_slot.h"

Reservation reservation_create(
        BWLContext  ctx,
        BWLSID      sid,
        BWLToolType tool_id,
        const char  *sender,
        const char  *receiver
        )
{
    BWLErrSeverity  err = BWLErrOK;
    Reservation     res = NULL;

    if( !(res = calloc(1,sizeof(*res)))){
        BWLError(ctx,BWLErrFATAL,ENOMEM,"malloc(): %M");
        goto error_exit;
    }

    res->sender = strdup(sender);
    if (!res->sender) {
        BWLError(ctx,err,BWLErrINVALID,"reservation_create: strdup() failed");
        goto error_exit;
    }

    res->receiver = strdup(receiver);
    if (!res->receiver) {
        BWLError(ctx,err,BWLErrINVALID,"reservation_create: strdup() failed");
        goto error_exit;
    }

    memcpy(res->sid,sid,sizeof(sid));

    res->tool = tool_id;
    res->scheduled = False;

    return res;

error_exit:
    if (res) {
        reservation_free(ctx, res);
    }

    return NULL;
}

void reservation_free(BWLContext ctx, Reservation res) {
    if (res->receiver)
        free(res->receiver);
    if (res->sender)
        free(res->sender);
    free(res);

    return;
}
