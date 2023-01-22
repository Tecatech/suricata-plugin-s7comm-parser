/* Copyright (C) 2015-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Dmitriy Rodionov <rodionovmephi@gmail.com>
 */

#ifndef __APP_LAYER_S7COMM_H__
#define __APP_LAYER_S7COMM_H__

#include "detect-engine-state.h"
#include "queue.h"
#include "rust.h"

void RegisterS7commParsers(void);
void S7commParserRegisterTests(void);

typedef struct S7commTransaction {
    uint64_t tx_id;                        /**< internal: id */
    uint32_t request_buffer_len;
    uint32_t response_buffer_len;
    uint8_t  *request_buffer;
    uint8_t  *response_buffer;
    uint8_t response_done;                 /**< response flag */
    
    AppLayerDecoderEvents *decoder_events; /**< application layer event */
    DetectEngineState *de_state;
    
    TAILQ_ENTRY(S7commTransaction) next;
    AppLayerTxData tx_data;
} S7commTransaction;

typedef struct S7commState {
    TAILQ_HEAD(, S7commTransaction) tx_list; /**< transaction list */
    uint64_t transaction_max;                /**< transaction count */
} S7commState;

#endif /* __APP_LAYER_S7COMM_H__ */