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

#ifndef __DETECT_S7COMM_BUFFER_H__
#define __DETECT_S7COMM_BUFFER_H__

#include "app-layer-s7comm.h"

typedef struct DetectS7comm_ {
    uint8_t type;
    uint8_t function;
    bool    type_match;
    bool    function_match;
} DetectS7comm;

void DetectS7commBufferRegister(void);

#endif /* __DETECT_S7COMM_BUFFER_H__ */