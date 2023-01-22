/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 *
 * Implements S7comm JSON logging portion of the engine.
 */

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-s7comm.h"

#include "conf.h"
#include "debug.h"
#include "detect.h"

#include "output.h"
#include "output-json.h"
#include "output-json-s7comm.h"

#include "pkt-var.h"
#include "suricata-common.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-buffer.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"

typedef struct LogS7commFileCtx_ {
    uint32_t   flags;
    LogFileCtx *file_ctx;
} LogS7commFileCtx;

typedef struct LogS7commLogThread_ {
    LogFileCtx       *file_ctx;
    LogS7commFileCtx *s7commlog_ctx;
    MemBuffer        *buffer;
} LogS7commLogThread;

static int JsonS7commLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    S7commTransaction *s7commtx = tx;
    LogS7commLogThread *thread = thread_data;
    
    SCLogNotice("Logging s7comm transaction %" PRIu64 ".", s7commtx->tx_id);
    
    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "s7comm", NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }
    
    jb_open_object(jb, "s7comm");
    
    /* Log the request buffer. */
    if (s7commtx->request_buffer != NULL) {
        jb_set_string_from_bytes(jb, "request", s7commtx->request_buffer,
                s7commtx->request_buffer_len);
    }
    
    /* Log the response buffer. */
    if (s7commtx->response_buffer != NULL) {
        jb_set_string_from_bytes(jb, "response", s7commtx->response_buffer,
                s7commtx->response_buffer_len);
    }
    
    /* Close s7comm. */
    jb_close(jb);
    
    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(jb, thread->file_ctx, &thread->buffer);
    
    jb_free(jb);
    return TM_ECODE_OK;
}

static void OutputS7commLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogS7commFileCtx *s7commlog_ctx = (LogS7commFileCtx *)output_ctx->data;
    SCFree(s7commlog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputS7commLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    
    LogS7commFileCtx *s7commlog_ctx = SCCalloc(1, sizeof(*s7commlog_ctx));
    if (unlikely(s7commlog_ctx == NULL)) {
        return result;
    }
    s7commlog_ctx->file_ctx = ajt->file_ctx;
    
    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(s7commlog_ctx);
        return result;
    }
    output_ctx->data = s7commlog_ctx;
    output_ctx->DeInit = OutputS7commLogDeInitCtxSub;
    
    SCLogNotice("S7comm log sub-module initialized.");
    
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_S7COMM);
    
    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonS7commLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogS7commLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }
    
    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogS7comm.");
        goto error_exit;
    }
    
    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }
    
    thread->s7commlog_ctx = ((OutputCtx *)initdata)->data;
    thread->file_ctx = LogFileEnsureExists(thread->s7commlog_ctx->file_ctx, t->id);
    if (!thread->file_ctx) {
        goto error_exit;
    }
    *data = (void *)thread;
    
    return TM_ECODE_OK;

error_exit:
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonS7commLogThreadDeinit(ThreadVars *t, void *data)
{
    LogS7commLogThread *thread = (LogS7commLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonS7commLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_S7COMM, "eve-log", "JsonS7commLog", "eve-log.s7comm",
            OutputS7commLogInitSub, ALPROTO_S7COMM, JsonS7commLogger,
            JsonS7commLogThreadInit, JsonS7commLogThreadDeinit, NULL);
    
    SCLogNotice("S7comm JSON logger registered.");
}