/*
 * @Author: pingox
 * @Copyright: pngox
 * @Github: https://github.com/pingox
 * @EMail: cczjp89@gmail.com
 */

#ifndef __NGX_WEBSOCKET_H_INCLUDE__
#define __NGX_WEBSOCKET_H_INCLUDE__

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <ngx_config.h>
#include <ngx_http.h>

#define NGX_WEBSOCKET_REC_CONF 0x00010000

#define NGX_WEBSOCKET_MAX_CHUNK_HEADER 14

#define NGX_WEBSOCKET_OPCODE_TEXT   0X01
#define NGX_WEBSOCKET_OPCODE_BINARY 0X02
#define NGX_WEBSOCKET_OPCODE_CLOSE  0X08
#define NGX_WEBSOCKET_OPCODE_PING   0X09
#define NGX_WEBSOCKET_OPCODE_PONG   0X0A

typedef struct ngx_websocket_header_s ngx_websocket_header_t;
typedef struct ngx_websocket_frame_s ngx_websocket_frame_t;
typedef struct ngx_websocket_session_s ngx_websocket_session_t;
typedef struct ngx_websocket_ctx_s ngx_websocket_ctx_t;
typedef struct ngx_websocket_loc_conf_s ngx_websocket_loc_conf_t;

typedef void (* ngx_websocket_recv_handler_pt)
                (ngx_websocket_session_t *ws, ngx_str_t *msg, u_char opcode);
typedef void (* ngx_websocket_connect_handler_pt)(ngx_websocket_session_t *ws);
typedef void (* ngx_websocket_disconnect_handler_pt)(ngx_websocket_session_t *ws);

struct ngx_websocket_header_s {
    u_char    fin:1;
    u_char    rsv1:1;
    u_char    rsv2:1;
    u_char    rsv3:1;
    u_char    opcode:4;

    u_char    mask:1;
    u_char    payload_length:7;

    uint16_t  extended_playload_length16;
    uint64_t  extended_playload_length64;

    u_char    masking_key[4];
};

struct ngx_websocket_frame_s {
    u_char                   *phl;
    u_char                   *ph;
    ngx_uint_t                opcode:4;
    ngx_flag_t                append;
    uint64_t                  len;
    uint64_t                  mlen;
    ngx_buf_t                *buf;
    ngx_websocket_frame_t    *next;
};

struct ngx_websocket_session_s {
    ngx_http_request_t                    *r;
    ngx_websocket_recv_handler_pt          recv_handler;
    ngx_websocket_disconnect_handler_pt    disconnect_handler;
    ngx_pool_t                            *pool;
    ngx_log_t                             *log;
    ngx_websocket_frame_t                  in_frame;
    ngx_event_t                            ping_evt;
    ngx_msec_t                             ping_interval;
    ngx_msec_t                             timeout;
    ngx_msec_t                             last_recv;
    ngx_chain_t                          **out;
    ngx_uint_t                             out_last;
    ngx_uint_t                             out_pos;
    ngx_uint_t                             out_queue;
    ngx_chain_t                           *out_chain;
    void                                  *ctx[];
};

struct ngx_websocket_ctx_s {
    ngx_websocket_session_t   *ws;
};

struct ngx_websocket_loc_conf_s {
    ngx_str_t                           name;
    ngx_websocket_connect_handler_pt    connect_handler;
    ngx_uint_t                          out_queue;
    ngx_uint_t                          max_length;
    ngx_chain_t                        *in_free;
    ngx_pool_t                         *pool;
    ngx_msec_t                          ping_interval;
    ngx_msec_t                          timeout;
};

void ngx_websocket_read_handler(ngx_http_request_t *r);
void *ngx_websocket_rmemcpy(void *dst, const void* src, size_t n);

ngx_int_t ngx_websocket_send_message(
        ngx_websocket_session_t *ws, ngx_str_t *str, ngx_int_t opcode);
void
ngx_websocket_finalize_session(ngx_websocket_session_t *s);

#include "ngx_http_set_header.h"

extern ngx_module_t  ngx_websocket_module;

#endif
