#ifndef __NGX_WEBSOCKET_H_INCLUDE__
#define __NGX_WEBSOCKET_H_INCLUDE__

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <ngx_config.h>
#include <ngx_http.h>

typedef struct ngx_websocket_loc_conf_s ngx_websocket_loc_conf_t;
typedef struct ngx_websocket_session_s ngx_websocket_session_t;

typedef void (* ngx_websocket_recv_handler_pt)(ngx_websocket_session_t *ws);
typedef void (* ngx_websocket_connect_handler_pt)(ngx_websocket_session_t *ws);
typedef void (* ngx_websocket_disconnect_handler_pt)(ngx_websocket_session_t *ws);

struct ngx_websocket_session_s {
    ngx_http_request_t                    *r;
    ngx_websocket_recv_handler_pt          recv_handler;
    ngx_websocket_disconnect_handler_pt    disconnect_handler;
    ngx_pool_t                            *pool;
    ngx_log_t                             *log;
    ngx_uint_t                             chunk_size;
    void                                  *ctx[];
};

struct ngx_websocket_loc_conf_s {
    ngx_websocket_connect_handler_pt    connect_handler;
    ngx_uint_t                          chunk_size;
    ngx_uint_t                          out_queue;
    ngx_chain_t                        *in_free;
    ngx_chain_t                        *out[];
};

void ngx_websocket_read_handler(ngx_http_request_t *r);
void ngx_websocket_write_handler(ngx_http_request_t *r);

#include "ngx_http_set_header.h"

#endif
