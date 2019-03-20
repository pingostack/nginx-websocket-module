/*
 * @Description: 
 * @Author: pingox
 * @Copyright: pngox
 * @Github: https://github.com/pingox
 * @EMail: cczjp89@gmail.com
 * @LastEditors: pingox
 * @Date: 2019-01-29 22:05:26
 * @LastEditTime: 2019-03-16 18:03:55
 */
#include "ngx_websocket.h"

static u_char SHA_INPUT[] = "XXXXXXXXXXXXXXXXXXXXXXXX258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static ngx_str_t HEADER_UPGRAGE = ngx_string("Upgrade");
static ngx_str_t HEADER_WS_KEY = ngx_string("Sec-WebSocket-Key");
static ngx_str_t HEADER_WS_VERSION = ngx_string("Sec-WebSocket-Version");
//static ngx_str_t HEADER_WS_EXTENSIONS = ngx_string("Sec-WebSocket-Extensions");

typedef struct ngx_websocket_ctx_s ngx_websocket_ctx_t;

static ngx_keyval_t ngx_websocket_headers[] = {
    { ngx_string("Upgrade"),   ngx_string("websocket") },
    { ngx_string("Sec-WebSocket-Version"),    ngx_string("13") },
    { ngx_string("Sec-WebSocket-Accept"),     ngx_null_string },
    { ngx_string("Sec-WebSocket-Protocol:"),  ngx_null_string },
    { ngx_string("Sec-WebSocket-Extensions"), ngx_null_string },
    { ngx_string("WebSocket-Server"),   ngx_string("pingox") },
    { ngx_null_string, ngx_null_string }
};

struct ngx_websocket_ctx_s {
    ngx_websocket_session_t    *ws;
};

static void *
ngx_websocket_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_websocket_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *
ngx_websocket_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_websocket_handler(ngx_http_request_t *r);

static ngx_http_module_t  ngx_websocket_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_websocket_create_loc_conf,         /* create location configuration */
    ngx_websocket_merge_loc_conf           /* merge location configuration */
};


static ngx_command_t  ngx_websocket_commands[] = {

    { ngx_string("websocket"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_websocket_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("websocket_chunk"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_websocket_loc_conf_t, chunk_size),
      NULL },

    { ngx_string("websocket_out_queue"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_websocket_loc_conf_t, out_queue),
      NULL },

    ngx_null_command
};

ngx_module_t  ngx_websocket_module = {
    NGX_MODULE_V1,
    &ngx_websocket_module_ctx,             /* module context */
    ngx_websocket_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_websocket_create_loc_conf(ngx_conf_t *cf)
{
    ngx_websocket_loc_conf_t       *wlcf;

    wlcf = ngx_pcalloc(cf->pool, sizeof(ngx_websocket_loc_conf_t));
    if (wlcf == NULL) {
        return NULL;
    }
    wlcf->chunk_size = NGX_CONF_UNSET;
    wlcf->out_queue = NGX_CONF_UNSET;

    return wlcf;
}

static char *
ngx_websocket_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_websocket_loc_conf_t *prev = parent;
    ngx_websocket_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->chunk_size, prev->chunk_size, 1024);
    ngx_conf_merge_uint_value(conf->out_queue, prev->out_queue, 512);

    return NGX_CONF_OK;
}

static char *
ngx_websocket_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t           *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_websocket_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_websocket_send_header(ngx_http_request_t *r)
{
    ngx_int_t           rc;
    ngx_keyval_t       *h;
    static ngx_str_t    http_status = ngx_string("101 Switching Protocols");

    r->headers_out.status_line = http_status;
    r->headers_out.status = NGX_HTTP_SWITCHING_PROTOCOLS;
    r->keepalive = 1;

    h = ngx_websocket_headers;
    for (; h->key.len; ++h) {
        if (!h->value.data || !h->value.len) {
            continue;
        }

        rc = ngx_http_set_header_out(r, &h->key, &h->value);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return ngx_http_send_header(r);
}


static void
ngx_websocket_cleanup(void *data)
{
    ngx_http_request_t         *r;
    ngx_websocket_session_t    *ws;
    ngx_websocket_ctx_t        *ctx;

    r = data;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "websocket: cleanup| disconnect");

    ctx = ngx_http_get_module_ctx(r, ngx_websocket_module);
    if (!ctx) {
        return;
    }

    ws = ctx->ws;
    if (ws && ws->disconnect_handler) {
        ws->disconnect_handler(ws);
    }
}

/*
static void
ngx_websocket_upgrade(ngx_str_t *key, ngx_str_t *extensions,
                    ngx_str_t *subprotocol, bool *perMessageDeflate)
{

}
*/

static ngx_websocket_session_t *
ngx_websocket_init_session(ngx_http_request_t *r)
{
    ngx_websocket_session_t    *ws;
    ngx_websocket_ctx_t        *ctx;
    ngx_pool_t                 *pool;
    ngx_websocket_loc_conf_t   *wlcf;

    wlcf = ngx_http_get_module_loc_conf(r, ngx_websocket_module);
    ctx = ngx_http_get_module_ctx(r, ngx_websocket_module);
    if (ctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "websocket: init_session| websocket session has been inited");
        return NULL;
    }
    ctx = ngx_pcalloc(r->connection->pool, sizeof(ngx_websocket_ctx_t));
    if (!ctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "websocket: init_session| pcalloc ctx failed");
        return NULL;
    }

    ws = ngx_pcalloc(r->connection->pool,
        sizeof(ngx_websocket_session_t) + ngx_http_max_module * sizeof(void *));
    if (!ws) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "websocket: init_session| pcalloc websocket session failed");
        return NULL;
    }

    ws->r = r;
    ctx->ws = ws;

    pool = r->connection->pool;
    ws->pool = pool;
    ws->log = r->connection->log;
    ws->chunk_size = wlcf->chunk_size;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "websocket: init_session| init websocket session");

    return ws;
}

static ngx_int_t
ngx_websocket_handshark(ngx_http_request_t *r)
{
    u_char                     sha_digest[SHA_DIGEST_LENGTH] = { 0 };
    ngx_str_t                 *upgrade;
    ngx_str_t                 *ws_version;
    ngx_str_t                 *ws_key;
    //ngx_str_t                 *ws_extensions;
    ngx_str_t                  ws_accept, digest;
    ngx_int_t                  ret;
    ngx_int_t                  v;
    ngx_websocket_loc_conf_t  *wlcf;
    ngx_websocket_session_t   *ws;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    upgrade = ngx_http_get_header_in(r, &HEADER_UPGRAGE);
    ws_key = ngx_http_get_header_in(r, &HEADER_WS_KEY);
    ws_version = ngx_http_get_header_in(r, &HEADER_WS_VERSION);
//    ws_extensions = ngx_http_get_header_in(r, &HEADER_WS_EXTENSIONS);

    v = ngx_atoi(ws_version->data, ws_version->len);

    if (v != 13 || !upgrade || !ws_key) {
        return NGX_DECLINED;
    }

    ws = ngx_websocket_init_session(r);
    if (!ws) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "websocket: handshark| init session failed");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    wlcf = ngx_http_get_module_loc_conf(r, ngx_websocket_module);
    if (wlcf->connect_handler) {
        wlcf->connect_handler(ws);
    }

    ngx_memcpy(SHA_INPUT, ws_key->data, ws_key->len);
    SHA1(SHA_INPUT, sizeof(SHA_INPUT) - 1, sha_digest);

    digest.data = sha_digest;
    digest.len = sizeof(sha_digest);

    ws_accept.data = ngx_pcalloc(r->connection->pool, 28);
    ngx_encode_base64(&ws_accept, &digest);

    ngx_websocket_headers[2].value = ws_accept;

    ret = ngx_websocket_send_header(r);
    if (ret != NGX_OK) {
        return ret;
    }

    ngx_http_send_special(r, NGX_HTTP_FLUSH);

    return NGX_OK;
}

static ngx_int_t
ngx_websocket_handler(ngx_http_request_t *r)
{
    ngx_http_cleanup_t   *cln;
    ngx_int_t             ret;

    ret = ngx_websocket_handshark(r);
    if (ret != NGX_OK) {
        return ret;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_websocket_cleanup;
    cln->data = r;

    r->read_event_handler = ngx_websocket_read_handler;
    r->write_event_handler = ngx_websocket_write_handler;
    r->count++;

    return NGX_DONE;
}
