/*
 * @Author: pingox
 * @Copyright: pngox
 * @Github: https://github.com/pingox
 * @EMail: cczjp89@gmail.com
 */

#include "ngx_websocket.h"

static u_char SHA_INPUT[] = "XXXXXXXXXXXXXXXXXXXXXXXX258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static ngx_str_t HEADER_UPGRAGE = ngx_string("Upgrade");
static ngx_str_t HEADER_WS_KEY = ngx_string("Sec-WebSocket-Key");
static ngx_str_t HEADER_WS_VERSION = ngx_string("Sec-WebSocket-Version");
//static ngx_str_t HEADER_WS_EXTENSIONS = ngx_string("Sec-WebSocket-Extensions");

static ngx_keyval_t ngx_websocket_headers[] = {
    { ngx_string("Upgrade"),   ngx_string("websocket") },
    { ngx_string("Sec-WebSocket-Version"),    ngx_string("13") },
    { ngx_string("Sec-WebSocket-Accept"),     ngx_null_string },
    { ngx_string("Sec-WebSocket-Protocol:"),  ngx_null_string },
    { ngx_string("Sec-WebSocket-Extensions"), ngx_null_string },
    { ngx_string("WebSocket-Server"),   ngx_string("pingox-websocket") },
    { ngx_null_string, ngx_null_string }
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
      NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_websocket_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
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
    wlcf->out_queue = NGX_CONF_UNSET;
    wlcf->max_length = NGX_CONF_UNSET;
    wlcf->ping_interval = NGX_CONF_UNSET_MSEC;
    wlcf->timeout = NGX_CONF_UNSET_MSEC;
    wlcf->pool = ngx_create_pool(1024, cf->log);

    return wlcf;
}

static char *
ngx_websocket_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_websocket_loc_conf_t *prev = parent;
    ngx_websocket_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->out_queue, prev->out_queue, 512);
    ngx_conf_merge_uint_value(conf->max_length, prev->max_length, 4096000);
    ngx_conf_merge_msec_value(conf->ping_interval, prev->ping_interval, 5000);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout,
                              conf->ping_interval * 3);

    return NGX_CONF_OK;
}

static char *
ngx_websocket_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t   *clcf;
    ngx_uint_t                  i;
    ngx_str_t                  *args, v;
    ngx_websocket_loc_conf_t   *wlcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_websocket_handler;

    wlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_websocket_module);
    if (wlcf == NULL) {
        return "websocket module loc conf is null";
    }

    wlcf->name = clcf->name;

    args = cf->args->elts;
    for (i = 1; i < cf->args->nelts; ++i) {
        if (ngx_strncmp(args[i].data, "out_queue=", 10) == 0) {
            v.data = args[i].data + 10;
            v.len = args[i].len - 10;
            wlcf->out_queue = ngx_atoi(v.data, v.len);

        } else if (ngx_strncmp(args[i].data, "message_length=", 15) == 0) {
            v.data = args[i].data + 15;
            v.len = args[i].len - 15;
            wlcf->max_length = ngx_atoi(v.data, v.len);

        } else if (ngx_strncmp(args[i].data, "ping_interval=", 14) == 0) {
            v.data = args[i].data + 14;
            v.len = args[i].len - 14;
            wlcf->ping_interval = ngx_parse_time(&v, 0);
            if (wlcf->ping_interval == (ngx_msec_t) NGX_ERROR) {
                return "invalid value";
            }
        } else if (ngx_strncmp(args[i].data, "timeout=", 8) == 0) {
            v.data = args[i].data + 8;
            v.len = args[i].len - 8;
            wlcf->timeout = ngx_parse_time(&v, 0);
            if (wlcf->timeout == (ngx_msec_t) NGX_ERROR) {
                return "invalid value";
            }
        } else {
            return "invalid option";
        }
    }

    return NGX_CONF_OK;
}

static void
ngx_websocket_ping(ngx_event_t *ev)
{
    ngx_websocket_session_t   *ws;

    ws = ev->data;
    if ((1000 * (ngx_time() - ws->last_recv)) >= ws->timeout) {
        ngx_websocket_finalize_session(ws);
        return;
    }

    ngx_websocket_send_message(ws, NULL, NGX_WEBSOCKET_OPCODE_PING);

    ngx_add_timer(ev, ws->ping_interval);
}

static ngx_websocket_session_t *
ngx_websocket_init_session(ngx_http_request_t *r)
{
    ngx_websocket_session_t    *ws;
    ngx_websocket_ctx_t        *ctx;
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

    ws->out = ngx_pcalloc(r->connection->pool,
                sizeof(ngx_chain_t *) * wlcf->out_queue);

    ws->r = r;
    ctx->ws = ws;

    ws->pool = ngx_create_pool(4096, r->connection->log);
    ws->log = r->connection->log;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "websocket: init_session| init websocket session");

    ngx_http_set_ctx(r, ctx, ngx_websocket_module);
    ws->out_queue = wlcf->out_queue;
    ws->ping_interval = wlcf->ping_interval;
    ws->timeout = wlcf->timeout;
    ws->last_recv = ngx_time();

    ws->ping_evt.handler = ngx_websocket_ping;
    ws->ping_evt.log = ws->log;
    ws->ping_evt.data = ws;
    ngx_add_timer(&ws->ping_evt, ws->ping_interval);

    return ws;
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
    if (ws->ping_evt.timer_set) {
        ngx_del_timer(&ws->ping_evt);
    }
    if (ws && ws->disconnect_handler) {
        ws->disconnect_handler(ws);
    }
}

static void
ngx_websocket_free_chain(ngx_websocket_session_t *ws, ngx_chain_t *cl) {
    ngx_http_request_t         *r;
    ngx_websocket_loc_conf_t   *wlcf;

    r = ws->r;
    wlcf = ngx_http_get_module_loc_conf(r, ngx_websocket_module);
    cl->next = wlcf->in_free;
    wlcf->in_free = cl;
}

static ngx_chain_t *
ngx_websocket_prepare_chain(ngx_websocket_session_t *ws,
                            ngx_str_t *msg, u_char opcode)
{
    ngx_http_request_t         *r;
    ngx_websocket_loc_conf_t   *wlcf;
    ngx_chain_t                *out;
    ngx_buf_t                  *b;
    u_char                     *p;

    r = ws->r;
    wlcf = ngx_http_get_module_loc_conf(r, ngx_websocket_module);

    if (msg && (msg->len > wlcf->max_length)) {
        ngx_log_error(NGX_LOG_ERR, ws->log, 0, "websocket: prepare_chain| "
            "max message length is %d", wlcf->max_length);
        return NULL;
    }

    if (wlcf->in_free) {
        out = wlcf->in_free;
        wlcf->in_free = wlcf->in_free->next;
        out->buf->last = out->buf->pos = out->buf->start;
        out->next = NULL;
        b = out->buf;
        ngx_memzero(b->start, wlcf->max_length);
    } else {
        b = ngx_create_temp_buf(wlcf->pool, wlcf->max_length);
        out = ngx_pcalloc(wlcf->pool, sizeof(ngx_chain_t));
        out->buf = b;
        out->next = NULL;
    }

    b->last_in_chain = 1;
    b->flush = 1;

    p = b->last;
    *p++ = 0x80 | opcode;    // fin + opcode

    if (!msg) {
        *p++ = 0;
        b->last = p;
    } else {
        if (msg->len < 126) {
            *p++ = msg->len;
        } else if (msg->len >= 126 && msg->len <= 0xffff) {
            *p++ = 126;
            *p++ = (msg->len & 0xff00) >> 8;
            *p++ = msg->len & 0x00ff;
        } else if (msg->len > 0xffff) {
            *p++ = 127;
            *p++ = (msg->len & 0xff000000) >> 24;
            *p++ = (msg->len & 0x00ff0000) >> 16;
            *p++ = (msg->len & 0x0000ff00) >> 8;
            *p++ = (msg->len & 0x000000ff);
        }

        b->last = ngx_cpymem(p, msg->data, msg->len);
    }

    return out;
}

void
ngx_websocket_write_handler(ngx_http_request_t *r)
{
    ngx_websocket_ctx_t       *ctx;
    ngx_websocket_session_t   *ws;
    ngx_event_t               *wev;
    ngx_int_t                  rc;

    wev = r->connection->write;

    if (r->connection->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, NGX_ETIMEDOUT,
                "websocket| write_handler| client timed out");
        r->connection->timedout = 1;
        if (r->header_sent) {
            ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
            ngx_http_run_posted_requests(r->connection);
        } else {
            r->error_page = 1;
            ngx_http_finalize_request(r, NGX_HTTP_SERVICE_UNAVAILABLE);
        }

        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_websocket_module);
    ws = ctx->ws;

    if (ws->out_chain == NULL && ws->out_pos != ws->out_last) {
        ws->out_chain = ws->out[ws->out_pos];
    }

    while (ws->out_chain) {

        if (r->connection->buffered) {
            rc = ngx_http_output_filter(r, NULL);
        } else {
            rc = ngx_http_output_filter(r, ws->out_chain);
        }

        if (rc == NGX_AGAIN) {
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "websocket: write_handler| handle write event failed");
                ngx_http_finalize_request(r, NGX_ERROR);
            }
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "websocket: write_handler| send error");
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        /* NGX_OK */

        ngx_websocket_free_chain(ws, ws->out[ws->out_pos]);
        ++ws->out_pos;
        ws->out_pos %= ws->out_queue;
        if (ws->out_pos == ws->out_last) {
            ws->out_chain = NULL;
            break;
        }

        ws->out_chain = ws->out[ws->out_pos];
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }
}

ngx_int_t
ngx_websocket_send_message(ngx_websocket_session_t *ws,
                            ngx_str_t *str, ngx_int_t opcode)
{
    ngx_uint_t             nmsg;
    ngx_http_request_t    *r;
    ngx_websocket_ctx_t   *ctx;
    ngx_chain_t           *out;

    r = ws->r;

    ctx = ngx_http_get_module_ctx(r, ngx_websocket_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "websocket: send| websocket ctx is null");
        return NGX_ERROR;
    }

    out = ngx_websocket_prepare_chain(ws, str, opcode);
    if (out == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "websocket: send| prepare chain failed.");
        return NGX_ERROR;
    }

    nmsg = (ws->out_last - ws->out_pos) % ws->out_queue + 1;

    if (nmsg >= ws->out_queue) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "websocket: send_message| drop message bufs=%ui", nmsg);
        return NGX_AGAIN;
    }

    ws->out[ws->out_last++] = out;
    ws->out_last %= ws->out_queue;

    if (!r->connection->write->active) {
        ngx_websocket_write_handler(r);
        ngx_http_run_posted_requests(r->connection);
    }

    return NGX_OK;
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
