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
    { ngx_string("WebSocket-Server"),   ngx_string("pingox") },
    { ngx_null_string, ngx_null_string }
};

enum ExtensionTokens {
    TOK_PERMESSAGE_DEFLATE = 1838,
    TOK_SERVER_NO_CONTEXT_TAKEOVER = 2807,
    TOK_CLIENT_NO_CONTEXT_TAKEOVER = 2783,
    TOK_SERVER_MAX_WINDOW_BITS = 2372,
    TOK_CLIENT_MAX_WINDOW_BITS = 2348
};

static void *
ngx_websocket_create_loc_conf(ngx_conf_t *cf);
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
    NULL                                   /* merge location configuration */
};


static ngx_command_t  ngx_websocket_commands[] = {

    { ngx_string("websocket"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
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

    return wlcf;
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
    ngx_int_t                           rc;
    ngx_keyval_t                       *h;
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
}

/*
static void
ngx_websocket_upgrade(ngx_str_t *key, ngx_str_t *extensions,
                    ngx_str_t *subprotocol, bool *perMessageDeflate)
{

}
*/

static ngx_int_t
ngx_websocket_handshark(ngx_http_request_t *r)
{
    u_char              sha_digest[SHA_DIGEST_LENGTH] = { 0 };
    ngx_str_t          *upgrade;
    ngx_str_t          *ws_version;
    ngx_str_t          *ws_key;
    //ngx_str_t        *ws_extensions;
    ngx_str_t           ws_accept, digest;
    ngx_int_t           ret;
    ngx_int_t           v;

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
