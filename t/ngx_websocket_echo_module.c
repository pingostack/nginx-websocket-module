/*
 * @Author: pingox
 * @Copyright: pngox
 * @Github: https://github.com/pingox
 * @EMail: cczjp89@gmail.com
 */

#include "ngx_websocket.h"

static char *
ngx_websocket_echo_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void
ngx_websocket_connect_handler(ngx_websocket_session_t *ws);
static void
ngx_websocket_recv_handler(ngx_websocket_session_t *ws,
                            ngx_str_t *msg, u_char opcode);
static void
ngx_websocket_disconnect_handler(ngx_websocket_session_t *ws);

static ngx_http_module_t  ngx_websocket_echo_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


static ngx_command_t  ngx_websocket_echo_commands[] = {

    { ngx_string("websocket_echo"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_websocket_echo_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

ngx_module_t  ngx_websocket_echo_module = {
    NGX_MODULE_V1,
    &ngx_websocket_echo_module_ctx,        /* module context */
    ngx_websocket_echo_commands,           /* module directives */
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

static char *
ngx_websocket_echo_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_websocket_loc_conf_t   *wlcf;

    wlcf = ngx_http_conf_get_module_loc_conf(cf, ngx_websocket_module);
    wlcf->connect_handler = ngx_websocket_connect_handler;

    return NGX_CONF_OK;
}

static void
ngx_websocket_connect_handler(ngx_websocket_session_t *ws)
{
    ngx_log_error(NGX_LOG_DEBUG, ws->log, 0,
        "websocket-echo: connect_handler| new client connection.");

    ws->recv_handler = ngx_websocket_recv_handler;
    ws->disconnect_handler = ngx_websocket_disconnect_handler;
}

static void
ngx_websocket_recv_handler(ngx_websocket_session_t *ws,
                                ngx_str_t *msg, u_char opcode)
{
    switch (opcode) {
        case NGX_WEBSOCKET_OPCODE_TEXT:
        case NGX_WEBSOCKET_OPCODE_BINARY:
            ngx_log_error(NGX_LOG_DEBUG, ws->log, 0,
                "websocket-echo: recv_handler| recv: %V", msg);
            ngx_websocket_send_message(ws, msg, opcode);
        break;

        case NGX_WEBSOCKET_OPCODE_PONG:
            ngx_log_error(NGX_LOG_DEBUG, ws->log, 0,
                "websocket-echo: recv_handler| getting pong ...");
        break;

        default:
            ngx_log_error(NGX_LOG_WARN, ws->log, 0,
                "websocket-echo: recv_handler| drop message, opcode %d", opcode);
    }
}

static void
ngx_websocket_disconnect_handler(ngx_websocket_session_t *ws)
{
    ngx_log_error(NGX_LOG_DEBUG, ws->log, 0,
        "websocket-echo: disconnect_handler| client disconnect.");
}