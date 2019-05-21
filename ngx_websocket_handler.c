/*
 * @Author: pingox
 * @Copyright: pngox
 * @Github: https://github.com/pingox
 * @EMail: cczjp89@gmail.com
 */

#include "ngx_websocket.h"

static void
ngx_websocket_close_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    r->count--;

    if (r->count || r->blocked) {
        return;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_v2_close_stream(r->stream, rc);
        return;
    }
#endif

    ngx_http_free_request(r, rc);
    ngx_http_close_connection(c);
}

void
ngx_websocket_finalize_session(ngx_websocket_session_t *ws)
{
    if (!ws || !ws->r) {
        return;
    }

    ngx_websocket_close_request(ws->r, NGX_HTTP_OK);
}

static ngx_int_t
ngx_websocket_recv(ngx_http_request_t *r, ngx_err_t *err)
{
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_websocket_session_t   *ws;
    ngx_websocket_ctx_t       *ctx;
    ngx_websocket_frame_t     *f;
    ngx_websocket_header_t     h;
    ngx_buf_t                 *b;
    size_t                     old_size;
    u_char                    *p, *old_pos;
    uint64_t                   i;
    ngx_event_t               *rev;
    ngx_str_t                  msg;
    ngx_websocket_loc_conf_t  *wlcf;

    c = r->connection;
    b = NULL;
    old_pos = NULL;
    old_size = 0;
    rev = c->read;
    wlcf = ngx_http_get_module_loc_conf(r, ngx_websocket_module);

    ctx = ngx_http_get_module_ctx(r, ngx_websocket_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "websocket: recv| ctx is null");
        return NGX_ERROR;
    }

    ws = ctx->ws;
    f = &ws->in_frame;

    for (;;) {

        if (f->buf == NULL) {
            f->buf = ngx_create_temp_buf(ws->pool, wlcf->max_length);
        }
        b = f->buf;

        if (old_size) {
            b->pos = b->start;
            b->last = ngx_movemem(b->pos, old_pos, old_size);
        } else {
#if 1
            n = recv(c->fd, b->last, b->end - b->last, 0);
            if (n == 0) {
                rev->eof = 1;
                c->error = 1;
                *err = 0;

                return NGX_ERROR;

            } else if (n == -1) {
                *err = ngx_socket_errno;

                if (*err != NGX_EAGAIN) {
                    rev->eof = 1;
                    c->error = 1;
                    return NGX_ERROR;
                }

                return NGX_AGAIN;
            }

            /* aio does not call this handler */

            if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {

                if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                    ngx_websocket_close_request(r, 0);
                    return NGX_OK;
                }
            }
#else
            n = c->recv(c, b->last, b->end - b->last);

            if (n == NGX_ERROR || n == 0) {
                return NGX_ERROR;
            }

            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                    ngx_websocket_close_request(r, 0);
                    return NGX_OK;
                }
                return NGX_AGAIN;
            }

#endif
            b->last += n;
        }

        old_pos = NULL;
        old_size = 0;

        if (f->ph == NULL) {
            f->ph = b->pos;
            f->phl = NULL;
        }

        if (f->phl == NULL) {
            p = f->ph;
            h.fin = (*p) >> 7;
            if (h.fin == 0) {
                f->append = 1;
            }

            h.opcode = *p & 0x0f;
            if (f->opcode == 0) {
                f->opcode = h.opcode;
            }

            p++;
            if (b->last - p < 1) {
                continue;
            }

            h.mask = (*p) >> 7;
            h.payload_length = (*p) & 0x7f;
            p++;

            if (h.payload_length < 126) {
                f->len = h.payload_length;
            } else if (h.payload_length == 126) {
                if (b->last - p < 2) {
                    continue;
                }
                ngx_websocket_rmemcpy(&h.extended_playload_length16, p, 2);
                p += 2;
                f->len = h.extended_playload_length16;
            } else if (h.payload_length == 127) {
                if (b->last - p < 2) {
                    continue;
                }
                ngx_websocket_rmemcpy(&h.extended_playload_length64, p, 8);
                p += 8;
                f->len = h.extended_playload_length64;
            }

            if (h.mask) {
                if (b->last - p < 4) {
                    continue;
                }
                ngx_memcpy(h.masking_key, p, 4);
                //ngx_websocket_rmemcpy(h.masking_key, p, 4);
                p += 4;
            }
            f->phl = p;
        }

        p = f->phl;

        if (b->last == b->end && (uint64_t) (b->last - p) < f->len) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "websocket: recv| message is too large.");
            return NGX_HTTP_UNKNOWN;
        }

        if ((uint64_t)(b->last - p) < f->len) {
            return NGX_AGAIN;
        }

        for (i = 0; i < f->len; i++) {
            *p = h.masking_key[i%4] ^ *p;
            p++;
        }

        if (f->append) {
            ngx_memmove(f->ph, f->phl, f->len);
            f->mlen += f->len;
            b->last -= f->phl - f->ph;
            p -= f->phl - f->ph;
        } else {
            b->pos = f->phl;
        }

        if (h.fin == 1) {
            msg.data = b->pos;
            msg.len = p - b->pos;
            if (f->opcode ==  NGX_WEBSOCKET_OPCODE_CLOSE) {
                ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "websocket: recv| get close message.");
                return NGX_HTTP_UNKNOWN;
            } else if (f->opcode ==  NGX_WEBSOCKET_OPCODE_PING) {
                ngx_websocket_send_message(ws, NULL, NGX_WEBSOCKET_OPCODE_PONG);
            } else if (ws->recv_handler) {
                ws->last_recv = ngx_time();
                ws->recv_handler(ws, &msg, f->opcode);
            }

            if (b->last == p) {
                b->last = b->pos = b->start;
            } else {
                old_pos = p;
                old_size = b->last - p;
            }
            f->ph = NULL;
            f->phl = NULL;
            f->opcode = 0;
            f->append = 0;

            return NGX_OK;
        }

        // if fin == 0
        if (b->last > p) {
            f->ph = p;
            f->phl = NULL;
        }
    }

    return NGX_OK;
}

void
ngx_websocket_read_handler(ngx_http_request_t *r)
{
    ngx_err_t                  err;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    int                        rc;

    c = r->connection;
    rev = c->read;

#if (NGX_HTTP_V2)

    if (r->stream) {
        if (c->error) {
            err = 0;
            goto closed;
        }

        return;
    }

#endif


#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT && rev->pending_eof) {

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif



#if (NGX_HAVE_EPOLLRDHUP)

    if (((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) &&
        rev->pending_eof)
    {
        socklen_t  len;

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        goto closed;
    }

#endif

    rc = ngx_websocket_recv(r, &err);
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_DEBUG, c->log, err,
                  "websocket-recv: read_handler| recv return error");
        goto closed;
    } else if (rc == NGX_HTTP_UNKNOWN) {
        ngx_websocket_close_request(r, 0);
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    ngx_log_error(NGX_LOG_DEBUG, c->log, err,
        "websocket-recv: read_handler| client prematurely closed connection");

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}
