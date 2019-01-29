#include "ngx_websocket.h"

void
ngx_websocket_write_handler(ngx_http_request_t *r)
{
    ngx_event_t                        *wev;
    ngx_int_t                           rc = NGX_OK;

    wev = r->connection->write;

    if (r->connection->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, NGX_ETIMEDOUT,
                "websocket: write_handler| client timed out");
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

    if (r->connection->buffered) {
        rc = ngx_http_output_filter(r, NULL);
    } else {
//            rc = ngx_http_output_filter(r, s->out_chain);
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(wev, 10);
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

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }
}