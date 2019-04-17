/*
 * @Author: pingox
 * @Copyright: pngox
 * @Github: https://github.com/pingox
 * @EMail: cczjp89@gmail.com
 */

#ifndef _NGX_RTMP_HTTP_HEADER_OUT_H_INCLUDED_
#define _NGX_RTMP_HTTP_HEADER_OUT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_http.h>

ngx_int_t ngx_http_set_header_out(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *value);

ngx_str_t *ngx_http_get_header_in(ngx_http_request_t *r, ngx_str_t *key);

#endif
