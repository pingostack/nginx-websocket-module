/*
 * @Author: pingox
 * @Copyright: pngox
 * @Github: https://github.com/pingox
 * @EMail: cczjp89@gmail.com
 */

#include "ngx_websocket.h"

void *
ngx_websocket_rmemcpy(void *dst, const void* src, size_t n)
{
    u_char     *d, *s;

    d = dst;
    s = (u_char*)src + n - 1;

    while(s >= (u_char*)src) {
        *d++ = *s--;
    }

    return dst;
}
