# NGINX-based Websocket Server

## nginx-websocket-module

### Project blog

[http://www.ping8.online/](http://www.ping8.online/)

* wss client
![client-wss](./README/client-wss.jpg)

* nginx-websocket-module supports wss protocol
![nginx-wss](./README/nginx-wss.jpg)

## Code sample

**If you want to know how to develop a websocket server, refer to the code in the ['nginx-websocket-module/t/ngx_websocket_echo_module.c'](https://github.com/pingox/nginx-websocket-module/blob/dev/t/ngx_websocket_echo_module.c) .**

## Build

```shell

$ git clone https://github.com/nginx/nginx.git

$ git clone https://github.com/pingox/nginx-websocket-module.git

$ cd nginx

$ ./auto/configure --add-module=../nginx-websocket-module --add-module=../nginx-websocket-module/t

$ sudo make && make install

```

## Config file

### websocket

* *syntax* : websocket [no args]

* *context*: location

**The switch of websocket service has no args**

```nginx

websocket;

```

### websocket_out_queue

* *syntax*: websocket_out_queue [num] (default 512)
* *context*: location

**Number of out queue**

```nginx

websocket_out_queue 512;

```

### websocket_message_length

* *syntax*: websocket_message_length [num] (default 4096000 bytes)
* *context*: location

**Max length of websocket message**

```nginx

websocket_message_length 4096000;

```

### websocket_ping_interval

* *syntax*: websocket_ping_interval [msec] (default 5000ms)
* *context*: location

**Time interval between pings**

```nginx

websocket_ping_interval 5000ms;

```

### websocket_echo

* *syntax*: websocket_echo [no args]
* *context*: location

**The server responses the data it received**

```nginx

websocket_echo;

```

### Example nginx.conf

```nginx

daemon on;
master_process on;
#user  nobody;
worker_processes  1;

error_log  logs/error.log  info;

pid        logs/nginx.pid;
events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       80;

        # use wss(ssl)
        listen       443 ssl;
        ssl_certificate /usr/local/nginx/key/pingox.crt;
        ssl_certificate_key /usr/local/nginx/key/pingox.key;

        server_name  localhost;

        location /pingox {
            websocket;
            websocket_out_queue 512;
            websocket_message_length 4096000;
            websocket_ping_interval 5000ms;
            websocket_echo;
        }
    }
}

```