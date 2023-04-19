# Nginx Test
## Browser-based Integration Test for Nginx Websocket

This test exercises the websocket logic using the websocket client implementation native to modern browsers.
In the test, we start an instance of Nginx with the websocket echo module loaded, then navigate using any
modern browser to a web page containing javascript code that connects to that websocket and validates
correct operation

### Quick Start for Linux using Bash shell
Since there are many ways that the websocket modules could be compiled, this is less quick that we'd like.
* Create a working directory - replace ${MY_HOME_OR_LOCAL_SCRATCH} with an appropriate directory:
> cd ${MY_HOME_OR_LOCAL_SCRATCH}<br>
> mkdir nginx_temp<br>
> cd nginx_temp
* Copy test files into working directory
> cp ${PATH_TO_NGINX_WEBSOCKET_GIT_REPO}/nginx-test/* .
* Symlink websocket modules into working directory (you could also copy, but symlinks mean you pick up changes following fixes)
> ln -s ${PATH_TO_BUILD_OUTPUT}/ngx_websocket_echo_module.so .<br>
> ln -s ${PATH_TO_BUILD_OUTPUT}/ngx_websocket_module.so .
* Run Nginx
> ${PATH_TO_NGINX}/nginx -p $(pwd) -c websocket_test.conf
* If the execution fails because of missing shared object dependencies (e.g. zlib, pcre, openssl), add paths to these dependencies to LD_LIBRARY_PATH and rerun.

### Run the test
* New open a browser and enter the URL of the test HTML page. For a browser running on the same host as Nginx
> http://localhost:8220/test_websocket.html
* If accessing remotely then replace localhost with the name of the host where Nginx is running.
* The output of the test is shown in the browser. Scroll down if necessary to confirm that all tests are green.
