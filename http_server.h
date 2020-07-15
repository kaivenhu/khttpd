#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <net/sock.h>

struct http_connection {
    bool is_alive;
    struct task_struct *worker;
    struct socket *socket;
    struct list_head list;
};

struct http_server_param {
    struct socket *listen_socket;
};

extern int http_server_daemon(void *arg);

#endif
