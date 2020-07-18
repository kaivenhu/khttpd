#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include <net/sock.h>

#include "http_server.h"

#define MODULE_NAME "khttp"

#define DEFAULT_PORT 8081
#define DEFAULT_BACKLOG 100

static ushort port = DEFAULT_PORT;
module_param(port, ushort, S_IRUGO);
static ushort backlog = DEFAULT_BACKLOG;
module_param(backlog, ushort, S_IRUGO);

static struct socket *listen_socket = NULL;
static struct http_server_param param;
static struct task_struct *http_server = NULL;

struct workqueue_struct *khttp_wq = NULL;

static inline int setsockopt(struct socket *sock,
                             int level,
                             int optname,
                             int optval)
{
    int opt = optval;
    return kernel_setsockopt(sock, level, optname, (char *) &opt, sizeof(opt));
}

static int open_listen_socket(ushort port, ushort backlog, struct socket **res)
{
    struct socket *sock;
    struct sockaddr_in s;

    int err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (err < 0) {
        pr_err("sock_create() failure, err=%d\n", err);
        return err;
    }

    err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    if (err < 0)
        goto bail_setsockopt;

    err = setsockopt(sock, SOL_TCP, TCP_NODELAY, 1);
    if (err < 0)
        goto bail_setsockopt;

    err = setsockopt(sock, SOL_TCP, TCP_CORK, 0);
    if (err < 0)
        goto bail_setsockopt;

    err = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, 1024 * 1024);
    if (err < 0)
        goto bail_setsockopt;

    err = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, 1024 * 1024);
    if (err < 0)
        goto bail_setsockopt;

    memset(&s, 0, sizeof(s));
    s.sin_family = AF_INET;
    s.sin_addr.s_addr = htonl(INADDR_ANY);
    s.sin_port = htons(port);
    err = kernel_bind(sock, (struct sockaddr *) &s, sizeof(s));
    if (err < 0) {
        pr_err("kernel_bind() failure, err=%d\n", err);
        goto bail_sock;
    }

    err = kernel_listen(sock, backlog);
    if (err < 0) {
        pr_err("kernel_listen() failure, err=%d\n", err);
        goto bail_sock;
    }
    *res = sock;
    return 0;

bail_setsockopt:
    pr_err("kernel_setsockopt() failure, err=%d\n", err);
bail_sock:
    sock_release(sock);
    return err;
}

static void close_listen_socket(struct socket *socket)
{
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
}

static void cleanup(void)
{
    if (http_server) {
        send_sig(SIGTERM, http_server, 1);
        kthread_stop(http_server);
    }
    if (listen_socket) {
        close_listen_socket(listen_socket);
    }
    if (khttp_wq) {
        destroy_workqueue(khttp_wq);
    }
}

static int __init khttpd_init(void)
{
    int err = open_listen_socket(port, backlog, &listen_socket);
    if (err < 0) {
        pr_err("can't open listen socket\n");
        goto err;
    }
    khttp_wq = alloc_workqueue(MODULE_NAME, 0, 0);
    if (NULL == khttp_wq) {
        pr_err("can't allocate workqueue\n");
        err = -1;
        goto err;
    }
    param.listen_socket = listen_socket;
    http_server = kthread_run(http_server_daemon, &param, KBUILD_MODNAME);
    if (IS_ERR(http_server)) {
        pr_err("can't start http server daemon\n");
        err = PTR_ERR(http_server);
        goto err;
    }
    return 0;

err:
    cleanup();
    return err;
}

static void __exit khttpd_exit(void)
{
    cleanup();
    pr_info("module unloaded\n");
}

module_init(khttpd_init);
module_exit(khttpd_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("in-kernel HTTP daemon");
MODULE_VERSION("0.1");
