#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"
#define REQUEST_FIB "fib"
#define RESPONSE_HELLO "Hello World!"
#define CONNECTION_CLOSE "Close"
#define CONNECTION_KEEP "Keep-Alive"

extern struct workqueue_struct *khttp_wq;

#ifdef DEBUG
#define debug(fmt, ...) pr_info(fmt, __VA_ARGS__)
#else /* DEBUG */
#define debug(fmt, ...) \
    do {                \
    } while (0)
#endif /* DEBUG */

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "%s" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "%s" CRLF
#define HTTP_RESPONSE_200_TEMP                                 \
    ""                                                         \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF      \
    "Content-Type: text/plain" CRLF "Content-Length: %lu" CRLF \
    "Connection: %s" CRLF CRLF "%s" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define RECV_BUFFER_SIZE 4096

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
};

static LIST_HEAD(connections);

static DEFINE_MUTEX(mutex_connection);
static atomic_t is_active = ATOMIC_INIT(0);

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static unsigned long long fib(unsigned int k)
{
    if (unlikely(!k))
        return 0;
    unsigned long long f_n = 1;
    unsigned long long f_n1 = 1;
    for (int i = (30 - __builtin_clz(k)); i >= 0; --i) {
        unsigned long long x = f_n * (2 * f_n1 - f_n);
        unsigned long long y = f_n * f_n + f_n1 * f_n1;

        if (k & (1 << i)) {
            f_n = y;
            f_n1 = x + y;
        } else {
            f_n = x;
            f_n1 = y;
        }
    }
    return f_n;
}

static void resp_req(const char *req, const char *conn, char *resp, size_t size)
{
    unsigned int idx = 0;
    char result[32] = {'\0'};
    if (!strstr(req, REQUEST_FIB) ||
        1 != sscanf(req, "/" REQUEST_FIB "/%u", &idx)) {
        snprintf(resp, size, HTTP_RESPONSE_200_TEMP, strlen(RESPONSE_HELLO),
                 conn, RESPONSE_HELLO);
        return;
    }
    snprintf(result, sizeof(result), "%llu", fib(idx));
    snprintf(resp, size, HTTP_RESPONSE_200_TEMP, strlen(result), conn, result);
    return;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    char response[256] = {'\0'};

    debug("requested_url = %s\n", request->request_url);
    if (request->method != HTTP_GET)
        snprintf(response, sizeof(response), "%s",
                 keep_alive ? HTTP_RESPONSE_501_KEEPALIVE : HTTP_RESPONSE_501);
    else
        resp_req(request->request_url,
                 keep_alive ? CONNECTION_KEEP : CONNECTION_CLOSE, response,
                 sizeof(response));
    http_server_send(request->socket, response, strlen(response));
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    size_t remain =
        (sizeof(request->request_url) - strlen(request->request_url) - 1);
    if (remain < len) {
        pr_err("Request url may truncate.\n");
        len = remain;
    }
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void remove_connection(struct http_connection *conn)
{
    mutex_lock(&mutex_connection);
    list_del(&conn->list);
    mutex_unlock(&mutex_connection);
    kfree(conn);
}

static void http_server_worker(struct work_struct *worker)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct http_connection *conn =
        container_of(worker, struct http_connection, worker);
    struct socket *socket = conn->socket;

    buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        goto end;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    while (atomic_read(&is_active)) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
    }
end:
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    debug("Remove connect %p!\n", conn);
    remove_connection(conn);
}

static int create_connection(struct socket *socket)
{
    struct http_connection *conn = (struct http_connection *) kzalloc(
        sizeof(struct http_connection), GFP_KERNEL);
    if (!conn) {
        pr_err("can't kalloc connection\n");
        return -1;
    }
    conn->socket = socket;
    mutex_lock(&mutex_connection);
    list_add_tail(&conn->list, &connections);
    mutex_unlock(&mutex_connection);
    INIT_WORK(&conn->worker, http_server_worker);
    debug("Add worker %p into connections\n", conn);
    queue_work(khttp_wq, &conn->worker);
    return 0;
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct http_server_param *param = (struct http_server_param *) arg;
    struct http_connection *conn = NULL, *tmp = NULL;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);
    atomic_set(&is_active, 1);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }
        if (0 != create_connection(socket)) {
            pr_err("Failed to create connection\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }
    }
    atomic_set(&is_active, 0);

    mutex_lock(&mutex_connection);
    list_for_each_entry_safe (conn, tmp, &connections, list) {
        kernel_sock_shutdown(conn->socket, SHUT_RDWR);
    }
    mutex_unlock(&mutex_connection);
    flush_workqueue(khttp_wq);

    return 0;
}
