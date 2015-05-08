/**
 * @file rpc.c
 * Used for RPC by Apteryx.
 *
 * Copyright 2014, Allied Telesis Labs New Zealand, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>
 */
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <semaphore.h>
#include <pthread.h>
#include <poll.h>
#include "internal.h"

#undef DEBUG
#define DEBUG(fmt, args...)

typedef struct rpc_socket_t
{
    const char *id;
    const char *url;
    union
    {
        struct sockaddr_in addr_in;
        struct sockaddr_in6 addr_in6;
        struct sockaddr_un addr_un;
    } address;
    socklen_t address_len;
    int family;
    int fd;
} rpc_socket_t;

typedef struct rpc_server_t
{
    bool running;
    ProtobufCService *service;
    pthread_mutex_t lock;
    GList *pending;
    GList *working;
    int wake_server[2];
    sem_t wake_workers;
    int num_workers;
    pthread_t *workers;
    GList *sockets;
} rpc_server_t;
__thread rpc_server_t *tl_server = NULL;

typedef struct rpc_client_t
{
    ProtobufCService service;
    int fd;
    int request_id;
    pthread_mutex_t lock;
} rpc_client_t;

typedef struct _rpc_connection_t
{
    int fd;
    rpc_server_t *server;
    ProtobufCBufferSimple incoming;
    ProtobufCBufferSimple outgoing;
} rpc_connection_t;

/* Message header */
#define RPC_HEADER_LENGTH (3 * sizeof (uint32_t))
typedef struct rpc_message_t
{
    rpc_connection_t *connection;
    uint32_t method_index;
    uint32_t request_id;
    uint32_t message_length;
} rpc_message_t;
static inline void unpack_header (unsigned char *b, rpc_message_t *h)
{
    h->method_index = (ltoh32 (((uint32_t*)b)[0]));
    h->message_length = (ltoh32 (((uint32_t*)b)[1]));
    h->request_id = (ltoh32 (((uint32_t*)b)[2]));
}
static inline void pack_header (rpc_message_t *h, unsigned char *b)
{
    ((uint32_t*)b)[0] = htol32(h->method_index);
    ((uint32_t*)b)[1] = htol32(h->message_length);
    ((uint32_t*)b)[2] = htol32(h->request_id);
}

typedef int (*fd_callback) (int fd, void *data);
typedef struct _callback_t
{
    int fd;
    fd_callback func;
    void *data;
} callback_t;

static void
add_cb (GList **list, int fd, fd_callback func, void *data)
{
    callback_t *cb = malloc (sizeof (callback_t));
    cb->fd = fd;
    cb->func = func;
    cb->data = data;
    *list = g_list_append (*list, cb);
}

static void
delete_cb (GList **list, int fd)
{
    GList *iter;
    callback_t *cb = NULL;
    for (iter = *list; iter; iter = iter->next)
    {
        cb = (callback_t *)iter->data;
        if (cb->fd == fd)
            break;
        cb = NULL;
    }
    if (cb)
    {
        *list = g_list_remove (*list, cb);
        free (cb);
    }
}

static void
server_connection_response_closure (const ProtobufCMessage *message,
        void *closure_data)
{
    rpc_message_t *msg = (rpc_message_t *)closure_data;
    rpc_connection_t *conn = msg->connection;
    ProtobufCBufferSimple *buffer = &conn->outgoing;
    uint8_t buf[sizeof(uint32_t)+RPC_HEADER_LENGTH] = {0}; //TEMP - stupid status

    DEBUG ("RPC[%d]: Closure\n", conn->fd);

    msg->message_length = protobuf_c_message_get_packed_size (message);
    pack_header (msg, &buf[4]);
    buffer->base.append ((ProtobufCBuffer *)buffer, sizeof(uint32_t)+RPC_HEADER_LENGTH, buf);
    if (protobuf_c_message_pack_to_buffer (message, (ProtobufCBuffer *)buffer)
            != msg->message_length)
    {
        ERROR ("RPC[%d]: error serializing the response\n", conn->fd);
        return;
    }

    uint8_t *data = buffer->data;
    while (buffer->len > 0)
    {
        int rv = send (conn->fd, data, buffer->len, MSG_NOSIGNAL);
        if (rv == 0)
        {
            DEBUG ("RPC[%d]: connection closed\n", conn->fd);
            return;
        }
        else if (rv < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            DEBUG ("RPC[%d]: send() failed: %s\n", conn->fd, strerror (errno));
            return;
        }
        DEBUG ("RPC[%d]: Wrote %d of %zd bytes\n", conn->fd, rv, buffer->len);
        buffer->len -= rv;
    }
    return;
}

static int
conn_callback (int fd, void *data)
{
    rpc_connection_t *conn = (rpc_connection_t *)data;
    rpc_server_t *server = conn->server;
    ProtobufCService *service = server->service;
    ProtobufCBufferSimple *buffer = &conn->incoming;
    unsigned char buf[8192];
    int rv;

    rv = read (fd, buf, sizeof (buf));
    if (rv == 0)
    {
        DEBUG ("RPC[%d]: connection closed\n", fd);
        goto error;
    }
    else if (rv < 0)
    {
        if (errno == EINTR || errno == EAGAIN)
            return 0;
        ERROR ("RPC[%d]: read() failed: %s\n", fd, strerror (errno));
        goto error;
    }

    DEBUG ("RPC[%d]: read %d bytes (%zu total)\n", fd, rv, buffer->len + rv);

    buffer->base.append ((ProtobufCBuffer*)buffer, rv, buf);
    while (buffer->len > 0)
    {
        const ProtobufCMessageDescriptor *desc = NULL;
        ProtobufCMessage *message;
        rpc_message_t msg;

        msg.connection = conn;
        unpack_header (buffer->data, &msg);
        if (buffer->len < RPC_HEADER_LENGTH ||
            buffer->len < (RPC_HEADER_LENGTH + msg.message_length))
        {
            DEBUG ("RPC: More data\n");
            break;
        }

        DEBUG ("RPC: ID=%d Method=%d Length=%d\n",
                msg.request_id, msg.method_index, msg.message_length);

        if (msg.method_index >= service->descriptor->n_methods)
        {
            ERROR ("RPC: bad method_index %u\n", msg.method_index);
            goto error;
        }
        desc = service->descriptor->methods[msg.method_index].input;
        message = protobuf_c_message_unpack (desc, NULL, msg.message_length,
                (const uint8_t *)buffer->data + RPC_HEADER_LENGTH);
        if (message == NULL)
        {
            ERROR ("RPC: unable to unpack message (%d)\n", msg.method_index);
            goto error;
        }

        buffer->len -= RPC_HEADER_LENGTH + msg.message_length;
        if (buffer->len)
            memcpy (buffer->data, buffer->data + RPC_HEADER_LENGTH +
                    msg.message_length, buffer->len);

        /* Invoke service (note that it may call back immediately) */
        service->invoke (service, msg.method_index, message,
                server_connection_response_closure, (void*)&msg);

        if (message)
            protobuf_c_message_free_unpacked (message, NULL);
    }
    return 0;

error:
    close (fd);
    if (conn->incoming.must_free_data)
        free (conn->incoming.data);
    if (conn->outgoing.must_free_data)
        free (conn->outgoing.data);
    free (conn);
    return -1;
}

static int
server_callback (int fd, void *data)
{
    rpc_server_t *server = (rpc_server_t *)data;
    struct sockaddr addr;
    socklen_t addr_len = sizeof (addr);
    int new_fd;

    new_fd = accept (fd, &addr, &addr_len);
    if (new_fd < 0)
    {
        if (errno == EINTR || errno == EAGAIN)
            return 0;
        ERROR ("RPC[%d]: accept() failed: %s\n",
                fd, strerror (errno));
        return 0;
    }

    DEBUG ("RPC[%d]: Client connect (%d)\n", fd, new_fd);

    rpc_connection_t *conn = calloc (1, sizeof (rpc_connection_t));
    conn->fd = new_fd;
    conn->server = server;
    conn->incoming.base.append = protobuf_c_buffer_simple_append;
    conn->incoming.alloced = RPC_HEADER_LENGTH; /* Just tricking */
    conn->outgoing.base.append = protobuf_c_buffer_simple_append;
    conn->outgoing.alloced = RPC_HEADER_LENGTH; /* Just tricking */

    pthread_mutex_lock (&server->lock);
    add_cb (&server->pending, new_fd, conn_callback, (void*)conn);
    pthread_mutex_unlock (&server->lock);
    return 0;
}

static void
wake_server (rpc_server_t *server)
{
    uint8_t dummy = 0;
    if (write (server->wake_server[1], &dummy, 1) !=1)
        ERROR ("Failed to write to wake server\n");
}

static int
stop_callback (int fd, void *data)
{
    rpc_server_t *server = (rpc_server_t *)data;
    server->running = false;
    wake_server (server);
    return -1;
}

static int
worker (void *data)
{
    rpc_server_t *server = (rpc_server_t *) data;
    pthread_t self = pthread_self();
    GList *event;
    int ret;
    int i;

    DEBUG ("RPC: New Worker (%p:%lu)\n", server, (unsigned long)self);
    tl_server = server;
    while (server->running)
    {
        sem_wait (&server->wake_workers);
        pthread_mutex_lock (&server->lock);
        event = g_list_first (server->working);
        server->working = g_list_remove_link (server->working, event);
        pthread_mutex_unlock (&server->lock);
        if (event)
        {
            callback_t *cb = (callback_t *)event->data;
            DEBUG ("[%lu]RPC: Callback for fd %d\n", (unsigned long)self, cb->fd);
            ret = cb->func (cb->fd, cb->data);
            if (ret == 0)
            {
                pthread_mutex_lock (&server->lock);
                server->pending = g_list_append (server->pending, cb);
                pthread_mutex_unlock (&server->lock);
                wake_server (server);
            }
            else
            {
                free (cb);
            }
            g_list_free (event);
        }
    }

    for (i=0; i < server->num_workers; i++)
        if (server->workers[i] == self)
            server->workers[i] = -1;
    DEBUG ("RPC: End Worker (%p:%lu)\n", server, (unsigned long)self);
    return 0;
}

static rpc_socket_t *
find_socket (const char *id, const char *url)
{
    rpc_socket_t *sock = NULL;
    GList *iter;

    /* Look through the list */
    pthread_mutex_lock (&tl_server->lock);
    for (iter = tl_server->sockets; iter; iter = iter->next)
    {
        sock = (rpc_socket_t *)iter->data;
        if ((id && strcmp (id, sock->id) == 0) ||
            (url && strcmp (url, sock->url) == 0))
        {
            break;
        }
        sock = NULL;
    }
    pthread_mutex_unlock (&tl_server->lock);
    return sock;
}

static rpc_socket_t*
parse_url (const char *url)
{
    rpc_socket_t *sock = calloc (1, sizeof (rpc_socket_t));
    char host[INET6_ADDRSTRLEN];
    int port = 80;

    /* UNIX path = "unix:///<unix-path>[:<apteryx-path>]" */
    if (strncmp (url, "unix://", 7) == 0)
    {
        const char *name = url + strlen ("unix://");
        const char *end = strchr (name, ':');
        int len = end ? end - name : strlen (name);

        sock->family = PF_UNIX;
        sock->address_len = sizeof (sock->address.addr_un);
        memset (&sock->address.addr_un, 0, sock->address_len);
        sock->address.addr_un.sun_family = AF_UNIX;
        strncpy (sock->address.addr_un.sun_path, name,
                len >= sizeof (sock->address.addr_un.sun_path) ?
                       sizeof (sock->address.addr_un.sun_path)-1 : len);
        DEBUG ("RPC: unix://%s\n", sock->address.addr_un.sun_path);
    }
    /* IPv4 TCP path = "tcp://<IPv4>:<port>[:<apteryx-path>]" */
    else if (sscanf (url, "tcp://%16[^:]:%d", host, &port) == 2)
    {
        if (inet_pton (AF_INET, host, &sock->address.addr_in.sin_addr) != 1)
        {
            ERROR ("RPC: Invalid IPv4 address: %s\n", host);
            free (sock);
            return NULL;
        }
        sock->family = AF_INET;
        sock->address_len = sizeof (sock->address.addr_in);
        sock->address.addr_in.sin_family = AF_INET;
        sock->address.addr_in.sin_port = htons (port);
        DEBUG ("RPC: tcp://%s:%u\n",
            inet_ntop (AF_INET, &sock->address.addr_in.sin_addr,
                host, INET6_ADDRSTRLEN), port);
    }
    /* IPv6 TCP path = "tcp:[<IPv6>]:<port>[:<apteryx-path>]" */
    else if (sscanf (url, "tcp://[%48[^]]]:%d", host, &port) == 2)
    {
        if (inet_pton (AF_INET6, host, &sock->address.addr_in6.sin6_addr) != 1)
        {
            ERROR ("RPC: Invalid IPv6 address: %s\n", host);
            free (sock);
            return NULL;
        }
        sock->family = AF_INET6;
        sock->address_len = sizeof (sock->address.addr_in6);
        sock->address.addr_in6.sin6_family = AF_INET6;
        sock->address.addr_in6.sin6_port = htons (port);
        DEBUG ("RPC: tcp://[%s]:%u\n",
            inet_ntop (AF_INET6, &sock->address.addr_in6.sin6_addr,
                host, INET6_ADDRSTRLEN), port);
    }
    else
    {
        ERROR ("RPC: Invalid URL: %s\n", url);
        free (sock);
        return NULL;
    }

    return sock;
}

bool
rpc_bind_url (const char *id, const char *url)
{
    rpc_socket_t *sock;
    int on = 1;

    /* Check the socket does not already exist */
    sock = find_socket (id, url);
    if (sock)
    {
        ERROR ("RPC: Socket(%s:%s) already bound.\n", id, url);
        return false;
    }

    /* Parse the URL */
    sock = parse_url (url);
    if (sock == NULL)
    {
        return false;
    }

    /* Create the listen socket */
    sock->fd = socket (sock->family, SOCK_STREAM, 0);
    if (sock->fd < 0)
    {
        ERROR ("RPC: Socket(%s:%s) failed: %s\n", id, url, strerror (errno));
        free (sock);
        return false;
    }
    setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind (sock->fd, (struct sockaddr *)&sock->address, sock->address_len) < 0)
    {
        ERROR ("RPC: Socket(%s:%s) error binding: %s\n", id, url, strerror (errno));
        close (sock->fd);
        free (sock);
        return false;
    }
    if (listen (sock->fd, 255) < 0)
    {
        ERROR ("RPC: Socket(%s:%s) listen failed: %s\n", id, url, strerror (errno));
        close (sock->fd);
        free (sock);
        return false;
    }
    int flags = fcntl (sock->fd, F_GETFL);
    if (flags >= 0)
        fcntl (sock->fd, F_SETFL, flags | O_NONBLOCK);

    DEBUG ("RPC: New Socket (%d:%s:%s)\n", sock->fd, id, url);
    sock->id = strdup (id);
    sock->url = strdup (url);
    pthread_mutex_lock (&tl_server->lock);
    tl_server->sockets = g_list_append (tl_server->sockets, sock);
    add_cb (&tl_server->pending, sock->fd, server_callback, (void*)tl_server);
    pthread_mutex_unlock (&tl_server->lock);

    return true;
}

bool
rpc_unbind_url (const char *id, const char *url)
{
    rpc_socket_t *sock;

    /* Check the socket does not already exist */
    sock = find_socket (id, url);
    if (!sock)
    {
        ERROR ("RPC: Socket(%s:%s) not bound.\n", id, url);
        return false;
    }

    /* Close and free */
    pthread_mutex_lock (&tl_server->lock);
    delete_cb (&tl_server->pending, sock->fd);
    tl_server->sockets = g_list_remove (tl_server->sockets, sock);
    pthread_mutex_unlock (&tl_server->lock);
    if (sock->fd >= 0)
        close (sock->fd);
    if (sock->family == PF_UNIX)
        unlink (sock->address.addr_un.sun_path);
    free ((void*) sock->id);
    free ((void*) sock->url);
    free (sock);
    return false;
}

bool
rpc_provide_service (const char *url, ProtobufCService *service, int num_threads, int stopfd)
{
    rpc_server_t server = {};
    struct pollfd *fds = NULL;
    GList *iter;
    bool rc = true;
    int i;

    /* Setup the thread local server structure */
    server.running = true;
    server.service = service;
    pthread_mutex_init (&server.lock, NULL);
    tl_server = &server;

    DEBUG ("RPC: New server (%p)\n", &server);

    /* Bind the default listen socket */
    if (!rpc_bind_url ("default", url))
    {
        rc = false;
        goto exit;
    }

    /* Start any worker threads */
    if (num_threads > 0)
    {
        if (pipe (server.wake_server) != 0)
            ERROR ("Failed to create pipe to wake server\n");
        add_cb (&server.pending, server.wake_server[0], NULL, (void*)&server);
        sem_init (&server.wake_workers, 1, 0);
        server.num_workers = num_threads;
        server.workers = calloc (num_threads, sizeof (pthread_t));
        for (i=0; i < num_threads; i++)
            pthread_create (&server.workers[i], NULL,
                    (void *) &worker, (void *) &server);
    }

    /* Add callbacks for stopping and new connections */
    if (stopfd > 0)
        add_cb (&server.pending, stopfd, stop_callback, (void*)&server);

    /* Loop while not asked to stop */
    while (server.running)
    {
        int num_fds;

        /* Create the event list */
        pthread_mutex_lock (&server.lock);
        num_fds = g_list_length (server.pending);
        fds = realloc (fds, num_fds * sizeof (struct pollfd));
        for (i=0, iter = server.pending; iter; iter = iter->next, i++)
        {
            callback_t *cb = (callback_t *)iter->data;
            fds[i].fd = cb->fd;
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }
        pthread_mutex_unlock (&server.lock);

        DEBUG ("RPC: Waiting for %d events\n", num_fds);
        if (poll (fds, num_fds, -1) <= 0)
        {
            DEBUG ("RPC: polling error: %s\n", strerror (errno));
        }

        if (server.workers)
        {
            /* The list may be invalid  */
            if (fds[0].revents && fds[0].fd == server.wake_server[0])
            {
                /* We have been woken because of a list change */
                uint8_t dummy = read (fds[0].fd, &dummy, 1);
                continue;
            }
            else if (num_fds != g_list_length (server.pending))
            {
                /* List has been changed due to callback */
                continue;
            }

            /* Process any valid callbacks */
            pthread_mutex_lock (&server.lock);
            iter = server.pending;
            i = 0;
            while (iter != NULL)
            {
                GList *next = iter->next;
                callback_t *cb = (callback_t *)iter->data;
                if (fds[i].revents && cb->func)
                {
                    DEBUG ("RPC: Event for fd %d\n", cb->fd);
                    server.pending = g_list_remove (server.pending, cb);
                    server.working = g_list_append (server.working, cb);
                    sem_post (&server.wake_workers);
                }
                iter = next;
                i++;
            }
            pthread_mutex_unlock (&server.lock);
        }
        else
        {
            server.working = g_list_copy (server.pending);
            for (i=0, iter = server.working; iter; iter = iter->next, i++)
            {
                if (fds[i].revents)
                {
                    callback_t *cb = (callback_t *)iter->data;
                    DEBUG ("RPC: Callback for fd %d\n", fds[i].fd);
                    if (cb->func (cb->fd, cb->data) < 0)
                        delete_cb (&server.pending, fds[i].fd);
                }
            }
            g_list_free (server.working);
            server.working = NULL;
        }
    }

exit:
    DEBUG ("RPC: Shutdown server (%p)\n", &server);
    if (server.workers)
    {
        for (i=0; i < num_threads; i++)
        {
            sem_post (&server.wake_workers);
            usleep (1000);
            if (server.workers[i] != -1)
            {
                pthread_cancel (server.workers[i]);
                pthread_join (server.workers[i], NULL);
            }
        }
        free (server.workers);
    }
    for (i=0, iter = server.sockets; iter; iter = iter->next, i++)
    {
        rpc_socket_t *sock = (rpc_socket_t *)iter->data;
        DEBUG ("RPC: Close socket (%s:%s)\n", sock->id, sock->url);
        if (sock->fd >= 0)
            close (sock->fd);
        if (sock->family == PF_UNIX)
            unlink (sock->address.addr_un.sun_path);
        free ((void*) sock->id);
        free ((void*) sock->url);
    }
    g_list_free_full (server.sockets, free);
    g_list_free_full (server.pending, free);
    if (fds)
        free (fds);
    pthread_mutex_destroy (&server.lock);
    server.running = false;
    return rc;
}

static void
invoke_client_service (ProtobufCService *service,
        unsigned method_index,
        const ProtobufCMessage *input,
        ProtobufCClosure closure,
        void *closure_data)
{
    rpc_client_t *client = (rpc_client_t *)service;
    rpc_message_t msg = {};
    uint8_t buffer_slab[512];
    ProtobufCBufferSimple buffer = PROTOBUF_C_BUFFER_SIMPLE_INIT (buffer_slab);

    /* One at a time please */
    pthread_mutex_lock (&client->lock);

    /* Serialise the message */
    msg.method_index = method_index;
    msg.request_id = ++client->request_id;
    msg.message_length = protobuf_c_message_get_packed_size (input);
    pack_header (&msg, buffer_slab);
    buffer.len = RPC_HEADER_LENGTH;
    if (protobuf_c_message_pack_to_buffer (input, (ProtobufCBuffer *)&buffer)
            != msg.message_length)
    {
        ERROR ("RPC[%d]: error serializing the response\n", client->fd);
        pthread_mutex_unlock (&client->lock);
        closure (NULL, closure_data);
        return;
    }

    DEBUG ("RPC: ID=%d Method=%d Length=%d\n",
            msg.request_id, msg.method_index, msg.message_length);

    /* Send the message */
    uint8_t *data = buffer.data;
    while (buffer.len > 0)
    {
        //int rv = write (client->fd, data, buffer.len);
        int rv = send (client->fd, data, buffer.len, MSG_NOSIGNAL);
        if (rv == 0)
        {
            DEBUG ("RPC[%d]: connection closed\n", client->fd);
            pthread_mutex_unlock (&client->lock);
            return;
        }
        else if (rv < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            ERROR ("RPC[%d]: write() failed: %s\n", client->fd, strerror (errno));
            pthread_mutex_unlock (&client->lock);
            return;
        }
        DEBUG ("RPC[%d]: Wrote %d of %zd bytes\n", client->fd, rv, buffer.len);
        buffer.len -= rv;
    }
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&buffer);

    /* Wait for response */
    DEBUG ("RPC[%d]: waiting for response\n", client->fd);
    uint64_t start = get_time_us ();
    while (1)
    {
        unsigned char buf[8192];
        int rv;
        rv = read (client->fd, buf, sizeof (buf));
        if (rv == 0)
        {
            DEBUG ("RPC[%d]: connection closed\n", client->fd);
            goto error;
        }
        else if ((get_time_us () - start) > RPC_TIMEOUT_US)
        {
            ERROR ("RPC[%d]: read() timeout\n", client->fd);
            goto error;
        }
        else if (rv < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            DEBUG ("RPC[%d]: read() failed: %s\n", client->fd, strerror (errno));
            goto error;
        }

        DEBUG ("RPC[%d]: read %d bytes (%zu total)\n", client->fd, rv, buffer.len + rv);

        buffer.base.append ((ProtobufCBuffer*)&buffer, rv, buf);
        unpack_header (&buffer.data[4], &msg);
        if (buffer.len >= (RPC_HEADER_LENGTH +sizeof (uint32_t)) &&
            buffer.len >= ((RPC_HEADER_LENGTH +sizeof (uint32_t)) + msg.message_length))
        {
            break;
        }
    }

    /* Unpack message */
    const ProtobufCMethodDescriptor *method = service->descriptor->methods + method_index;
    const ProtobufCMessageDescriptor *desc = method->output;
    ProtobufCMessage *message = NULL;
    if (msg.message_length > 0)
    {
        DEBUG ("RPC[%d]: unpacking response\n", client->fd);
        message = protobuf_c_message_unpack (desc, NULL,
                msg.message_length, buffer.data+RPC_HEADER_LENGTH+sizeof (uint32_t));
    }
    else
    {
        DEBUG ("RPC[%d]: empty response\n", client->fd);
        message = protobuf_c_message_unpack (desc, NULL, 0, NULL);
    }

    /* Return result */
    pthread_mutex_unlock (&client->lock);
    closure (message, closure_data);
    if (message)
        protobuf_c_message_free_unpacked (message, NULL);
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&buffer);
    return;

error:
    pthread_mutex_unlock (&client->lock);
    closure (NULL, closure_data);
    return;
}

static void
destroy_client_service (ProtobufCService *service)
{
    rpc_client_t *client = (rpc_client_t *)service;
    DEBUG ("RPC: destroy_client_service\n");
    close (client->fd);
    free (client);
}

ProtobufCService *
rpc_connect_service (const char *url, const ProtobufCServiceDescriptor *descriptor)
{
    rpc_socket_t *sock;
    rpc_client_t *client;

    /* Parse URL */
    sock = parse_url (url);
    if (sock == NULL)
    {
        return NULL;
    }
    DEBUG ("RPC: New Client\n");

    /* Create socket */
    sock->fd = socket (sock->family, SOCK_STREAM, 0);
    if (sock->fd < 0)
    {
        ERROR ("RPC: socket() failed: %s\n", strerror (errno));
        free (sock);
        return NULL;
    }
    int flags = fcntl (sock->fd, F_GETFL);
    if (flags >= 0)
        fcntl (sock->fd, F_SETFL, flags | O_NONBLOCK);
    if (connect (sock->fd, (struct sockaddr *) &sock->address, sock->address_len) < 0
            && errno != EINPROGRESS)
    {
        ERROR ("RPC: error connecting to remote host: %s\n", strerror (errno));
        close (sock->fd);
        free (sock);
        return NULL;
    }
    DEBUG ("RPC[%d]: Connected to Server\n", sock->fd);

    /* Create client */
    client = calloc (1, sizeof (rpc_client_t));
    if (!client)
    {
        ERROR ("RPC: Failed to allocate memory for client service\n");
        close (sock->fd);
        free (sock);
        return NULL;
    }
    client->service.descriptor = descriptor;
    client->service.invoke = invoke_client_service;
    client->service.destroy = destroy_client_service;
    client->fd = sock->fd;
    pthread_mutex_init (&client->lock, NULL);
    free (sock);
    return (ProtobufCService *)client;
}
