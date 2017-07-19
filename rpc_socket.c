#include "internal.h"
#include "rpc_transport.h"

#include <errno.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/tcp.h>
#include <fcntl.h>

#define MODE_REQUEST 1
#define MODE_RESPONSE 2

struct msg_s {
    rpc_id id;
    void *data;
    size_t len;
};

static bool
recv_data (int fd, void *data, size_t len)
{
    ssize_t recvd = 0;
    while (recvd < len)
    {
        ssize_t r = recv (fd, data + recvd, len - recvd, 0);
        if (r < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
            {
                continue;
            }
            else if (errno == ECONNRESET)
            {
                DEBUG ("RPC[%i]: Recv data: %s\n", fd, strerror (errno));
            }
            else
            {
                ERROR ("RPC[%i]: Recv data error: %s\n", fd, strerror (errno));
            }
        }
        if (r <= 0)
        {
            /* Shutdown */
            DEBUG ("RPC[%i]: Shutdown\n", fd);
            goto finished;
        }
        recvd += r;
    }
    return true;
finished:
    return false;
}

static void *
listen_thread (void *p)
{
    rpc_socket sock = (rpc_socket) p;

    /* Mask signals */
    sigset_t set;
    sigfillset (&set);
    pthread_sigmask (SIG_BLOCK, &set, NULL);

    do
    {
        int fd = sock->sock;
        struct rpc_hdr_s hdr;
        size_t len;
        rpc_id id;

        /* Get the header */
        if (!recv_data (fd, &hdr, sizeof (hdr)))
        {
            goto finished;
        }
        len = ntohl (hdr.len);
        id = ntohl (hdr.id);

        /* Get the message */
        void *data = g_malloc (len);
        if (!recv_data (fd, data, len))
        {
            g_free (data);
            goto finished;
        }

        if (ntohl (hdr.mode) == MODE_RESPONSE)
        {
            struct msg_s *m = g_malloc0 (sizeof (*m));
            m->id = id;
            m->data = data;
            m->len = len;
            pthread_mutex_lock (&sock->in_lock);
            sock->in_queue = g_list_prepend (sock->in_queue, m);
            if (sock->waiting)
            {
                pthread_cond_broadcast (&sock->in_cond);
            }
            pthread_mutex_unlock (&sock->in_lock);
        }
        else if (ntohl (hdr.mode) == MODE_REQUEST)
        {
            /* Call the request callback */
            if (sock->request_cb)
            {
                sock->request_cb (sock, id, data, len);
            }
            g_free (data);
        }
        else
        {
            ERROR ("Unknown message type %x", ntohl(hdr.mode));
            g_free (data);
            goto finished;
        }
    } while (!sock->dead);

finished:
    /* Socket is no longer useful */
    sock->dead = true;

    /* Check if we are referenced on the server list */
    rpc_server s = rpc_socket_parent_get (sock);
    if (s)
    {
        pthread_mutex_lock (&s->lock);
        if (g_list_find (s->clients, sock) != NULL)
        {
            s->clients = g_list_remove (s->clients, sock);
            rpc_socket_deref (sock);
        }
        pthread_mutex_unlock (&s->lock);
    }
    return 0;
}

bool
rpc_socket_recv (rpc_socket sock, rpc_id id, void **data, size_t *len, uint64_t waitUS)
{
    struct msg_s *m = NULL;

    struct timespec waitUntil;
    struct timeval now;
    int ret = 0;

    if (waitUS)
    {
        gettimeofday (&now, NULL);
        waitUntil.tv_sec = now.tv_sec + (waitUS / (1000UL * 1000UL));
        waitUntil.tv_nsec = (now.tv_usec + (waitUS % (1000UL * 1000UL))) * 1000UL;
        waitUntil.tv_sec += waitUntil.tv_nsec / (1000UL * 1000UL * 1000UL);
        waitUntil.tv_nsec %= (1000UL * 1000UL * 1000UL);
    }

    pthread_mutex_lock (&sock->in_lock);
    do
    {
        if (sock->dead)
        {
            pthread_mutex_unlock (&sock->in_lock);
            return false;
        }
        for (GList *itr = sock->in_queue; itr; itr = itr->next)
        {
            struct msg_s *msg = (struct msg_s *) itr->data;
            if (msg->id == id)
            {
                m = msg;
                break;
            }
        }
        if (m == NULL)
        {
            sock->waiting++;
            if (waitUS)
            {
                ret = pthread_cond_timedwait (&sock->in_cond, &sock->in_lock, &waitUntil);
            }
            else
            {
                ret = pthread_cond_wait (&sock->in_cond, &sock->in_lock);
            }
            sock->waiting--;
        }
    } while (ret == 0 && m == NULL);
    if (m)
    {
        sock->in_queue = g_list_remove (sock->in_queue, m);
        *data = m->data;
        *len = m->len;
        g_free (m);
    }
    pthread_mutex_unlock (&sock->in_lock);
    return m != NULL;
}

rpc_socket
rpc_socket_create (int fd, rpc_callback cb, rpc_server parent)
{
    rpc_socket sock = g_malloc0 (sizeof(*sock));
    sock->refcount = 1;
    sock->sock = fd;
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    sock->next_id = 1;
    sock->request_cb = cb;
    sock->parent = parent;
    pthread_mutex_init (&sock->in_lock, NULL);
    pthread_mutex_init (&sock->out_lock, NULL);
    pthread_mutex_init (&sock->lock, NULL);
    pthread_cond_init (&sock->in_cond, NULL);
    return sock;
}

bool
rpc_socket_process (rpc_socket sock)
{
    int ret = pthread_create (&sock->thread, NULL, listen_thread, sock);
    if (ret != 0)
    {
        syslog (LOG_CRIT, "Failed to create thread: %s\n", strerror (errno));
        return false;
    }
    char tname[16];
    snprintf ((char *)&tname, 16, "rpc.%i", sock->sock);
    pthread_setname_np (sock->thread, tname);
    return true;
}

void *
rpc_socket_priv_get (rpc_socket sock)
{
    if (sock == NULL)
    {
        return NULL;
    }
    return sock->priv;
}

static bool
rpc_socket_die (rpc_socket sock)
{
    DEBUG ("RPC[%i]: Socket Die\n", sock->sock);
    pthread_mutex_lock (&sock->lock);
    assert (sock->refcount == 0);
    sock->dead = true;
    pthread_mutex_unlock (&sock->lock);
    pthread_mutex_lock (&sock->in_lock);
    close (sock->sock);
    usleep (1000);
    pthread_mutex_unlock (&sock->in_lock);
    if (!pthread_equal (pthread_self (), sock->thread))
    {
        pthread_cancel (sock->thread);
        pthread_join (sock->thread, NULL);
    }
    else
    {
        pthread_detach (sock->thread);
    }
    pthread_mutex_lock (&sock->in_lock);
    for (GList *itr = sock->in_queue; itr; itr = itr->next)
    {
        struct msg_s *m = (struct msg_s *)itr->data;
        g_free (m->data);
        g_free (m);
    }
    g_list_free (sock->in_queue);
    sock->in_queue = NULL;
    while (sock->waiting)
    {
        pthread_cond_broadcast (&sock->in_cond);
        pthread_mutex_unlock (&sock->in_lock);
        pthread_mutex_lock (&sock->in_lock);
    }
    pthread_mutex_unlock (&sock->in_lock);
    pthread_mutex_destroy (&sock->in_lock);
    pthread_mutex_destroy (&sock->out_lock);
    pthread_mutex_destroy (&sock->lock);
    DEBUG ("RPC[%i]: Socket Dead\n", sock->sock);
    g_free (sock);
    return true;
}

void
rpc_socket_ref (rpc_socket sock)
{
    if (sock == NULL)
    {
        return;
    }
    pthread_mutex_lock (&sock->lock);
    sock->refcount++;
    pthread_mutex_unlock (&sock->lock);
}

void
rpc_socket_deref (rpc_socket sock)
{
    pthread_mutex_lock (&sock->lock);
    sock->refcount--;
    bool destroy = sock->refcount == 0;
    pthread_mutex_unlock (&sock->lock);
    if (destroy)
    {
        rpc_socket_die (sock);
    }
}

static bool
rpc_socket_send_s (rpc_socket sock, rpc_id id, void *data, size_t len, uint32_t mode)
{
    ssize_t sent = 0;
    struct rpc_hdr_s *hdr = (struct rpc_hdr_s *)data;

    if (sock->dead)
    {
        return false;
    }

    hdr->len = htonl (len);
    hdr->mode = htonl (mode);
    hdr->id = htonl (id);

    len += sizeof (struct rpc_hdr_s);

    while (sent < len)
    {
        ssize_t s = send (sock->sock, data + sent, len - sent, MSG_NOSIGNAL);
        if (s < 0)
        {
            ERROR ("RPC[%i] Send Failed: %s\n", sock->sock, strerror (errno));
            sock->dead = true;
            return false;
        }
        sent += s;
    }
    return true;
}

rpc_id
rpc_socket_send_request (rpc_socket sock, void *data, size_t len)
{
    rpc_id id = 0;
    pthread_mutex_lock (&sock->out_lock);
    while (id == 0)
    {
        id = sock->next_id++;
    }
    if (!rpc_socket_send_s (sock, id, data, len, MODE_REQUEST))
    {
        id = 0;
    }
    pthread_mutex_unlock (&sock->out_lock);
    return id;
}

bool
rpc_socket_send_response (rpc_socket sock, rpc_id id, void *data, size_t len)
{
    pthread_mutex_lock (&sock->out_lock);
    bool res = rpc_socket_send_s (sock, id, data, len, MODE_RESPONSE);
    pthread_mutex_unlock (&sock->out_lock);
    return res;
}

rpc_server
rpc_socket_parent_get (rpc_socket sock)
{
    if (sock == NULL)
    {
        return NULL;
    }
    return sock->parent;
}
