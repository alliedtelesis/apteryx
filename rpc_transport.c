#include "internal.h"
#include "rpc_transport.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static socket_info
parse_url (const char *url)
{
    socket_info sock = g_malloc0 (sizeof (*sock));
    char host[INET6_ADDRSTRLEN];
    int port = 9999;

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
            g_free (sock);
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
    else if (sscanf (url, "tcp://[%45[^]]]:%d", host, &port) == 2)
    {
        if (inet_pton (AF_INET6, host, &sock->address.addr_in6.sin6_addr) != 1)
        {
            ERROR ("RPC: Invalid IPv6 address: %s\n", host);
            g_free (sock);
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
        g_free (sock);
        return NULL;
    }

    return sock;
}

static bool
get_peer_details (int fd, uint64_t *pid, uint64_t *ns)
{
    struct ucred ucred;
    socklen_t uclen = sizeof(struct ucred);
    struct stat st = { 0 };
    char *path;

    *pid = 0;
    *ns = 0;

    /* Get socket peer pid */
    if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &ucred, &uclen))
    {
        ERROR ("RPC: Failed to get socket peer pid: %s\n", strerror (errno));
        return false;
    }
    *pid = (uint64_t) ucred.pid;

    /* Get socket peer namespace */
    path = g_strdup_printf ("/proc/%"PRIu64"/ns/mnt", *pid);
    if (stat (path, &st))
    {
        ERROR ("RPC: Failed to get socket peer namespace: %s\n", strerror (errno));
        free (path);
        return false;
    }
    *ns = (uint64_t) st.st_ino;
    free (path);

    /* Check if we are in a different namespace */
    if (*ns != getns ())
    {
        char *cmd = g_strdup_printf ("grep NSpid /proc/%"PRIu64"/status | cut -f3", *pid);
        FILE *file = popen (cmd, "r");
        uint64_t nspid = 0;
        if (!file || fscanf (file, "%"PRIu64, &nspid) != 1)
        {
            ERROR ("RPC: Failed to get socket pid in other namespace: %s\n", strerror (errno));
            if (file)
                pclose (file);
            free (cmd);
            return false;
        }
        if (file)
            pclose (file);
        free (cmd);

        DEBUG ("RPC: Peer namespace different (here:%"PRIX64".%"PRIu64" there:%"PRIX64".%"PRIu64")\n",
               getns (), *pid, *ns, nspid);

        *pid = nspid;
    }

    return true;
}

static void *
accept_thread (void *p)
{
    /* Mask signals */
    sigset_t set;
    sigfillset (&set);
    pthread_sigmask (SIG_BLOCK, &set, NULL);

    rpc_server s = (rpc_server) p;
    while (1)
    {
        struct sockaddr addr;
        socklen_t len = sizeof (addr);
        int new_fd = accept (s->sock, &addr, &len);
        if (new_fd != -1)
        {
            uint64_t pid, ns;
            get_peer_details (new_fd, &pid, &ns);
            DEBUG ("RPC: New client (fd=%i, id=%"PRIX64".%"PRIu64")\n", new_fd, ns, pid);
            rpc_socket r = rpc_socket_create (new_fd, s->request_cb, s, pid, ns);
            r->priv = s->parent->priv;
            pthread_mutex_lock (&s->lock);
            GList *iter = NULL;
            /* This may be a reused fd, so close the old ones */
            for (iter = s->clients; iter; iter = g_list_next(iter))
            {
                rpc_socket extant = iter->data;
                if (extant->sock == new_fd)
                {
                    DEBUG ("RPC: Closing reused socket");
                    extant->dead = true;
                }
            }
            s->clients = g_list_append (s->clients, r);
            if (!rpc_socket_process (r))
            {
                s->clients = g_list_remove (s->clients, r);
                rpc_socket_deref (r);
            }
            pthread_mutex_unlock (&s->lock);
        }
    }
    return 0;
}

rpc_server
create_rpc_server_with_listener (const char *guid, const char *url, int fd, rpc_callback cb,
                                 rpc_service parent, socket_info sock)
{
    rpc_server s = g_malloc0 (sizeof (*s));
    s->sock = fd;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    s->url = g_strdup (url);
    s->guid = g_strdup (guid);
    s->request_cb = cb;
    s->parent = parent;
    s->sockinfo = sock;
    pthread_mutex_init (&s->lock, NULL);
    pthread_create (&s->thread, NULL, accept_thread, s);
    return s;
}

rpc_service
rpc_server_parent_get (rpc_server s)
{
    if (s == NULL)
    {
        return NULL;
    }
    return s->parent;
}

static bool
socket_is_active(socket_info sock)
{
    bool active = false;
    int sockfd = socket (sock->family, SOCK_STREAM, 0);
    if (sockfd >= 0) {
        if (connect (sockfd, (struct sockaddr *) &sock->address, sock->address_len) == 0) {
            active = true;
        }
        close (sockfd);
    }
    return active;
}

bool
rpc_server_die (rpc_server s)
{
    close (s->sock);
    usleep (1000);
    pthread_mutex_lock (&s->lock);
    pthread_cancel (s->thread);
    pthread_join (s->thread, NULL);
    for (GList *itr = s->clients; itr; itr = itr->next)
    {
        rpc_socket sock = (rpc_socket) itr->data;
        sock->parent = NULL;
        rpc_socket_deref (sock);
    }
    g_list_free (s->clients);
    pthread_mutex_unlock (&s->lock);
    if (s->sockinfo->family == AF_UNIX && !socket_is_active (s->sockinfo))
    {
        unlink (s->sockinfo->address.addr_un.sun_path);
    }
    g_free (s->sockinfo);
    g_free (s->url);
    g_free (s->guid);
    g_free (s);
    return true;
}

rpc_service
rpc_service_init (rpc_callback cb, void *priv)
{
    rpc_service s = g_malloc0 (sizeof (*s));
    pthread_mutex_init (&s->lock, NULL);
    s->request_cb = cb;
    s->priv = priv;
    return s;
}

bool
rpc_service_run (rpc_service s, int stopfd)
{
    char data[10];
    if (stopfd)
        while (read (stopfd, data, 10) == 0) ;
    else
        while (1) { pause(); }
    return false;
}

rpc_server
rpc_service_find_server (rpc_service s, const char *guid)
{
    pthread_mutex_lock (&s->lock);
    for (GList *itr = s->servers; itr; itr = itr->next)
    {
        if (strcmp (((rpc_server)itr->data)->guid, guid) == 0)
        {
            pthread_mutex_unlock (&s->lock);
            return (rpc_server)itr->data;
        }
    }
    pthread_mutex_unlock (&s->lock);
    return NULL;
}

static bool
rpc_service_add_server (rpc_service s, rpc_server serv)
{
    pthread_mutex_lock (&s->lock);
    s->servers = g_list_append (s->servers, serv);
    pthread_mutex_unlock (&s->lock);
    return true;
}

static bool
rpc_service_remove_server (rpc_service s, rpc_server serv)
{
    pthread_mutex_lock (&s->lock);
    s->servers = g_list_remove (s->servers, serv);
    pthread_mutex_unlock (&s->lock);
    return true;
}

void *
rpc_service_priv_get (rpc_service s)
{
    if (s == NULL)
    {
        return NULL;
    }
    return s->priv;
}

bool
rpc_service_die (rpc_service s)
{
    /* Stop all of the servers */
    pthread_mutex_lock (&s->lock);
    for (GList *itr = s->servers; itr; itr = itr->next)
    {
        rpc_server serv = (rpc_server) itr->data;
        rpc_server_die (serv);
    }
    pthread_mutex_unlock (&s->lock);
    g_list_free (s->servers);
    g_free ((void*)s);
    return true;
}

bool
rpc_service_bind_url (rpc_service s, const char *guid, const char *url)
{
    int on = 1;

    /* Already exists */
    if (rpc_service_find_server (s, url))
    {
        return false;
    }

    /* Parse the URL */
    socket_info sock = parse_url (url);
    if (sock == NULL)
    {
        return false;
    }

    /* Create the listen socket */
    int fd = socket (sock->family, SOCK_STREAM, 0);
    if (fd < 0)
    {
        ERROR ("RPC: Socket(%s) failed: %s\n", url, strerror (errno));
        g_free (sock);
        return false;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &on, sizeof(on));
    if (bind (fd, (struct sockaddr *)&sock->address, sock->address_len) < 0)
    {
        ERROR ("RPC: Socket(%s) error binding: %s\n", url, strerror (errno));
        close (fd);
        g_free (sock);
        return false;
    }
    if (listen (fd, 255) < 0)
    {
        ERROR ("RPC: Socket(%s) listen failed: %s\n", url, strerror (errno));
        close (fd);
        g_free (sock);
        return false;
    }
    if (sock->family == AF_UNIX)
    {
        chmod (sock->address.addr_un.sun_path, 0666);
    }
    DEBUG ("RPC: New Socket (%d:%s)\n", fd, url);

    rpc_server serv = create_rpc_server_with_listener (guid, url, fd, s->request_cb, s, sock);
    rpc_service_add_server (s, serv);

    return true;
}

bool
rpc_service_unbind_url (rpc_service s, const char *guid)
{
    rpc_server serv = rpc_service_find_server (s, guid);
    if (serv == NULL)
    {
        return false;
    }
    rpc_service_remove_server (s, serv);
    rpc_server_die (serv);
    return true;
}

rpc_socket
rpc_socket_connect_service (const char *url, rpc_callback cb)
{
    socket_info sock;
    rpc_socket client;

    /* Parse URL */
    sock = parse_url (url);
    if (sock == NULL)
    {
        return NULL;
    }
    DEBUG ("RPC: New Client\n");

    /* Create socket */
    int fd = socket (sock->family, SOCK_STREAM, 0);
    if (fd < 0)
    {
        ERROR ("RPC: socket() failed: %s\n", strerror (errno));
        g_free (sock);
        return NULL;
    }
    if (connect (fd, (struct sockaddr *) &sock->address, sock->address_len) < 0
            && errno != EINPROGRESS)
    {
        ERROR ("RPC: error connecting to remote host: %s\n", strerror (errno));
        close (fd);
        g_free (sock);
        return NULL;
    }
    DEBUG ("RPC[%d]: Connected to Server\n", fd);

    /* Create client */
    client = rpc_socket_create (fd, cb, NULL, 0, getns ());
    g_free (sock);

    return client;
}
