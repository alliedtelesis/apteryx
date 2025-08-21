/**
 * @file rpc.c
 * RPC implementation for Apteryx.
 *
 * Copyright 2015, Allied Telesis Labs New Zealand, Ltd
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

#include "apteryx.h"
#include "internal.h"

/* An RPC instance.
 * Provides the service, service
 * Connects to the remote service using the descriptor
 */
struct rpc_instance_s {
    /* Protect the instance */
    pthread_mutex_t lock;

    /* General settings */
    int timeout;
    bool reuse_sock;
    uint64_t gc_time;

    /* Single service */
    rpc_msg_handler handler;
    rpc_service server;
    /* Fast workers */
    sigset_t worker_sigmask;
    GThreadPool *workers;
    /* Slow worker and background task thread */
    GMainContext *slow_context;
    GMainLoop *slow_loop;
    GThread *slow_thread;
    int slow_count;
    /* Single threaded mode handler */
    int pollfd[2];
    GAsyncQueue *queue;
    uint32_t overflow;

    /* Clients */
    GHashTable *clients;
};

/* Garbage collection timer */
#define RPC_GC_TIMEOUT_US (10 * RPC_TIMEOUT_US)

/* Force test delay */
bool rpc_test_random_watch_delay = false;

/* Client object */
typedef struct rpc_client_t
{
    rpc_socket sock;
    uint32_t refcount;
    char *url;
    uint64_t timeout;
    int pid;
} rpc_client_t;

/* Message header */
#define RPC_HEADER_LENGTH (2 * sizeof (uint32_t))


/* Server work */
struct rpc_work_s {
    rpc_instance rpc;
    rpc_socket sock;
    rpc_id id;
    rpc_msg_handler handler;
    rpc_message_t msg;
    bool responded;
    GSourceFunc cb;
    gpointer data;
};

static void
work_destroy (gpointer data)
{
    struct rpc_work_s *work = (struct rpc_work_s *)data;
    if (!work->cb)
    {
        rpc_msg_reset (&work->msg);
        rpc_socket_deref (work->sock);
    }
    g_free (work);
}

static void
worker_func (struct rpc_work_s *work, sigset_t *sigmask)
{
    sigset_t oldmask;

    /* Process callbacks using the worker sigmask */
    if (sigmask)
        pthread_sigmask (SIG_SETMASK, sigmask, &oldmask);

    if (work && work->cb)
    {
        if (work->cb (work->data) == G_SOURCE_REMOVE)
            work_destroy (work);
    }
    else if (work)
    {
        rpc_socket sock = work->sock;
        rpc_msg_handler handler = work->handler;
        rpc_id id = work->id;
        rpc_message msg = &work->msg;

        /* TEST: force a delay here to change callback timing */
        if (rpc_test_random_watch_delay)
            usleep (rand() & RPC_TEST_DELAY_MASK);

        /* Process the callback */
        DEBUG ("RPC[%d]: processing message from "APTERYX_CLIENT_ID"\n", sock->sock, sock->ns, sock->pid);
        if (!handler (msg))
        {
            DEBUG ("RPC[%i]: handler failed\n", sock->sock);
            work_destroy (work);
            goto exit;
        }

        /* Send result */
        DEBUG ("RPC[%d]: sending %zd bytes\n", sock->sock, msg->length);
        if (!work->responded)
        {
            if (!msg->length)
            {
                msg->buffer = g_malloc0 (RPC_SOCKET_HDR_SIZE);
                msg->size = RPC_SOCKET_HDR_SIZE;
            }
            rpc_socket_send_response (sock, id, msg->buffer, msg->length);
        }
        work_destroy (work);
    }
exit:
    /* Restore the process sigmask */
    if (sigmask)
        pthread_sigmask (SIG_SETMASK, sigmask, &oldmask);
}

static gboolean
slow_callback_fn (gpointer arg1)
{
    struct rpc_work_s *work = (struct rpc_work_s *) arg1;
    rpc_instance rpc = work->rpc;

    /* Destroy GSource under the safety of the rpc lock */
    pthread_mutex_lock (&rpc->lock);
    GSource *source = g_main_context_find_source_by_funcs_user_data (rpc->slow_context, &g_timeout_funcs, (gpointer) work);
    if (source)
        g_source_destroy (source);
    pthread_mutex_unlock (&rpc->lock);

    /* Timeout callback but in single thread mode */
    if (rpc->queue)
    {
        uint8_t dummy = 0;
        g_async_queue_push (rpc->queue, (gpointer) work);
        if (write (rpc->pollfd[1], &dummy, 1) != 1)
        {
            g_atomic_int_inc (&rpc->overflow);
        }
    }
    else
        worker_func (arg1, &rpc->worker_sigmask);
    g_atomic_int_dec_and_test (&rpc->slow_count);
    return G_SOURCE_REMOVE;
}

static gpointer
slow_thread_fn (gpointer data)
{
    /* Block all signals */
    sigset_t set;
    sigfillset (&set);
    pthread_sigmask (SIG_BLOCK, &set, NULL);
    rpc_instance rpc = (rpc_instance) data;
    g_main_loop_run (rpc->slow_loop);
    g_main_loop_unref (rpc->slow_loop);
    rpc->slow_loop = NULL;
    g_main_context_unref (rpc->slow_context);
    rpc->slow_context = NULL;
    return NULL;
}

static void
submit_slow_work (rpc_instance rpc, struct rpc_work_s *work, guint timeout_ms)
{
    /* Start the slow worker thread on demand */
    if (!rpc->slow_loop)
    {
        rpc->slow_context = g_main_context_new ();
        rpc->slow_loop = g_main_loop_new (rpc->slow_context, FALSE);
        rpc->slow_thread = g_thread_new ("apteryx_slow", slow_thread_fn, (gpointer)rpc);
    }

    /* Pass to the slow worker thread either via a timeout or invoke directly */
    g_atomic_int_inc (&rpc->slow_count);
    if (timeout_ms)
    {
        /* Create a timeout callback on the slow worker thread */
        GSource *source = g_timeout_source_new (timeout_ms);
        g_source_set_priority (source, G_PRIORITY_DEFAULT);
        g_source_set_callback (source, slow_callback_fn, (gpointer) work, NULL);
        g_source_attach (source, rpc->slow_context);
        g_source_unref (source);
    }
    else
    {
        /* Pass the work to the slow worker thread */
        GSource *source;
        source = g_idle_source_new ();
        g_source_set_priority (source, G_PRIORITY_DEFAULT);
        g_source_set_callback (source, slow_callback_fn, work, NULL);
        g_source_attach (source, rpc->slow_context);
        g_source_unref (source);
    }
}

gpointer
rpc_add_callback (rpc_instance rpc, GSourceFunc cb, gpointer data, guint timeout_ms)
{
    struct rpc_work_s *work = (struct rpc_work_s *) g_malloc0 (sizeof(*work));
    assert (timeout_ms > 0);
    work->rpc = rpc;
    work->cb = cb;
    work->data = data;
    pthread_mutex_lock (&rpc->lock);
    submit_slow_work (rpc, work, timeout_ms);
    pthread_mutex_unlock (&rpc->lock);
    DEBUG ("RPC-CB[%p]: ADD callback with timeout %dms\n", work, timeout_ms);
    return (gpointer) work;
}

void
rpc_restart_callback (rpc_instance rpc, gpointer handle, guint timeout_ms)
{
    struct rpc_work_s *work = (struct rpc_work_s *) handle;
    GSource *source;

    pthread_mutex_lock (&rpc->lock);
    source = g_main_context_find_source_by_funcs_user_data (rpc->slow_context, &g_timeout_funcs, (gpointer) work);
    if (source && !g_source_is_destroyed (source))
    {
        DEBUG ("RPC-CB[%p]: RESTART callback with timeout %dms\n", work, timeout_ms);
        g_source_destroy (source);
        g_atomic_int_dec_and_test (&rpc->slow_count);
        submit_slow_work (rpc, work, timeout_ms);
    }
    else
    {
        DEBUG ("RPC-CB[%p]: RESTART - already completed sorry ...\n", work);
    }
    pthread_mutex_unlock (&rpc->lock);
}

void
rpc_cancel_callback (rpc_instance rpc, gpointer handle)
{
    struct rpc_work_s *work = (struct rpc_work_s *) handle;
    GSource *source;

    pthread_mutex_lock (&rpc->lock);
    source = g_main_context_find_source_by_funcs_user_data (rpc->slow_context, &g_timeout_funcs, (gpointer) work);
    if (source && !g_source_is_destroyed (source))
    {
        DEBUG ("RPC-CB[%p]: CANCEL callback\n", work);
        g_source_destroy (source);
        g_atomic_int_dec_and_test (&rpc->slow_count);
        work_destroy (work);
    }
    else
    {
        DEBUG ("RPC-CB[%p]: CANCEL - already completed sorry ...\n", work);
    }
    pthread_mutex_unlock (&rpc->lock);
}

static void
request_cb (rpc_socket sock, rpc_id id, void *buffer, size_t len)
{
    rpc_instance rpc;
    struct rpc_work_s *work;
    bool watch = false;

    DEBUG ("RPC[%d]: received %zd bytes\n", sock->sock, len);

    /* Get the rpc instance from the socket */
    rpc = (rpc_instance) rpc_socket_priv_get (sock);
    if (rpc == NULL || rpc->handler == NULL)
    {
        ERROR ("RPC[%i]: bad service (instance:%p)\n", sock->sock, rpc);
        return;
    }

    /* Store what we need to process this later */
    rpc_socket_ref (sock);
    work = g_malloc0 (sizeof(*work));
    work->rpc = rpc;
    work->sock = sock;
    work->id = id;
    work->handler = rpc->handler;
    work->responded = false;
    rpc_msg_push (&work->msg, len);
    memcpy (work->msg.buffer + work->msg.offset, buffer, len);
    work->msg.length = len;
    work->msg.ns = sock->ns;
    work->msg.pid = sock->pid;

    /* Sneak a peak to see if we can respond now */
    if (*(unsigned char*)buffer == MODE_WATCH)
    {
        DEBUG ("RPC[%i]: Early closure (no result required)\n", sock->sock);
        uint8_t *empty = g_malloc0 (RPC_SOCKET_HDR_SIZE);
        rpc_socket_send_response (sock, id, empty, 0);
        g_free (empty);
        work->responded = true;
    }

    /* Both variants of watch callbacks need to be processed on the same thread -
     * this is the single thread servicing the "slow workers".
     */
    if (*(unsigned char*)buffer == MODE_WATCH ||
        *(unsigned char*)buffer == MODE_WATCH_WITH_ACK)
    {
        watch = true;
    }

    /* Check if in polling mode first */
    if (rpc->queue)
    {
        uint8_t dummy = 0;
        g_async_queue_push (rpc->queue, (gpointer) work);
        if (write (rpc->pollfd[1], &dummy, 1) != 1)
        {
            g_atomic_int_inc (&rpc->overflow);
        }
    }
    /* Callbacks from local Apteryx threads */
    else if (watch || work->responded)
    {
        pthread_mutex_lock (&rpc->lock);
        submit_slow_work (rpc, work, 0);
        pthread_mutex_unlock (&rpc->lock);
    }
    else
    {
        if (!rpc->workers)
        {
            rpc->workers = g_thread_pool_new ((GFunc)worker_func, (gpointer)&rpc->worker_sigmask,
                                              8, FALSE, NULL);
        }
        g_thread_pool_push (rpc->workers, work, NULL);
    }
}

rpc_instance
rpc_init (int timeout, bool reuse_sock, rpc_msg_handler handler)
{
    assert (timeout > 0);

    /* Malloc memory for the new service */
    rpc_instance rpc = (rpc_instance) g_malloc0 (sizeof(*rpc));

    /* Create the server */
    rpc_service server = rpc_service_init (request_cb, rpc);
    if (server == NULL)
    {
        ERROR ("RPC: Failed to initialise server\n");
        g_free ((void*)rpc);
        return NULL;
    }

    /* Create a new RPC instance */
    pthread_mutex_init (&rpc->lock, NULL);
    pthread_sigmask (SIG_SETMASK, NULL, &rpc->worker_sigmask);
    rpc->timeout = timeout;
    rpc->reuse_sock = reuse_sock;
    rpc->gc_time = get_time_us ();
    rpc->handler = handler;
    rpc->server = server;
    rpc->clients = g_hash_table_new (g_str_hash, g_str_equal);

    DEBUG ("RPC: New Instance (%p)\n", rpc);
    return rpc;
}

static bool
destroy_rpc_client (gpointer key, gpointer value, gpointer rpc)
{
    rpc_client_t *client = (rpc_client_t *) value;

    DEBUG ("RPC: Destroy client to %s\n", (const char *)key);

    /* Release the socket and free the client */
    rpc_socket_deref (client->sock);
    g_free (client->url);
    g_free (client);
    g_free (key);

    return true;
}

static void
halt_client (gpointer _unused, gpointer _client, gpointer _also_unused)
{
    rpc_client_t *client = (rpc_client_t*)_client;

    if (client && client->sock && client->sock->thread)
    {
        pthread_cancel (client->sock->thread);
        pthread_join (client->sock->thread, NULL);
    }
}

void
rpc_halt (rpc_instance rpc)
{
    if (rpc)
    {
        pthread_mutex_lock (&rpc->lock);
        if (rpc->workers)
            g_thread_pool_set_max_threads (rpc->workers, 0, NULL);

        if (rpc->clients)
        {
            g_hash_table_foreach(rpc->clients, halt_client, NULL);
        }
        pthread_mutex_unlock (&rpc->lock);
    }
}

void
rpc_shutdown (rpc_instance rpc)
{
    int i;

    assert (rpc);

    DEBUG ("RPC: Shutdown Instance (%p)\n", rpc);

    /* Need to wait until all threads are cleaned up */
    if (rpc->workers)
    {
        for (i=0; i<10; i++)
        {
            g_thread_pool_stop_unused_threads ();
            if (g_thread_pool_unprocessed (rpc->workers) == 0 &&
                g_thread_pool_get_num_threads (rpc->workers) == 0 &&
                g_thread_pool_get_num_unused_threads () == 0)
            {
                break;
            }
            else if (i >= 9)
            {
                ERROR ("RPC: Worker threads not shutting down\n");
            }
            g_usleep (RPC_TIMEOUT_US / 10);
        }
        g_thread_pool_free (rpc->workers, FALSE, TRUE);
        rpc->workers = NULL;
    }
    if (rpc->slow_loop)
    {
        for (i=0; i<10; i++)
        {
            if (g_atomic_int_get(&rpc->slow_count) == 0)
            {
                break;
            }
            else if (i >= 9)
            {
                ERROR ("RPC: Slow thread not shutting down (%d more jobs)\n", g_atomic_int_get (&rpc->slow_count));
            }
            g_usleep (RPC_TIMEOUT_US / 10);
        }
        g_main_loop_quit (rpc->slow_loop);
        g_thread_join (rpc->slow_thread);
        rpc->slow_thread = NULL;
    }
    if (rpc->queue)
    {
        g_async_queue_unref (rpc->queue);
        rpc->queue = NULL;
    }

    /* Stop the server */
    rpc_service_die (rpc->server);

    /* Remove all clients */
    g_hash_table_foreach_remove (rpc->clients, (GHRFunc)destroy_rpc_client, rpc);
    g_hash_table_destroy (rpc->clients);
    rpc->clients = NULL;

    /* Free instance */
    g_free ((void*) rpc);
    rpc = NULL;
}

bool
rpc_server_bind (rpc_instance rpc, const char *guid, const char *url)
{
    assert (rpc);
    assert (url);

    /* Bind to the URL */
    return rpc_service_bind_url (rpc->server, guid, url);
}

bool
rpc_server_release (rpc_instance rpc, const char *guid)
{
    assert (rpc);
    assert (guid);

    /* Unbind from the URL */
    return rpc_service_unbind_url (rpc->server, guid);
}

int
rpc_server_process (rpc_instance rpc, bool poll)
{
    assert (rpc);
    int flags;
    int dummy = 0;

    /* Start polling if requested */
    if (poll && rpc->queue == NULL)
    {
        DEBUG ("RPC: Starting Polling mode\n");
        if (pipe (rpc->pollfd) < 0 ||
         (rpc->queue = g_async_queue_new_full (work_destroy)) == NULL)
        {
            ERROR ("RPC: Failed to enable poll mode\n");
            goto cleanup;
        }
        /* Write is non-blocking to avoid blocking apteryxd */
        flags = fcntl (rpc->pollfd[1], F_GETFL, 0);
        if (fcntl (rpc->pollfd[1], F_SETFL, flags | O_NONBLOCK) < 0)
        {
            ERROR ("RPC: Failed to set pipe nonblocking\n");
            goto cleanup;
        }
    }

    /* Check for work and process it if required */
    if (poll)
    {
        struct rpc_work_s *work = (struct rpc_work_s *) g_async_queue_try_pop (rpc->queue);
        if (work)
        {
            /* Process a single work job */
            DEBUG ("RPC: Polled processing...\n");
            worker_func (work, NULL);
        }
        else
        {
            DEBUG ("RPC: Polling. Nothing to process\n");
        }

        /* Check for overflow */
        if (g_atomic_int_get (&rpc->overflow) &&
            write (rpc->pollfd[1], &dummy, 1) == 1)
        {
            g_atomic_int_dec_and_test (&rpc->overflow);
        }

        /* Return the poll fd for the client to monitor */
        return rpc->pollfd[0];
    }

    /* Disable poll mode */
    DEBUG ("RPC: Stopping Polling mode\n");
cleanup:
    if (rpc->pollfd[0] != -1)
    {
        close (rpc->pollfd[0]);
        rpc->pollfd[0] = -1;
        close (rpc->pollfd[1]);
        rpc->pollfd[1] = -1;
    }
    if (rpc->queue)
    {
        g_async_queue_unref (rpc->queue);
        rpc->queue = NULL;
    }
    return -1;
}

static void
client_release (rpc_instance rpc, rpc_client_t *client, bool keep)
{
    bool done;

    /* Remove this client from the active list if requested */
    if (!keep)
    {
        rpc_client_t *existing = NULL;
        char *name = NULL;

        /* Make sure it is actually on the list */
        if (g_hash_table_lookup_extended (rpc->clients, client->url, (void **)&name, (void **)&existing)
                && existing == client)
        {
            DEBUG ("RPC[%d]: Abandon client to %s\n", client->sock ? client->sock->sock : -1, client->url);
            /* Release the client and remove it from the list */
            g_hash_table_remove (rpc->clients, client->url);
            g_free (name);
            client->refcount--;
        }
    }

    /* Release the client */
    done = (client->refcount <= 1);
    client->refcount--;
    if (done)
    {
        DEBUG ("RPC[%d]: Release client\n", client->sock ? client->sock->sock : -1);
        /* Release the socket and free the client */
        rpc_socket_deref (client->sock);
        g_free (client->url);
        g_free (client);
    }

    return;
}

static void
gc_clients (rpc_instance rpc)
{
    GHashTableIter hiter;
    const char *url;
    rpc_client_t *client;
    GList *dead = NULL;
    GList *iter = NULL;

    /* Minimum timeout between collections */
    if (get_time_us () > rpc->gc_time + RPC_GC_TIMEOUT_US)
    {
        /* Iterate over all clients */
        g_hash_table_iter_init (&hiter, rpc->clients);
        while (g_hash_table_iter_next (&hiter, (void **)&url, (void **)&client))
        {
            if (client->sock && client->sock->dead)
                dead = g_list_append (dead, client);
        }

        /* Cleanup any dead clients */
        for (iter = dead; iter; iter = g_list_next (iter))
        {
            client = (rpc_client_t *) iter->data;
            DEBUG ("RPC[%d]: Collecting dead socket for %s\n", client->sock->sock, client->url);
            if (client->refcount < 2)
                client_release (rpc, client, false);
        }
        g_list_free (dead);

        /* Wait another timeout */
        rpc->gc_time = get_time_us ();
    }
}

static rpc_client_t *
rpc_client_existing_s (rpc_instance rpc, const char *url)
{
    rpc_client_t *client = NULL;
    char *name = NULL;

    /* Garbage collect any stale clients */
    gc_clients (rpc);

    /* Find an existing client */
    if (g_hash_table_lookup_extended (rpc->clients, url, (void **)&name, (void **)&client))
    {
        /* Reference this client */
        client->refcount++;

        /* Check the attached socket is still valid */
        if (client->sock != NULL && !client->sock->dead && client->pid == getpid ())
        {
            /* This client will do */
            return client;
        }

        /* Otherwise chuck this one away and make another */
        DEBUG ("RPC[%d]: Pruning dead socket for %s\n", client->sock ? client->sock->sock : -1, url);
        client_release (rpc, client, false);
    }

    /* Find an existing connection to one of our servers */
    if (rpc->reuse_sock && rpc->server && rpc->server->servers)
    {
        for (GList *s = rpc->server->servers; s; s = s->next)
        {
            rpc_server server = (rpc_server) s->data;
            for (GList *c = server->clients; c; c = c->next)
            {
                rpc_socket sock = (rpc_socket) c->data;
                if (sock->dead)
                    continue;
                char *surl = g_strdup_printf ("%s."APTERYX_CLIENT_ID, server->url, sock->ns, sock->pid);
                DEBUG ("Compare client: %s to %s\n", url, surl);
                if (g_strcmp0 (url, surl) == 0)
                {
                    /* Create client */
                    client = g_malloc0 (sizeof (rpc_client_t));
                    client->sock = sock;
                    client->refcount = 1;
                    client->url = surl;
                    client->timeout = rpc->timeout;
                    client->pid = getpid ();
                    rpc_socket_ref (sock);

                    DEBUG ("RPC[%d]: Reuse client to %s\n", sock->sock, url);

                    /* Add it to the list of clients */
                    g_hash_table_insert (rpc->clients, g_strdup (url), client);

                    client->refcount++;
                    return client;
                }
                free (surl);
            }
        }
    }

    return NULL;
}

rpc_client
rpc_client_existing (rpc_instance rpc, const char *url)
{
    rpc_client_t *client = NULL;

    assert (rpc);
    assert (url);

    /* Protect the instance */
    pthread_mutex_lock (&rpc->lock);

    client = rpc_client_existing_s (rpc, url);

    /* Release the instance */
    pthread_mutex_unlock (&rpc->lock);
    return client;
}

rpc_client
rpc_client_connect (rpc_instance rpc, const char *url)
{
    rpc_client_t *client = NULL;

    assert (rpc);
    assert (url);

    /* Protect the instance */
    pthread_mutex_lock (&rpc->lock);

    client = rpc_client_existing_s (rpc, url);
    if (client)
    {
        /* Found a client */
        pthread_mutex_unlock (&rpc->lock);
        return client;
    }

    /* Catch old style client callbacks */
    if (rpc->reuse_sock && g_str_has_prefix (url, "unix:") && g_strcmp0 (url, apteryx_server_url()) != 0)
    {
        ERROR ("RPC: Client socket to %s has been lost!\n", url);
    }

    /* Create a new socket */
    rpc_socket sock = rpc_socket_connect_service (url, request_cb);
    if (sock == NULL)
    {
        ERROR ("RPC: Failed to create socket to %s\n", url);
        pthread_mutex_unlock (&rpc->lock);
        return NULL;
    }
    sock->priv = (void*)rpc;

    /* Create client */
    client = g_malloc0 (sizeof (rpc_client_t));
    if (!client)
    {
        ERROR ("RPC: Failed to allocate memory for client service\n");
        rpc_socket_deref (sock);
        pthread_mutex_unlock (&rpc->lock);
        return NULL;
    }
    client->sock = sock;
    client->refcount = 1;
    client->url = g_strdup (url);
    client->timeout = rpc->timeout;
    client->pid = getpid ();

    DEBUG ("RPC[%d]: New client to %s\n", sock->sock, url);

    /* Add it to the list of clients */
    g_hash_table_insert (rpc->clients, g_strdup (url), client);
    client->refcount++;

    /* Start processing this socket */
    if (!rpc_socket_process (sock))
    {
        ERROR ("RPC: Failed to start socket processing for client service\n");
        g_hash_table_remove (rpc->clients, client->url);
        g_free (client->url);
        g_free (client);
        rpc_socket_deref (sock);
        pthread_mutex_unlock (&rpc->lock);
        return NULL;
    }

    /* Release the instance */
    pthread_mutex_unlock (&rpc->lock);
    return client;
}

void
rpc_client_release (rpc_instance rpc, rpc_client client, bool keep)
{
    assert (rpc);
    assert (client);

    /* Protected release */
    pthread_mutex_lock (&rpc->lock);
    client_release (rpc, client, keep);
    pthread_mutex_unlock (&rpc->lock);
    return;
}

#define MSG_MINIMUM_MALLOC 1024

void
rpc_msg_reset (rpc_message msg)
{
    if (msg->size)
        g_free (msg->buffer);
    memset (msg, 0, sizeof (rpc_message_t));
}

void
rpc_msg_push (rpc_message msg, size_t len)
{
    /* Check if we need to (re)alloc */
    if (!msg->buffer || (msg->size - msg->offset) < len)
    {
        size_t size = RPC_SOCKET_HDR_SIZE + msg->length + len;
        size = size < MSG_MINIMUM_MALLOC ? MSG_MINIMUM_MALLOC : size;
        //DEBUG ("MSG: realloc(%zd/%zd)\n", len, size);
        msg->buffer = g_realloc (msg->buffer, size);
        msg->size = size;
    }
    msg->offset = msg->offset ?: RPC_SOCKET_HDR_SIZE;
}

void
rpc_msg_encode_uint8 (rpc_message msg, uint8_t value)
{
    int len = sizeof (uint8_t);
    rpc_msg_push (msg, len);
    *((uint8_t*)(msg->buffer + msg->offset)) = value;
    msg->length += len;
    msg->offset += len;
}

uint8_t
rpc_msg_decode_uint8 (rpc_message msg)
{
    int len = sizeof (uint8_t);
    if (((msg->length + RPC_SOCKET_HDR_SIZE)- msg->offset) < len)
        return 0;
    uint8_t value = (*((uint8_t*)(msg->buffer + msg->offset)));
    msg->offset += len;
    return value;
}

void
rpc_msg_encode_uint64 (rpc_message msg, uint64_t value)
{
    int len = sizeof (uint64_t);
    rpc_msg_push (msg, len);
    value = htobe64 (value);
    memcpy (((char*)msg->buffer) + msg->offset, &value, len);
    msg->length += len;
    msg->offset += len;
}

uint64_t
rpc_msg_decode_uint64 (rpc_message msg)
{
    int len = sizeof (uint64_t);
    if (((msg->length + RPC_SOCKET_HDR_SIZE) - msg->offset) < len)
        return 0;
    uint64_t value;
    memcpy (&value, ((char*)msg->buffer) + msg->offset, len);
    value = be64toh (value);
    msg->offset += len;
    return value;
}

void
rpc_msg_encode_string (rpc_message msg, const char *value)
{
    int len = strlen (value) + 1;
    rpc_msg_push (msg, len);
    memcpy (msg->buffer + msg->offset, value, len);
    msg->length += len;
    msg->offset += len;
    return;
}

char*
rpc_msg_decode_string (rpc_message msg)
{
    if (msg->offset >= (msg->length + RPC_SOCKET_HDR_SIZE))
        return NULL;
    char *value = (char *) (msg->buffer + msg->offset);
    msg->offset += strlen (value) + 1;
    return value;
}

static void rpc_msg_encode_tree_full (rpc_message msg, GNode *root, bool break_key);

static void
rpc_msg_add_children (rpc_message msg, GNode *root)
{
    GNode *child = NULL;

    /* If there are any children, write them here. */
    if (g_node_first_child (root))
    {
        rpc_msg_encode_uint8 (msg, rpc_start_children);
        for (child = g_node_last_child (root); child; child = g_node_prev_sibling (child))
        {
            rpc_msg_encode_tree_full (msg, child, true);
        }
        rpc_msg_encode_uint8 (msg, rpc_end_children);
    }
}

static void
rpc_msg_encode_tree_full (rpc_message msg, GNode *root, bool break_key)
{
    const char *key = APTERYX_NAME (root);
    const char *value = APTERYX_HAS_VALUE (root) ? APTERYX_VALUE (root) : NULL;

    if (break_key && strchr (key, '/'))
    {
        char *broken_key = g_strdup (key);
        char *end;
        char *chunk = broken_key;
        int extra_nodes = 0;

        while ((end = strchr (chunk, '/')) != NULL)
        {
            /* Truncate at the first slash */
            *end = '\0';

            /* This is an intermediate node, so we don't ever want to
             * print the value attached to the end, just the first bit of
             * the key.
             */
            rpc_msg_encode_uint8 (msg, rpc_value);
            rpc_msg_encode_string (msg, chunk);
            rpc_msg_encode_string (msg, "");

            /* We are going to need to close exactly this many children nodes
             * at the end of the loop, so keep count.
             */
            extra_nodes++;
            rpc_msg_encode_uint8 (msg, rpc_start_children);

            /* Skip past the null terminator */
            chunk = end + 1;
        }

        /* Write the end of the key and the value (if any.) */
        rpc_msg_encode_uint8 (msg, rpc_value);
        rpc_msg_encode_string (msg, chunk);
        rpc_msg_encode_string (msg, value ?: "");
        g_free (broken_key);

        /* If this node has no value, add its children. */
        if (!APTERYX_HAS_VALUE (root))
        {
            rpc_msg_add_children (msg, root);
        }

        /* Close all the children opened when breaking up the key */
        while (extra_nodes--)
        {
            rpc_msg_encode_uint8 (msg, rpc_end_children);
        }
    }
    else
    {
        rpc_msg_encode_uint8 (msg, rpc_value);
        /* Write this key (and value). */
        rpc_msg_encode_string (msg, key);
        rpc_msg_encode_string (msg, value ?: "");

        /* If this node has no value, add its children. */
        if (!APTERYX_HAS_VALUE (root))
        {
            rpc_msg_add_children (msg, root);
        }
    }
}

void
rpc_msg_encode_tree (rpc_message msg, GNode *root)
{
    rpc_msg_encode_tree_full (msg, root, false);
}

static GNode *
_rpc_msg_decode_tree (rpc_message msg, GNode *root)
{
    rpc_type_t type;
    char *key = NULL;
    const char *value = NULL;
    GNode *node = NULL;

    do
    {
        type = rpc_msg_decode_uint8 (msg);
        switch (type)
        {
            case rpc_value:
                key = rpc_msg_decode_string (msg);
                value = rpc_msg_decode_string (msg);

                if (!root)
                {
                    /* Find the leading part of this path. Sometimes these nodes
                     * can be a compound path (root key = /test/a/b/c) and they need
                     * to be broken up into root + value.
                     */
                    gchar *path = g_strdup (key);
                    key = strrchr(path, '/');
                    if (key)
                    {
                        *key = '\0';
                        key++;
                    }

                    /* Actually create the root node. */
                    root = APTERYX_NODE (NULL, path);

                    /* Add null value - this may be superceded later */
                    g_node_prepend_data(root, NULL);
                }

                if (value && value[0])
                {
                    /* If we've got a value, remove the temp NULL entry */
                    GNode *temp_leaf = g_node_first_child(root);
                    if (temp_leaf && temp_leaf->data == NULL)
                    {
                        g_node_destroy(temp_leaf);
                    }
                    APTERYX_LEAF (root, g_strdup (key), g_strdup (value));
                }
                else if (key)
                {
                    /* If we've got a node below, remove the temp NULL entry */
                    GNode *temp_leaf = g_node_first_child(root);
                    if (temp_leaf && temp_leaf->data == NULL)
                    {
                        g_node_destroy(temp_leaf);
                    }

                    /* Add this node, and a terminating leaf */
                    node = g_node_prepend_data(root, g_strdup (key));
                    g_node_prepend_data(node, NULL);
                }
                else
                {
                    /* If this is a short root, we don't need anything hanging off
                     * below it.
                     */
                    node = root;
                }

                break;
            case rpc_start_children:
                /* This node has children (which are also a tree). */
                _rpc_msg_decode_tree (msg, node ?: root);
                break;
            case rpc_end_children:
            default:
            case rpc_done:
                return root;
        }
    } while (type != rpc_end_children);

    return root;
}

GNode *
rpc_msg_decode_tree (rpc_message msg)
{
    GNode *root = _rpc_msg_decode_tree (msg, NULL);

    /* We might have a tree with an exploded root - collapse it
     * as much as we can.
     */
    while (root &&
           !APTERYX_HAS_VALUE (root) &&
           g_node_n_children (root) == 1)
    {
        /* This node has no value and only one child, so we can
         * squish it into the child.
         */
        GNode *child = g_node_first_child (root);
        gchar *compressed_path = g_strdup_printf ("%s/%s", APTERYX_NAME (root), APTERYX_NAME (child));
        g_free (child->data);
        child->data = compressed_path;
        g_node_unlink (child);
        g_free (root->data);
        g_node_destroy (root);
        root = child;
    }

    return root;
}

bool
rpc_msg_send (rpc_client client, rpc_message msg)
{
    void *buffer = NULL;
    size_t length = 0;
    bool rc = true;

    /* Send the message */
    DEBUG ("RPC[%d]: sending %zd bytes\n", client->sock->sock, msg->length);
    rpc_id id = rpc_socket_send_request (client->sock, msg->buffer, msg->length);
    if (id == 0)
    {
        errno = -ETIMEDOUT;
        rc = false;
        goto error;
    }

    /* Wait for response */
    rpc_msg_reset (msg);
    DEBUG ("RPC[%d]: waiting for response\n", client->sock->sock);
    if (!rpc_socket_recv (client->sock, id, (void **) &buffer, &length, client->timeout))
    {
        errno = -ETIMEDOUT;
        rc = false;
        goto error;
    }
    rpc_msg_push (msg, length);
    memcpy (msg->buffer + msg->offset, buffer, length);
    msg->length = length;
    DEBUG ("RPC[%d]: received %zd bytes\n", client->sock->sock, msg->length);
    free (buffer);

error:
    return rc;
}

void
rpc_msg_free (rpc_message msg)
{
    g_free (msg->buffer);
    g_free (msg);
}
