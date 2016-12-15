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
    uint64_t gc_time;

    /* Single service */
    rpc_msg_handler handler;
    rpc_service server;
    GThreadPool *workers;
    GThreadPool *slow_workers;
    int pollfd[2];
    GAsyncQueue *queue;

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
    rpc_socket sock;
    rpc_id id;
    rpc_msg_handler handler;
    rpc_message_t msg;
    bool responded;
};

static void
work_destroy (gpointer data)
{
    struct rpc_work_s *work = (struct rpc_work_s *)data;
    rpc_msg_reset (&work->msg);
    rpc_socket_deref (work->sock);
    g_free (work);
}

static void
worker_func (gpointer a, gpointer b)
{
    struct rpc_work_s *work = (struct rpc_work_s *)a;
    if (work)
    {
        rpc_socket sock = work->sock;
        rpc_msg_handler handler = work->handler;
        rpc_id id = work->id;
        rpc_message msg = &work->msg;

        /* TEST: force a delay here to change callback timing */
        if (rpc_test_random_watch_delay)
            usleep (rand() & RPC_TEST_DELAY_MASK);

        /* Process the callback */
        DEBUG ("RPC[%d]: processing message\n", sock->sock);
        if (!handler (msg))
        {
            ERROR ("RPC[%i]: handler failed\n", sock->sock);
            work_destroy (work);
            return;
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
}

static void
request_cb (rpc_socket sock, rpc_id id, void *buffer, size_t len)
{
    rpc_instance rpc;
    struct rpc_work_s *work;

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
    work->sock = sock;
    work->id = id;
    work->handler = rpc->handler;
    work->responded = false;
    rpc_msg_push (&work->msg, len);
    memcpy (work->msg.buffer + work->msg.offset, buffer, len);
    work->msg.length = len;

    /* Sneak a peak to see if we can respond now */
    if (*(unsigned char*)buffer == MODE_WATCH)
    {
        DEBUG ("RPC[%i]: Early closure (no result required)\n", sock->sock);
        uint8_t *empty = g_malloc0 (RPC_SOCKET_HDR_SIZE);
        rpc_socket_send_response (sock, id, empty, 0);
        g_free (empty);
        work->responded = true;
    }

    /* Check if in polling mode first */
    if (rpc->queue)
    {
        uint8_t dummy = 0;
        g_async_queue_push (rpc->queue, (gpointer) work);
        if (write (rpc->pollfd[1], &dummy, 1) != 1)
        {
            ERROR ("RPC: Unable to signal client\n");
        }
    }
    /* Callbacks from local Apteryx threads */
    else if (rpc->workers && work->responded)
        g_thread_pool_push (rpc->slow_workers, work, NULL);
    else if (rpc->workers)
        g_thread_pool_push (rpc->workers, work, NULL);
    else
        goto error;

    return;

error:
    if (work)
    {
        g_free (work);
    }
    rpc_socket_deref (sock);
    return;
}

rpc_instance
rpc_init (int timeout, rpc_msg_handler handler)
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
    rpc->timeout = timeout;
    rpc->gc_time = get_time_us ();
    rpc->handler = handler;
    rpc->server = server;
    rpc->clients = g_hash_table_new (g_str_hash, g_str_equal);
    rpc->workers = g_thread_pool_new ((GFunc)worker_func, NULL, 8, FALSE, NULL);
    rpc->slow_workers = g_thread_pool_new ((GFunc)worker_func, NULL, 1, FALSE, NULL);

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

void
rpc_shutdown (rpc_instance rpc)
{
    int i;

    assert (rpc);

    DEBUG ("RPC: Shutdown Instance (%p)\n", rpc);

    /* Need to wait until all threads are cleaned up */
    for (i=0; i<10; i++)
    {
        g_thread_pool_stop_unused_threads ();
        if (g_thread_pool_unprocessed (rpc->workers) == 0 &&
            g_thread_pool_get_num_threads (rpc->workers) == 0 &&
            g_thread_pool_unprocessed (rpc->slow_workers) == 0 &&
            g_thread_pool_get_num_threads (rpc->slow_workers) == 0 &&
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
    g_thread_pool_free (rpc->slow_workers, FALSE, TRUE);
    rpc->slow_workers = NULL;
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

    /* Free instance */
    g_free ((void*) rpc);
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
    }

    /* Check for work and process it if required */
    if (poll)
    {
        gpointer *work = g_async_queue_try_pop (rpc->queue);
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
    rpc_socket_process (sock);

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
    *((uint64_t*)(msg->buffer + msg->offset)) = htobe64 (value);
    msg->length += len;
    msg->offset += len;
}

uint64_t
rpc_msg_decode_uint64 (rpc_message msg)
{
    int len = sizeof (uint64_t);
    if (((msg->length + RPC_SOCKET_HDR_SIZE) - msg->offset) < len)
        return 0;
    uint64_t value = be64toh (*((uint64_t*)(msg->buffer + msg->offset)));
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
