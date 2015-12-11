/**
 * @file rpc.c
 * RPC implementation for for Apteryx.
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
#include "rpc_transport.h"

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
    ProtobufCService *service;
    rpc_service server;
    GThreadPool *workers;
    int pollfd[2];
    GAsyncQueue *queue;

    /* Clients */
    const ProtobufCServiceDescriptor *descriptor;
    GHashTable *clients;
};

/* Garbage collection timer */
#define RPC_GC_TIMEOUT_US (10 * RPC_TIMEOUT_US)

/* Client object */
typedef struct rpc_client_t
{
    ProtobufCService service;
    rpc_socket sock;
    uint32_t refcount;
    char *url;
} rpc_client_t;

/* Message header */
#define RPC_HEADER_LENGTH (2 * sizeof (uint32_t))
typedef struct rpc_message_t
{
    rpc_socket sock;
    rpc_id id;
    uint32_t method_index;
    uint32_t message_length;
} rpc_message_t;

/* Server work */
struct rpc_work_s {
    ProtobufCService *service;
    rpc_message_t msg;
    ProtobufCMessage *message;
};

static inline void unpack_header (unsigned char *b, rpc_message_t *h)
{
    h->method_index = (ltoh32 (((uint32_t*)b)[0]));
    h->message_length = (ltoh32 (((uint32_t*)b)[1]));
}

static inline void pack_header (rpc_message_t *h, unsigned char *b)
{
    ((uint32_t*)b)[0] = htol32(h->method_index);
    ((uint32_t*)b)[1] = htol32(h->message_length);
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
    uint8_t buffer_slab[512] = {};
    ProtobufCBufferSimple tx_buffer = PROTOBUF_C_BUFFER_SIMPLE_INIT (buffer_slab);
    ProtobufCBufferSimple rx_buffer = PROTOBUF_C_BUFFER_SIMPLE_INIT (buffer_slab);

    /* Serialise the message */
    msg.method_index = method_index;
    msg.message_length = protobuf_c_message_get_packed_size (input);
    pack_header (&msg, &buffer_slab[RPC_SOCKET_HDR_SIZE]);
    tx_buffer.len = RPC_HEADER_LENGTH + RPC_SOCKET_HDR_SIZE;
    if (protobuf_c_message_pack_to_buffer (input, (ProtobufCBuffer *)&tx_buffer)
            != msg.message_length)
    {
        ERROR ("RPC[%d]: error serializing the response\n", client->sock->sock);
        closure (NULL, closure_data);
        PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&tx_buffer);
        return;
    }

    DEBUG ("RPC[%i]: (invoke client) Method=%d Length=%d\n", client->sock->sock,
            msg.method_index, msg.message_length);

    /* Send the message */
    rpc_id id = rpc_socket_send_request (client->sock, tx_buffer.data, tx_buffer.len - RPC_SOCKET_HDR_SIZE);
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&tx_buffer);

    if (id == 0)
    {
        goto error;
    }

    /* Wait for response */
    DEBUG ("RPC[%d]: waiting for response\n", client->sock->sock);
    void *data = NULL;
    size_t len = 0;
    if (!rpc_socket_recv (client->sock, id, &data, &len, RPC_TIMEOUT_US))
    {
        goto error;
    }

    rx_buffer.base.append ((ProtobufCBuffer*)&rx_buffer, len, data);
    g_free (data);
    unpack_header (rx_buffer.data, &msg);

    /* Unpack message */
    const ProtobufCMethodDescriptor *method = service->descriptor->methods + method_index;
    const ProtobufCMessageDescriptor *desc = method->output;
    ProtobufCMessage *message = NULL;
    if (msg.message_length > 0)
    {
        DEBUG ("RPC[%d]: unpacking response\n", client->sock->sock);
        message = protobuf_c_message_unpack (desc, NULL,
                msg.message_length, rx_buffer.data+RPC_HEADER_LENGTH);
    }
    else
    {
        DEBUG ("RPC[%d]: empty response\n", client->sock->sock);
        message = protobuf_c_message_unpack (desc, NULL, 0, NULL);
    }

    /* Return result */
    closure (message, closure_data);
    if (message)
        protobuf_c_message_free_unpacked (message, NULL);
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&rx_buffer);
    return;

error:
    closure (NULL, closure_data);
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&rx_buffer);
    return;
}

static void
server_connection_response_closure (const ProtobufCMessage *message,
        void *closure_data)
{
    rpc_message_t *msg = (rpc_message_t *)closure_data;
    rpc_socket sock = msg->sock;
    uint8_t buffer_slab[512];
    ProtobufCBufferSimple buffer  = PROTOBUF_C_BUFFER_SIMPLE_INIT (buffer_slab);
    uint8_t buf[RPC_SOCKET_HDR_SIZE + RPC_HEADER_LENGTH] = {0}; //TEMP - stupid status

    DEBUG ("RPC[%d]: Closure\n", sock->sock);

    msg->message_length = message ? protobuf_c_message_get_packed_size (message) : 0;
    pack_header (msg, &buf[RPC_SOCKET_HDR_SIZE]);
    buffer.base.append ((ProtobufCBuffer *)&buffer, RPC_SOCKET_HDR_SIZE + RPC_HEADER_LENGTH, buf);
    if (msg->message_length &&
        protobuf_c_message_pack_to_buffer (message, (ProtobufCBuffer *)&buffer)
                            != msg->message_length)
    {
        ERROR ("RPC[%d]: error serializing the response\n", sock->sock);
        return;
    }

    rpc_socket_send_response (sock, msg->id, buffer.data, buffer.len - RPC_SOCKET_HDR_SIZE);
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&buffer);
    return;
}

static void
work_destroy (gpointer data)
{
    struct rpc_work_s *work = (struct rpc_work_s *)data;
    if (work->message)
        protobuf_c_message_free_unpacked (work->message, NULL);
    rpc_socket_deref (work->msg.sock);
    g_free (work);
}

static void
worker_func (gpointer a, gpointer b)
{
    struct rpc_work_s *work = (struct rpc_work_s *)a;
    if (work)
    {
        /* Invoke service (note that it may call back immediately) */
        work->service->invoke (work->service, work->msg.method_index, work->message,
                               server_connection_response_closure, (void*)&work->msg);
        work_destroy (a);
    }
}

static void
request_cb (rpc_socket sock, rpc_id id, void *data, size_t len)
{
    ProtobufCService *service;
    rpc_instance rpc = (rpc_instance) rpc_socket_priv_get (sock);
    if (rpc == NULL || rpc->service == NULL)
    {
        ERROR ("RPC: bad service (skt:%p instance:%p)\n", sock, rpc);
        return;
    }
    service = rpc->service;

    uint8_t buffer_slab[512];
    ProtobufCBufferSimple buffer = PROTOBUF_C_BUFFER_SIMPLE_INIT (buffer_slab);

    buffer.base.append ((ProtobufCBuffer*)&buffer, len, data);

    struct rpc_work_s *work = g_malloc0 (sizeof(*work));
    work->service = service;

    const ProtobufCMessageDescriptor *desc = NULL;

    work->msg.sock = sock;
    rpc_socket_ref (sock);
    work->msg.id = id;
    unpack_header (buffer.data, &work->msg);

    DEBUG ("RPC[%i]: (request) Method=%d Length=%zd\n", sock->sock,
            work->msg.method_index, len);

    if (work->msg.method_index >= service->descriptor->n_methods)
    {
        ERROR ("RPC: bad method_index %u\n", work->msg.method_index);
        goto error;
    }

    desc = service->descriptor->methods[work->msg.method_index].input;
    work->message = protobuf_c_message_unpack (desc, NULL, work->msg.message_length,
            (const uint8_t *)buffer.data + RPC_HEADER_LENGTH);
    if (work->message == NULL)
    {
        ERROR ("RPC: unable to unpack message (%d)\n", work->msg.method_index);
        goto error;
    }

    /* Check for methods that require no result */
    desc = service->descriptor->methods[work->msg.method_index].output;
    if (desc->n_fields == 0)
    {
        DEBUG ("RPC[%i]: Early closure (no result required)\n", sock->sock);
        server_connection_response_closure (NULL, (void*)&work->msg);
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
    else if (rpc->workers)
        g_thread_pool_push (rpc->workers, work, NULL);
    else
        goto error;

    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&buffer);
    return;

error:
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&buffer);
    if (work)
    {
        if (work->message)
            protobuf_c_message_free_unpacked (work->message, NULL);
        g_free (work);
    }
    rpc_socket_deref (sock);
    return;
}

rpc_instance
rpc_init (ProtobufCService *service, const ProtobufCServiceDescriptor *descriptor, int timeout)
{
    assert (descriptor);
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
    rpc->service = service;
    rpc->server = server;
    rpc->descriptor = descriptor;
    rpc->clients = g_hash_table_new (g_str_hash, g_str_equal);
    rpc->workers = g_thread_pool_new ((GFunc)worker_func, NULL, 8, FALSE, NULL);

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
            g_thread_pool_get_num_unused_threads () == 0)
        {
            break;
        }
        else if (i >= 9)
        {
            ERROR ("RPC: Worker threads not shutting down\n");
        }
        g_usleep (G_USEC_PER_SEC / 10);
    }
    g_thread_pool_free (rpc->workers, FALSE, TRUE);
    rpc->workers = NULL;

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
            DEBUG ("RPC[%d]: Abandon client to %s\n", client->sock->sock, client->url);
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
        DEBUG ("RPC[%d]: Release client\n", client->sock->sock);
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
            else
                client->refcount--;
        }
        g_list_free (dead);

        /* Wait another timeout */
        rpc->gc_time = get_time_us ();
    }
}

ProtobufCService *
rpc_client_connect (rpc_instance rpc, const char *url)
{
    rpc_client_t *client = NULL;
    char *name = NULL;

    assert (rpc);
    assert (url);

    /* Protect the instance */
    pthread_mutex_lock (&rpc->lock);

    /* Garbage collect any stale clients */
    gc_clients (rpc);

    /* Find an existing client */
    if (g_hash_table_lookup_extended (rpc->clients, url, (void **)&name, (void **)&client))
    {
        /* Reference this client */
        client->refcount++;

        /* Check the attached socket is still valid */
        if (client->sock != NULL && !client->sock->dead)
        {
            /* This client will do */
            pthread_mutex_unlock (&rpc->lock);
            return (ProtobufCService *)client;
        }

        /* Otherwise chuck this one away and make another */
        DEBUG ("RPC[%d]: Pruning dead socket for %s\n", client->sock->sock, url);
        client_release (rpc, client, false);
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
    client->service.descriptor = rpc->descriptor;
    client->service.invoke = invoke_client_service;
    client->sock = sock;
    client->refcount = 1;
    client->url = g_strdup (url);

    DEBUG ("RPC[%d]: New client to %s\n", sock->sock, url);

    /* Add it to the list of clients */
    g_hash_table_insert (rpc->clients, g_strdup (url), client);
    client->refcount++;

    /* Start processing this socket */
    rpc_socket_process (sock);

    /* Release the instance */
    pthread_mutex_unlock (&rpc->lock);
    return (ProtobufCService *)client;
}

void
rpc_client_release (rpc_instance rpc, ProtobufCService *service, bool keep)
{
    assert (rpc);
    assert (service);

    /* Protected release */
    pthread_mutex_lock (&rpc->lock);
    client_release (rpc, (rpc_client_t *)service, keep);
    pthread_mutex_unlock (&rpc->lock);
    return;
}
