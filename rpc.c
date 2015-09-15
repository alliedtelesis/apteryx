#include "internal.h"

#include <errno.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include "apteryx.pb-c.h"

#include "rpc_transport.h"

static rpc_service Service;
static GHashTable *connection_cache = NULL;
static pthread_mutex_t connection_cache_lock = PTHREAD_MUTEX_INITIALIZER; /* Protect globals */

/* Message header */
#define RPC_HEADER_LENGTH (2 * sizeof (uint32_t))
typedef struct rpc_message_t
{
    rpc_socket sock;
    rpc_id id;
    uint32_t method_index;
    uint32_t message_length;
} rpc_message_t;

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

__thread rpc_socket this_sock = NULL;

rpc_socket
rpc_socket_current ()
{
    return this_sock;
}

void
rpc_socket_current_set (rpc_socket sock)
{
    this_sock = sock;
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

    msg->message_length = protobuf_c_message_get_packed_size (message);
    pack_header (msg, &buf[RPC_SOCKET_HDR_SIZE]);
    buffer.base.append ((ProtobufCBuffer *)&buffer, RPC_SOCKET_HDR_SIZE + RPC_HEADER_LENGTH, buf);
    if (protobuf_c_message_pack_to_buffer (message, (ProtobufCBuffer *)&buffer)
            != msg->message_length)
    {
        ERROR ("RPC[%d]: error serializing the response\n", sock->sock);
        return;
    }

    rpc_socket_send_response (sock, msg->id, buffer.data, buffer.len - RPC_SOCKET_HDR_SIZE);
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&buffer);
    return;
}

static GThreadPool *rpc_workers = NULL;
struct rpc_work_s {
    ProtobufCService *service;
    rpc_message_t msg;
    ProtobufCMessage *message;
};

static void
worker_func (gpointer a, gpointer b)
{
    struct rpc_work_s *work = (struct rpc_work_s *)a;
    if (work)
    {
        rpc_socket_current_set (work->msg.sock);
        /* Invoke service (note that it may call back immediately) */
        work->service->invoke (work->service, work->msg.method_index, work->message,
                               server_connection_response_closure, (void*)&work->msg);

        if (work->message)
        {
            protobuf_c_message_free_unpacked (work->message, NULL);
        }

        rpc_socket_deref (work->msg.sock);
        free (work);
    }
}

bool
rpc_init ()
{
    if (!rpc_workers)
    {
        rpc_workers = g_thread_pool_new ((GFunc)worker_func, NULL, 8, false, NULL);
    }
    return true;
}

void
request_cb (rpc_socket sock, rpc_id id, void *data, size_t len)
{
    ProtobufCService *service = (ProtobufCService *)
                                rpc_service_priv_get (
                                    rpc_server_parent_get (rpc_socket_parent_get (sock)));

    if (service == NULL)
    {
        service = (ProtobufCService *) rpc_socket_priv_get (sock);
    }

    uint8_t buffer_slab[512];
    ProtobufCBufferSimple buffer = PROTOBUF_C_BUFFER_SIMPLE_INIT (buffer_slab);

    buffer.base.append ((ProtobufCBuffer*)&buffer, len, data);

    struct rpc_work_s *work = calloc (1, sizeof(*work));
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

    g_thread_pool_push (rpc_workers, work, NULL);

    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&buffer);

    return;

error:
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&buffer);
    free (work);
    rpc_socket_deref (sock);
    return;
}

bool rpc_provide_service (const char *url, ProtobufCService *service, int stopfd)
{
    rpc_service s = rpc_service_init (request_cb, service);

    Service = s;

    /* Create a thread for the default port */
    rpc_bind_url (url, url);

    rpc_service_run (s, stopfd);

    Service = NULL;
    /* Stop all of the servers */
    rpc_service_die (s);
    return true;
}

bool rpc_bind_url (const char *guid, const char *url)
{
    return rpc_service_bind_url (Service, guid, url);
}

bool rpc_unbind_url (const char *guid, const char *url)
{
    return rpc_service_unbind_url (Service, guid);
}


typedef struct rpc_client_t
{
    ProtobufCService service;
    rpc_socket sock;
    pthread_mutex_t lock;
    uint32_t refcount;
} rpc_client_t;

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
    free (data);
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
destroy_client_service (ProtobufCService *service)
{
    rpc_client_t *client = (rpc_client_t *)service;
    DEBUG ("RPC: destroy_client_service\n");
    rpc_socket_deref (client->sock);
    pthread_mutex_lock (&client->lock);
    assert (client->refcount == 0);
    pthread_mutex_unlock (&client->lock);
    free (client);
}

ProtobufCService *
rpc_connect_service (const char *url, const ProtobufCServiceDescriptor *descriptor, const ProtobufCService *service)
{
    rpc_socket sock = rpc_socket_connect_service (url, request_cb);

    if (sock == NULL)
    {
        ERROR ("RPC: Failed to create socket to %s\n", url);
        return NULL;
    }

    rpc_client_t *client;

    /* Create client */
    client = calloc (1, sizeof (rpc_client_t));
    if (!client)
    {
        ERROR ("RPC: Failed to allocate memory for client service\n");
        rpc_socket_deref (sock);
        return NULL;
    }
    client->service.descriptor = descriptor;
    client->service.invoke = invoke_client_service;
    client->service.destroy = destroy_client_service;
    client->sock = sock;
    sock->priv = (void *)service;
    pthread_mutex_init (&client->lock, NULL);
    client->refcount = 1;

    return (ProtobufCService *)client;
}

ProtobufCService *
rpc_connect_service_sock (rpc_socket sock, const ProtobufCServiceDescriptor *descriptor)
{
    if (!sock || sock->dead)
    {
        return NULL;
    }

    /* Create client */
    rpc_client_t *client = calloc (1, sizeof (rpc_client_t));
    if (!client)
    {
        ERROR ("RPC: Failed to allocate memory for client service\n");
        return NULL;
    }
    client->service.descriptor = descriptor;
    client->service.invoke = invoke_client_service;
    client->service.destroy = destroy_client_service;
    client->sock = sock;
    rpc_socket_ref (sock);
    pthread_mutex_init (&client->lock, NULL);
    client->refcount = 1;
    return (ProtobufCService *)client;
}

void
rpc_connect_ref (ProtobufCService *service)
{
    rpc_client_t *client = (rpc_client_t *) service;
    pthread_mutex_lock (&client->lock);
    client->refcount++;
    pthread_mutex_unlock (&client->lock);
}

void
rpc_connect_deref (ProtobufCService *service)
{
    rpc_client_t *client = (rpc_client_t *) service;
    pthread_mutex_lock (&client->lock);
    client->refcount--;
    bool done = (client->refcount == 0);
    pthread_mutex_unlock (&client->lock);
    if (done)
    {
        destroy_client_service (service);
    }
}

ProtobufCService *
rpc_client_get_service (const char *url, const ProtobufCService *service)
{
    if (url == NULL)
    {
        return NULL;
    }
    pthread_mutex_lock (&connection_cache_lock);
    if (connection_cache == NULL)
    {
        connection_cache = g_hash_table_new (g_str_hash, g_str_equal);
    }
    ProtobufCService *rpc_client = (ProtobufCService *) g_hash_table_lookup (connection_cache, url);
    if (!rpc_client)
    {
        rpc_client = rpc_connect_service (url, &apteryx__server__descriptor, service);
        if (rpc_client)
        {
            g_hash_table_insert (connection_cache, strdup (url), rpc_client);
        }
    }
    pthread_mutex_unlock (&connection_cache_lock);

    if (rpc_client)
    {
        rpc_connect_ref (rpc_client);
    }

    return rpc_client;
}

ProtobufCService *
rpc_client_get (const char *url)
{
    return rpc_client_get_service (url, NULL);
}

void
rpc_client_abandon (const char *url)
{
    if (url == NULL || connection_cache == NULL)
    {
        return;
    }
    char *name = NULL;
    ProtobufCService *rpc_client = NULL;

    pthread_mutex_lock (&connection_cache_lock);
    if (g_hash_table_lookup_extended (connection_cache, url, (void **)&name, (void **)&rpc_client))
    {
        g_hash_table_remove (connection_cache, url);
        free (name);
        rpc_connect_deref (rpc_client);
    }
    pthread_mutex_unlock (&connection_cache_lock);

    return;
}

bool
remove_rpc_client (gpointer key, gpointer value, gpointer empty)
{
    ProtobufCService * service = (ProtobufCService *) value;
    if (service)
    {
        rpc_connect_deref (service);
    }
    if (key)
    {
        free (key);
    }

    return true;
}

void
rpc_client_shutdown ()
{
    pthread_mutex_lock (&connection_cache_lock);
    if (connection_cache)
    {
        g_hash_table_foreach_remove (connection_cache, (GHRFunc)remove_rpc_client, NULL);
    }
    pthread_mutex_unlock (&connection_cache_lock);
}
