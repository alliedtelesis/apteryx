/**
 * @file apteryx.c
 * API for configuration and state shared between Apteryx processes.
 * Features:
 * - A simple path:value database.
 * - Tree like structure with each node being a value.
 * - Path specified in directory format (e.g. /root/node1/node2).
 * - Searching for nodes children requires substring search of the path.
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
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <semaphore.h>
#include <errno.h>
#include "internal.h"
#include "apteryx.pb-c.h"
#include "apteryx.h"

/* Configuration */
bool debug = false;                      /* Debug enabled */
static int ref_count = 0;               /* Library reference count */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; /* Protect globals */
static int stopfd = -1;                 /* Used to stop the RPC server service */
static pthread_t client_id = 0;        /* Thread to process Apteryx events */
static pthread_t worker_id = 0;        /* Worker to handle watch callbacks */
static GList *pending_watches = NULL;   /* List of watches to process */
static sem_t wake_worker;               /* How we wake up the watch callback handler */
static volatile bool client_running = false;
static volatile bool worker_running = false;

/* Callback */
typedef struct _cb_info_t
{
    apteryx_watch_callback cb;
    const char *path;
    void *priv;
    unsigned char *value;
    size_t size;
} cb_info_t;

static void
cb_info_destroy (gpointer data)
{
    cb_info_t *info = (cb_info_t*)data;
    free ((void *) info->path);
    free ((void *) info->value);
    free (info);
}

static gpointer
cb_info_create (const Apteryx__Watch *watch)
{
    cb_info_t *info = calloc (1, sizeof (cb_info_t));
    info->cb = (apteryx_watch_callback) (long) watch->cb;
    info->path = strdup (watch->path);
    info->priv = (void *) (long) watch->priv;
    if (watch->value.len)
    {
        info->size = watch->value.len;
        info->value = malloc (info->size);
        memcpy (info->value, watch->value.data, info->size);
    }
    return (gpointer)info;
}

/* Callback for watched items */
static void
apteryx__watch (Apteryx__Client_Service *service,
                const Apteryx__Watch *watch,
                Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    (void) service;

    DEBUG ("WATCH CB \"%s\" = \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
           watch->path, bytes_to_string (watch->value.data, watch->value.len),
           watch->id, watch->cb, watch->priv);

    /* Queue the callback for processing */
    pthread_mutex_lock (&lock);
    if (pending_watches == NULL)
        sem_post (&wake_worker);
    pending_watches = g_list_append (pending_watches, cb_info_create (watch));
    pthread_mutex_unlock (&lock);

    /* Return result */
    closure (&result, closure_data);
    return;
}

/* Callback for provided items */
static void
apteryx__provide (Apteryx__Client_Service *service,
                  const Apteryx__Provide *provide,
                  Apteryx__GetResult_Closure closure, void *closure_data)
{
    Apteryx__GetResult result = APTERYX__GET_RESULT__INIT;
    apteryx_provide_callback cb = (apteryx_provide_callback) (long) provide->cb;
    unsigned char *value = NULL;
    size_t vsize = 0;
    (void) service;

    DEBUG ("PROVIDE CB: \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
           provide->path, provide->id, provide->cb, provide->priv);

    /* Call the callback */
    if (cb)
        cb (provide->path, (void *) (long) provide->priv, &value, &vsize);

    /* Return result */
    result.value.data = value;
    result.value.len = vsize;
    closure (&result, closure_data);
    if (value)
        free (value);
    return;
}

static void*
worker_thread (void *data)
{
    GList *pending, *iter;

    /* Process callbacks while the client thread is running */
    DEBUG ("Worker Thread: started...\n");
    worker_running = true;
    while (worker_running)
    {
        /* Wait for some work */
        sem_wait (&wake_worker);
        if (!worker_running)
            break;

        /* Dequeue the work */
        pthread_mutex_lock (&lock);
        pending = pending_watches;
        pending_watches = NULL;
        pthread_mutex_unlock (&lock);

        /* Process each callback */
        for (iter = pending; iter; iter = g_list_next (iter))
        {
            cb_info_t *info = (cb_info_t *) iter->data;
            if (info->cb)
                info->cb (info->path, info->priv, info->value, info->size);
        }
        g_list_free_full (pending, cb_info_destroy);
    }
    DEBUG ("Worker Thread: Exiting\n");
    sem_destroy(&wake_worker);
    worker_id = 0;
    worker_running = false;
    return NULL;
}

static void*
client_thread (void *data)
{
    Apteryx__Client_Service service = APTERYX__CLIENT__INIT (apteryx__);
    char service_name[64];
    int pipefd[2];

    /* Create fd to stop server */
    if (pipe (pipefd) != 0)
    {
        ERROR ("Failed to create pipe\n");
        return NULL;
    }
    stopfd = pipefd[1];

    /* Create service and process requests */
    DEBUG ("Watch/Provide Thread: started...\n");
    client_running = true;
    sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", (uint64_t)getpid ());
    if (!rpc_provide_service (service_name, (ProtobufCService *)&service, 0, pipefd[0]))
    {
        ERROR ("Watch/Provide Thread: Failed to start rpc service\n");
    }

    /* Clean up */
    DEBUG ("Watch/Provide Thread: Exiting\n");
    close (pipefd[0]);
    close (pipefd[1]);
    stopfd = -1;
    client_id = 0;
    client_running = false;
    return NULL;
}

static void
stop_client_threads (void)
{
    uint8_t dummy = 1;
    int i;

    /* Not from a callback please */
    if (pthread_self () == worker_id)
        return;

    /* Stop the client thread */
    pthread_mutex_lock (&lock);
    if (client_running && client_id != 0)
    {
        /* Signal stop and wait */
        client_running = false;
        if (write (stopfd, &dummy, 1) != 1)
            ERROR ("Failed to stop server\n");
        for (i=0; i < 5000 && client_id != 0; i++)
            usleep (1000);
        if (client_id != 0)
        {
            DEBUG ("Shutdown: Killing Client thread\n");
            pthread_cancel (client_id);
            pthread_join (client_id, NULL);
        }
    }

    /* Stop the worker thread */
    if (worker_running && worker_id != 0)
    {
        /* Wait for the worker to exit */
        worker_running = false;
        sem_post (&wake_worker);
        for (i=0; i < 5000 && worker_id != 0; i++)
            usleep (1000);
        if (worker_id != 0)
        {
            DEBUG ("Shutdown: Killing worker thread\n");
            pthread_cancel (worker_id);
            pthread_join (worker_id, NULL);
        }
        g_list_free_full (pending_watches, cb_info_destroy);
        pending_watches = NULL;
    }

    /* Done */
    worker_running = false;
    client_running = false;
    pthread_mutex_unlock (&lock);
    return;
}

static bool
start_client_threads (void)
{
    int i;

    /* Create threads if not already running */
    pthread_mutex_lock (&lock);
    if (!client_running)
    {
        /* Create the worker to process the watch callbacks */
        sem_init (&wake_worker, 1, 0);
        pthread_create (&worker_id, NULL, worker_thread, NULL);
        for (i=0; i < 5000 && !worker_running; i++)
            usleep (1000);
        if (!worker_running || worker_id == 0)
        {
            ERROR ("Failed to create Apteryx worker thread\n");
            pthread_mutex_unlock (&lock);
            return false;
        }

        /* Create a thread to process Apteryx events */
        pthread_create (&client_id, NULL, client_thread, NULL);
        for (i=0; i < 5000 && !client_running; i++)
            usleep (1000);
        if (!client_running || client_id == 0)
        {
            pthread_mutex_unlock (&lock);
            stop_client_threads ();
            ERROR ("Failed to create Apteryx client thread\n");
            return false;
        }
    }
    pthread_mutex_unlock (&lock);
    return true;
}

static void
handle_ok_response (const Apteryx__OKResult *result, void *closure_data)
{
    if (result == NULL)
        ERROR ("RESULT: Error processing request.\n");
    *(protobuf_c_boolean *) closure_data = 1;
}

bool
apteryx_init (bool debug_enabled)
{
    /* Increment refcount */
    pthread_mutex_lock (&lock);
    ref_count++;
    debug |= debug_enabled;
    pthread_mutex_unlock (&lock);

#ifdef USE_SHM_CACHE
    /* Init cache */
    if (ref_count == 1)
        cache_init ();
#endif

    /* Ready to go */
    if (ref_count > 1)
        DEBUG ("Init: Initialised\n");
    return true;
}

bool
apteryx_shutdown (void)
{
    /* Check if already shutdown */
    if (ref_count <= 0)
    {
        ERROR ("Shutdown: Already shutdown\n");
        return false;
    }

    /* Decrement ref count */
    pthread_mutex_lock (&lock);
    ref_count--;
    pthread_mutex_unlock (&lock);

    /* Check if there are still other users */
    if (ref_count > 0)
    {
        DEBUG ("Shutdown: More users (refcount=%d)\n", ref_count);
        return true;
    }

#ifdef USE_SHM_CACHE
    /* Shut cache */
    cache_shutdown (false);
#endif

    /* Shutdown */
    DEBUG ("Shutdown: Shutting down\n");
    stop_client_threads ();
    DEBUG ("Shutdown: Shutdown\n");
    return true;
}

bool
apteryx_prune (const char *path)
{
    ProtobufCService *rpc_client;
    Apteryx__Prune prune = APTERYX__PRUNE__INIT;
    protobuf_c_boolean is_done = 0;

    DEBUG ("PRUNE: %s\n", path);

    /* Check path */
    if (path[0] != '/')
    {
        ERROR ("PRUNE: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("PRUNE: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    prune.path = (char *) path;
    apteryx__server__prune (rpc_client, &prune, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        ERROR ("PRUNE: No response\n");
        return false;
    }

    /* Success */
    return true;
}

static inline char *
format_to_string (APTERYX_FORMAT format)
{
    switch (format)
    {
    case FORMAT_RAW:
        return "raw";
    case FORMAT_JSON:
        return "json";
    case FORMAT_XML:
        return "xml";
    default:
        return "unknown";
    }
}

bool
apteryx_import (const char *path, APTERYX_FORMAT format, const char *data)
{
    ProtobufCService *rpc_client;
    Apteryx__Import import = APTERYX__IMPORT__INIT;
    protobuf_c_boolean is_done = 0;

    DEBUG ("IMPORT(%s): %s = %s\n", format_to_string (format), path, data);

    /* Check path */
    if (path[0] != '/')
    {
        ERROR ("IMPORT: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("IMPORT: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    import.format = format;
    import.path = (char *) path;
    import.data = (char *) data;
    apteryx__server__import (rpc_client, &import, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        ERROR ("IMPORT: No response\n");
        return false;
    }

    /* Success */
    return true;
}
typedef struct _export_data_t
{
    char *data;
    bool done;
} export_data_t;

static void
handle_export_response (const Apteryx__ExportResult *result, void *closure_data)
{
    export_data_t *data = (export_data_t *)closure_data;
    if (result == NULL)
    {
        ERROR ("EXPORT: Error processing request.\n");
    }
    else if (result->data != 0)
    {
        data->data = strdup (result->data);
    }
    data->done = true;
}

bool
apteryx_export (const char *path, APTERYX_FORMAT format, char **data)
{
    ProtobufCService *rpc_client;
    Apteryx__Export export = APTERYX__EXPORT__INIT;
    export_data_t result = {0};

    DEBUG ("EXPORT(%s): %s\n", format_to_string (format), path);

    /* Check path */
    if (path[0] != '/')
    {
        ERROR ("EXPORT: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("EXPORT: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    export.format = format;
    export.path = (char *) path;
    apteryx__server__export (rpc_client, &export, handle_export_response, &result);
    protobuf_c_service_destroy (rpc_client);
    if (!result.done)
    {
        ERROR ("EXPORT: No response\n");
        return false;
    }

    /* Result */
    *data = result.data;

    DEBUG ("    = %s\n", *data);
    return (*data != NULL);
}

bool
apteryx_set (const char *path, unsigned char *value, size_t size)
{
    ProtobufCService *rpc_client;
    Apteryx__Set set = APTERYX__SET__INIT;
    protobuf_c_boolean is_done = 0;

    DEBUG ("SET: %s = %s\n", path, bytes_to_string (value, size));

    /* Check path */
    if (path[0] != '/' || path[strlen(path) - 1] == '/')
    {
        ERROR ("SET: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("SET: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    set.path = (char *) path;
    set.value.data = value;
    set.value.len = size;
    apteryx__server__set (rpc_client, &set, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        ERROR ("SET: No response\n");
        return false;
    }

    /* Success */
    return true;
}

bool
apteryx_set_int (const char *path, const char *key, int32_t value)
{
    char *full_path;
    size_t len;
    unsigned char *v;
    bool res = false;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        /* Store as a string at the moment */
        len = asprintf ((char **) &v, "%d", value);
        res = apteryx_set (full_path, v, len + 1);
        free ((void *) v);
        free (full_path);
    }
    return res;
}

bool
apteryx_set_string (const char *path, const char *key, const char *value)
{
    char *full_path;
    size_t len;
    bool res = false;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        res = apteryx_set (full_path, (unsigned char *) value,
                           value ? strlen (value) + 1 : 0);
        free (full_path);
    }
    return res;
}

typedef struct _get_data_t
{
    unsigned char *value;
    size_t length;
    bool done;
} get_data_t;

static void
handle_get_response (const Apteryx__GetResult *result, void *closure_data)
{
    get_data_t *data = (get_data_t *)closure_data;
    if (result == NULL)
    {
        ERROR ("GET: Error processing request.\n");
    }
    else if (result->value.len != 0)
    {
        data->length = result->value.len;
        data->value = malloc (data->length);
        memcpy (data->value, result->value.data, data->length);
    }
    data->done = true;
}

bool
apteryx_get (const char *path, unsigned char **value, size_t *size)
{
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;
    get_data_t data = {0};

    DEBUG ("GET: %s\n", path);

    /* Check path */
    if (path[0] != '/' || path[strlen(path)-1] == '/')
    {
        ERROR ("GET: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* Start blank */
    *value = NULL;
    *size = 0;

#ifdef USE_SHM_CACHE
    if (cache_get (path, value, size))
    {
        DEBUG ("    = (c)%s\n", bytes_to_string (*value, *size));
        return (*value != NULL);
    }
#endif

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("GET: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    get.path = (char *) path;
    apteryx__server__get (rpc_client, &get, handle_get_response, &data);
    protobuf_c_service_destroy (rpc_client);
    if (!data.done)
    {
        ERROR ("GET: No response\n");
        return false;
    }

    /* Result */
    *size = data.length;
    *value = data.value;

    DEBUG ("    = %s\n", bytes_to_string (*value, *size));
    return (*value != NULL);
}

int32_t
apteryx_get_int (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    unsigned char *v = NULL;
    int value = -1;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if (apteryx_get (full_path, &v, &len) && v)
        {
            value = atoi ((char *) v);
            free (v);
        }
        free (full_path);
    }
    return value;
}

char *
apteryx_get_string (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    unsigned char *value = NULL;
    char *str = NULL;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if (!apteryx_get ((const char *) full_path, &value, &len))
        {
            value = NULL;
        }
        str = (char *) value;
        free (full_path);
    }
    return str;
}

typedef struct _search_data_t
{
    GList *paths;
    bool done;
} search_data_t;

static void
handle_search_response (const Apteryx__SearchResult *result, void *closure_data)
{
    search_data_t *data = (search_data_t *)closure_data;
    int i;
    data->paths = NULL;
    if (result == NULL)
    {
        ERROR ("SEARCH: Error processing request.\n");
    }
    else if (result->paths == NULL)
    {
        DEBUG ("    = (null)\n");
    }
    else if (result->n_paths != 0)
    {
        for (i = 0; i < result->n_paths; i++)
        {
            DEBUG ("    = %s\n", result->paths[i]);
            data->paths = g_list_append (data->paths,
                              (gpointer) strdup (result->paths[i]));
        }
    }
    data->done = true;
}

GList *
apteryx_search (const char *path)
{
    ProtobufCService *rpc_client;
    Apteryx__Search search = APTERYX__SEARCH__INIT;
    search_data_t data = {0};

    DEBUG ("SEARCH: %s\n", path);

    /* Validate path */
    if (!path ||
        strcmp (path, "/") == 0 ||
        strcmp (path, "/*") == 0 ||
        strcmp (path, "*") == 0 ||
        strlen (path) == 0)
    {
        path = "";
    }
    else if (path[0] != '/' ||
             path[strlen (path) - 1] != '/' ||
             strstr (path, "//") != NULL)
    {
        ERROR ("SEARCH: invalid root (%s)!\n", path);
        assert(!debug || path[0] == '/');
        assert(!debug || path[strlen (path) - 1] == '/');
        assert(!debug || strstr (path, "//") == NULL);
        return NULL;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("SEARCH: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    search.path = (char *) path;
    apteryx__server__search (rpc_client, &search, handle_search_response, &data);
    protobuf_c_service_destroy (rpc_client);
    if (!data.done)
    {
        ERROR ("SEARCH: No response\n");
        return NULL;
    }

    /* Result */
    return data.paths;
}

bool
apteryx_watch (const char *path, apteryx_watch_callback cb, void *priv)
{
    ProtobufCService *rpc_client;
    Apteryx__Watch watch = APTERYX__WATCH__INIT;
    char *empty_root = "/*";
    protobuf_c_boolean is_done = 0;

    DEBUG ("WATCH: %s %p %p\n", path, cb, priv);

    /* Check path */
    if (!path ||
        strcmp (path, "/") == 0 ||
        strcmp (path, "/*") == 0 || strcmp (path, "*") == 0 || strlen (path) == 0)
    {
        path = empty_root;
    }
    if (path[0] != '/')
    {
        ERROR ("WATCH: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("WATCH: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    watch.path = (char *) path;
    watch.id = (uint64_t) getpid ();
    watch.cb = (uint64_t) (long) cb;
    watch.priv = (uint64_t) (long) priv;
    apteryx__server__watch (rpc_client, &watch, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        ERROR ("WATCH: No response\n");
        return false;
    }

    /* Start the listen thread if required */
    if (cb)
        return start_client_threads ();

    /* Success */
    return true;
}

bool
apteryx_provide (const char *path, apteryx_provide_callback cb, void *priv)
{
    ProtobufCService *rpc_client;
    Apteryx__Provide provide = APTERYX__PROVIDE__INIT;
    protobuf_c_boolean is_done = 0;

    DEBUG ("PROVIDE: %s %p %p\n", path, cb, priv);

    /* Check path */
    if (path[0] != '/')
    {
        ERROR ("PROVIDE: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("PROVIDE: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    provide.path = (char *) path;
    provide.id = (uint64_t) getpid ();
    provide.cb = (uint64_t) (long) cb;
    provide.priv = (uint64_t) (long) priv;
    apteryx__server__provide (rpc_client, &provide, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        ERROR ("PROVIDE: No response\n");
        return false;
    }

    /* Start the listen thread if required */
    if (cb)
        return start_client_threads ();

    /* Success */
    return true;
}
