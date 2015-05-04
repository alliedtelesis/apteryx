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
typedef struct _ccb_info_t
{
    apteryx_watch_callback cb;
    const char *path;
    void *priv;
    char *value;
} ccb_info_t;

static void
ccb_info_destroy (gpointer data)
{
    ccb_info_t *info = (ccb_info_t*)data;
    free ((void *) info->path);
    free ((void *) info->value);
    free (info);
}

static gpointer
ccb_info_create (const Apteryx__Watch *watch)
{
    ccb_info_t *info = calloc (1, sizeof (ccb_info_t));
    info->cb = (apteryx_watch_callback) (long) watch->cb;
    info->path = strdup (watch->path);
    info->priv = (void *) (long) watch->priv;
    if (watch->value && watch->value[0] != '\0')
        info->value = strdup (watch->value);
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
           watch->path, watch->value,
           watch->id, watch->cb, watch->priv);

    /* Queue the callback for processing */
    pthread_mutex_lock (&lock);
    if (pending_watches == NULL)
        sem_post (&wake_worker);
    pending_watches = g_list_append (pending_watches, ccb_info_create (watch));
    pthread_mutex_unlock (&lock);

    /* Return result */
    closure (&result, closure_data);
    return;
}

/* Callback for validated items */
static void
apteryx__validate (Apteryx__Client_Service *service,
                const Apteryx__Validate *validate,
                Apteryx__ValidateResult_Closure closure, void *closure_data)
{
    Apteryx__ValidateResult result = APTERYX__VALIDATE_RESULT__INIT;
    (void) service;

    DEBUG ("VALIDATE CB \"%s\" = \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
           validate->path, validate->value,
           validate->id, validate->cb);

    result.result = ((apteryx_validate_callback)validate->cb) (validate->path, validate->value);

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
    char *value = NULL;
    (void) service;

    DEBUG ("PROVIDE CB: \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
           provide->path, provide->id, provide->cb, provide->priv);

    /* Call the callback */
    if (cb)
        value = cb (provide->path, (void *) (long) provide->priv);

    /* Return result */
    result.value = value;
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
            ccb_info_t *info = (ccb_info_t *) iter->data;
            if (info->cb)
                info->cb (info->path, info->priv, info->value);
        }
        g_list_free_full (pending, ccb_info_destroy);
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
    DEBUG ("Watch/Provide/Validate Thread: started...\n");
    client_running = true;
    sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", (uint64_t)getpid ());
    if (!rpc_provide_service (service_name, (ProtobufCService *)&service, 0, pipefd[0]))
    {
        ERROR ("Watch/Provide/Validate Thread: Failed to start rpc service\n");
    }

    /* Clean up */
    DEBUG ("Watch/Provide/Validate Thread: Exiting\n");
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
        pthread_mutex_lock (&lock);
        g_list_free_full (pending_watches, ccb_info_destroy);
        pending_watches = NULL;
        pthread_mutex_unlock (&lock);
    }

    /* Done */
    worker_running = false;
    client_running = false;
    return;
}

static bool
start_client_threads (void)
{
    int i;

    /* Create threads if not already running */
    pthread_mutex_lock (&lock);

    /* Return early if we are shutting down */
    if (ref_count == 0)
    {
        pthread_mutex_unlock (&lock);
        return false;
    }

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
    {
        *(protobuf_c_boolean *) closure_data = false;
        errno = -ECONNABORTED;
    }
    else
    {
        *(protobuf_c_boolean *) closure_data = result->result == 0;
        errno = result->result;
    }
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
    assert (!client_running);
    assert (!worker_running);
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

bool
apteryx_dump (const char *path, FILE *fp)
{
    char *value = NULL;

    DEBUG ("DUMP: %s\n", path);

    /* Check initialised */
    if (ref_count <= 0)
    {
        ERROR ("DUMP: not initialised!\n");
        assert(ref_count > 0);
        return false;
    }

    if (strlen (path) > 0 && (value = apteryx_get (path)))
    {
        fprintf (fp, "%-64s%-64s\n", path, value);
        free (value);
    }

    char *_path = NULL;
    int len = asprintf (&_path, "%s/", path);
    if (len >= 0)
    {
        GList *children, *iter;
        children = apteryx_search (_path);
        for (iter = children; iter; iter = g_list_next (iter))
        {
            apteryx_dump ((const char *) iter->data, fp);
        }
        g_list_free_full (children, free);
        free (_path);
    }
    return true;
}

bool
apteryx_set (const char *path, const char *value)
{
    ProtobufCService *rpc_client;
    Apteryx__Set set = APTERYX__SET__INIT;
    protobuf_c_boolean is_done = 0;

    DEBUG ("SET: %s = %s\n", path, value);

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
    set.value = (char *) value;
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
        res = apteryx_set (full_path, value);
        free (full_path);
    }
    return res;
}

bool
apteryx_set_int (const char *path, const char *key, int32_t value)
{
    char *full_path;
    size_t len;
    char *v;
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
        if (len)
        {
            res = apteryx_set (full_path, v);
            free ((void *) v);
        }
        free (full_path);
    }
    return res;
}

typedef struct _get_data_t
{
    char *value;
    bool done;
} get_data_t;

static void
handle_get_response (const Apteryx__GetResult *result, void *closure_data)
{
    get_data_t *data = (get_data_t *)closure_data;
    if (result == NULL)
    {
        ERROR ("GET: Error processing request.\n");
        errno = -ETIMEDOUT;
    }
    else if (result->value && result->value[0] != '\0')
    {
        data->value = strdup (result->value);
    }
    data->done = true;
}

char *
apteryx_get (const char *path)
{
    char *value = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;
    get_data_t data = {0};

    DEBUG ("GET: %s\n", path);

    /* Check path */
    if (path[0] != '/' || path[strlen(path)-1] == '/')
    {
        ERROR ("GET: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return NULL;
    }

#ifdef USE_SHM_CACHE
    if ((value = cache_get (path)))
    {
        DEBUG ("    = (c)%s\n", value);
        return value;
    }
#endif

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("GET: Falied to connect to server: %s\n", strerror (errno));
        return NULL;
    }
    get.path = (char *) path;
    apteryx__server__get (rpc_client, &get, handle_get_response, &data);
    protobuf_c_service_destroy (rpc_client);
    if (!data.done)
    {
        ERROR ("GET: No response\n");
        errno = -ETIMEDOUT;
        return NULL;
    }

    /* Result */
    value = data.value;

    DEBUG ("    = %s\n", value);
    return value;
}

char *
apteryx_get_string (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    char *value = NULL;
    char *str = NULL;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if ((value = apteryx_get ((const char *) full_path)))
        {
            str = (char *) value;
        }
        free (full_path);
    }
    return str;
}

int32_t
apteryx_get_int (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    char *v = NULL;
    int value = -1;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if ((v = apteryx_get (full_path)))
        {
            value = atoi ((char *) v);
            free (v);
        }
        free (full_path);
    }
    return value;
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

    if (!cb)
    {
        ERROR ("Unwatching by passing in NULL cb is NOT SUPPORTED\n");
        return false;
    }

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
apteryx_unwatch (const char *path, apteryx_watch_callback cb)
{
    ProtobufCService *rpc_client;
    Apteryx__Watch watch = APTERYX__WATCH__INIT;
    char *empty_root = "/*";
    protobuf_c_boolean is_done = 0;

    DEBUG ("UNWATCH: %s %p\n", path, cb);

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
    watch.priv = 0;
    apteryx__server__unwatch (rpc_client, &watch, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        ERROR ("WATCH: No response\n");
        return false;
    }

    /* Success */
    return true;
}

bool
apteryx_validate (const char *path, apteryx_validate_callback cb)
{
    ProtobufCService *rpc_client;
    Apteryx__Validate validate = APTERYX__VALIDATE__INIT;
    char *empty_root = "/*";
    bool is_done = 0;

    DEBUG ("VALIDATE: %s %p\n", path, cb);

    if (!cb)
    {
        ERROR ("Unvalidating by passing in NULL cb is NOT SUPPORTED\n");
        return false;
    }

    /* Check path */
    if (!path ||
        strcmp (path, "/") == 0 ||
        strcmp (path, "/*") == 0 || strcmp (path, "*") == 0 || strlen (path) == 0)
    {
        path = empty_root;
    }
    if (path[0] != '/')
    {
        ERROR ("VALIDATE: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("VALIDATE: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    validate.path = (char *) path;
    validate.id = (uint64_t) getpid ();
    validate.cb = (uint64_t) (long) cb;
    apteryx__server__validate (rpc_client, &validate, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
         ERROR ("VALIDATE: No response\n");
         return false;
    }

    /* Start the listen thread if required */
    if (cb)
        return start_client_threads ();

    return true;
}

bool
apteryx_unvalidate (const char *path, apteryx_validate_callback cb)
{
    ProtobufCService *rpc_client;
    Apteryx__Validate validate = APTERYX__VALIDATE__INIT;
    char *empty_root = "/*";
    bool is_done = 0;

    DEBUG ("UNVALIDATE: %s %p\n", path, cb);

    if (!cb)
    {
        ERROR ("Unvalidating by passing in NULL cb is NOT SUPPORTED\n");
        return false;
    }

    /* Check path */
    if (!path ||
        strcmp (path, "/") == 0 ||
        strcmp (path, "/*") == 0 || strcmp (path, "*") == 0 || strlen (path) == 0)
    {
        path = empty_root;
    }
    if (path[0] != '/')
    {
        ERROR ("UNVALIDATE: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("VALIDATE: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    validate.path = (char *) path;
    validate.id = (uint64_t) getpid ();
    validate.cb = (uint64_t) (long) cb;
    apteryx__server__unvalidate (rpc_client, &validate, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
         ERROR ("UNVALIDATE: No response\n");
         return false;
    }

    return true;
}

bool
apteryx_provide (const char *path, apteryx_provide_callback cb, void *priv)
{
    ProtobufCService *rpc_client;
    Apteryx__Provide provide = APTERYX__PROVIDE__INIT;
    protobuf_c_boolean is_done = 0;

    DEBUG ("PROVIDE: %s %p %p\n", path, cb, priv);

    if (!cb)
    {
        ERROR ("Unwatching by passing in NULL cb is NOT SUPPORTED\n");
        return false;
    }

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

bool
apteryx_unprovide (const char *path, apteryx_provide_callback cb)
{
    ProtobufCService *rpc_client;
    Apteryx__Provide provide = APTERYX__PROVIDE__INIT;
    protobuf_c_boolean is_done = 0;

    DEBUG ("PROVIDE: %s %p\n", path, cb);

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
    provide.priv = 0;
    apteryx__server__unprovide (rpc_client, &provide, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        ERROR ("PROVIDE: No response\n");
        return false;
    }

    /* Success */
    return true;
}

static void
handle_get_ts_response (const Apteryx__GetTimeStampResult *result, void *closure_data)
{
    uint64_t *data = (uint64_t *)closure_data;
    if (result == NULL)
    {
        ERROR ("GET: Error processing request.\n");
    }
    *data = result->value;
}

uint64_t
apteryx_get_timestamp (const char *path)
{
    uint64_t value = 0;
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;

    DEBUG ("GET_TimeStamp: %s\n", path);

    /* Check path */
    if (path[0] != '/' || path[strlen(path)-1] == '/')
    {
        ERROR ("GET_TimeStamp: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return 0;
    }

    /* IPC */
    rpc_client = rpc_connect_service (APTERYX_SERVER, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("GET: Falied to connect to server: %s\n", strerror (errno));
        return 0;
    }
    get.path = (char *) path;
    apteryx__server__get_timestamp (rpc_client, &get, handle_get_ts_response, &value);
    protobuf_c_service_destroy (rpc_client);

    DEBUG ("    = %"PRIu64"\n", value);
    return value;
}
