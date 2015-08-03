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
static const char *default_url = APTERYX_SERVER; /* Default path to Apteryx database */
static int ref_count = 0;               /* Library reference count */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; /* Protect globals */
static int stopfd = -1;                 /* Used to stop the RPC server service */
static pthread_t client_id = 0;        /* Thread to process Apteryx events */
static pthread_t worker_id = 0;        /* Worker to handle watch callbacks */
static GList *pending_watches = NULL;   /* List of watches to process */
static sem_t wake_worker;               /* How we wake up the watch callback handler */
static volatile bool client_running = false;
static volatile bool worker_running = false;

static pthread_mutex_t pending_watches_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t no_pending_watches = PTHREAD_COND_INITIALIZER;
static int pending_watch_count = 0;

/* Callback */
typedef struct _ccb_info_t
{
    apteryx_watch_callback cb;
    const char *path;
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
    if (watch->value && watch->value[0] != '\0')
        info->value = strdup (watch->value);
    return (gpointer)info;
}

static const char *
validate_path (const char *path, const char **url)
{
    /* Database path or none at all */
    if (path && path[0] == '/')
    {
        /* Use the default URL */
        if (url)
            *url = default_url;
        return path;
    }
    /* Check for a full URL */
    else if (path &&
      (strncmp (path, "unix://", 7) == 0 ||
       strncmp (path, "tcp://", 6) == 0))
    {
        if (url)
            *url = path;
        path = strrchr (path, ':') + 1;
        return path;
    }
    ERROR ("Invalid path (%s)!\n", path);
    return NULL;
}

/* Callback for indexed items */
static void
apteryx__index (Apteryx__Client_Service *service,
                  const Apteryx__Index *index,
                  Apteryx__SearchResult_Closure closure, void *closure_data)
{
    Apteryx__SearchResult result = APTERYX__SEARCH_RESULT__INIT;
    apteryx_index_callback cb = (apteryx_index_callback) (long) index->cb;
    GList *results = NULL;
    GList *iter = NULL;
    int i;
    (void) service;

    DEBUG ("INDEX CB: \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
            index->path, index->id, index->cb);

    /* Call the callback */
    if (cb)
        results = cb (index->path);

    /* Return result */
    result.n_paths = g_list_length (results);
    if (result.n_paths > 0)
    {
        result.paths = (char **) malloc (result.n_paths * sizeof (char *));
        for (i = 0, iter = results; iter; iter = g_list_next (iter), i++)
        {
            DEBUG ("         = %s\n", (char *) iter->data);
            result.paths[i] = (char *) iter->data;
        }
    }
    closure (&result, closure_data);
    g_list_free_full (results, free);
    if (result.paths)
        free (result.paths);
    return;
}

/* Callback for watched items */
static void
apteryx__watch (Apteryx__Client_Service *service,
                const Apteryx__Watch *watch,
                Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    (void) service;

    DEBUG ("WATCH CB \"%s\" = \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
           watch->path, watch->value,
           watch->id, watch->cb);

    pthread_mutex_lock (&pending_watches_lock);
    ++pending_watch_count;
    pthread_mutex_unlock (&pending_watches_lock);

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
    char *value = NULL;

    DEBUG ("VALIDATE CB \"%s\" = \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
           validate->path, validate->value,
           validate->id, validate->cb);

    if (!validate->cb)
    {
        result.result = 0;
        goto exit;
    }

    /* We want to wait for all pending watches to be processed */
    pthread_mutex_lock (&pending_watches_lock);
    if (pending_watch_count)
    {
        pthread_cond_wait (&no_pending_watches, &pending_watches_lock);
        pthread_mutex_unlock (&pending_watches_lock);
    }
    else
        pthread_mutex_unlock (&pending_watches_lock);

    if (validate->value && (validate->value[0] != '\0'))
    {
        value = validate->value;
    }
    result.result = ((apteryx_validate_callback)(size_t)validate->cb) (validate->path, value);

exit:
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

    DEBUG ("PROVIDE CB: \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
           provide->path, provide->id, provide->cb);

    /* Call the callback */
    if (cb)
        value = cb (provide->path);

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
    GList *job;

    /* Process callbacks while the client thread is running */
    DEBUG ("Worker Thread: started...\n");
    worker_running = true;
    while (worker_running)
    {
        /* Wait for some work */
        pthread_mutex_lock (&lock);
        if (pending_watches == NULL)
        {
            pthread_mutex_unlock (&lock);
            sem_wait (&wake_worker);
            if (!worker_running)
                break;
            if (pending_watches == NULL)
                continue;
            pthread_mutex_lock (&lock);
        }

        /* Dequeue the work */
        job = pending_watches;
        pending_watches = g_list_remove_link (pending_watches, job);
        pthread_mutex_unlock (&lock);

        /* Process callback */
        ccb_info_t *info = (ccb_info_t *) job->data;
        if (info->cb)
            info->cb (info->path, info->value);

        /* Free this element */
        ccb_info_destroy (job->data);
        g_list_free_1 (job);

        pthread_mutex_lock (&pending_watches_lock);
        if (--pending_watch_count == 0)
            pthread_cond_signal(&no_pending_watches);
        pthread_mutex_unlock (&pending_watches_lock);
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
        errno = -ETIMEDOUT;
    }
    else
    {
        *(protobuf_c_boolean *) closure_data = (result->result == 0);
        if (result->result)
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

    /* Shutdown */
    DEBUG ("Shutdown: Shutting down\n");
    stop_client_threads ();
#ifdef USE_SHM_CACHE
    /* Shut cache */
    cache_shutdown (false);
#endif
    DEBUG ("Shutdown: Shutdown\n");
    assert (!client_running);
    assert (!worker_running);
    return true;
}

bool
apteryx_bind (const char *url)
{
    char path[PATH_MAX];

    if (sprintf (path, APTERYX_SOCKETS_PATH"/%zX",
            (size_t)g_str_hash (url)) <= 0)
        return false;
    return apteryx_set_blocking (path, url);
}

bool
apteryx_unbind (const char *url)
{
    char path[PATH_MAX];

    if (sprintf (path, APTERYX_SOCKETS_PATH"/%zX",
            (size_t)g_str_hash (url)) <= 0)
        return false;
    return apteryx_set_blocking (path, NULL);
}

bool
apteryx_prune (const char *path)
{
    const char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Prune prune = APTERYX__PRUNE__INIT;
    protobuf_c_boolean is_done = 0;

    DEBUG ("PRUNE: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("PRUNE: invalid path (%s)!\n", path);
        assert (!debug || path);
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (url, &apteryx__server__descriptor);
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
        fprintf (fp, "%-64s%s\n", path, value);
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
apteryx_set_blocking (const char *path, const char *value)
{
    const char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Set set = APTERYX__SET__INIT;
    Apteryx__PathValue _pv = APTERYX__PATH_VALUE__INIT;
    Apteryx__PathValue *pv[1] = {&_pv};
    protobuf_c_boolean is_done = 0;

    DEBUG ("SET: %s = %s\n", path, value);

    /* Check path */
    path = validate_path (path, &url);
    if (!path || path[strlen(path) - 1] == '/')
    {
        ERROR ("SET: invalid path (%s)!\n", path);
        assert (!debug || path);
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (url, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("SET: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }
    pv[0]->path = (char *) path;
    pv[0]->value = (char *) value;
    set.n_sets = 1;
    set.sets = pv;
    apteryx__server__set (rpc_client, &set, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        DEBUG ("SET: Failed %s\n", strerror(errno));
        return false;
    }

    /* Success */
    return true;
}

bool
apteryx_set (const char *path, const char *value)
{
#ifdef USE_SHM_CACHE
    /* Try cache first */
    if (path && path[0] == '/' && cache_set (path, value, true))
    {
        DEBUG ("SET(c): %s = %s\n", path, value);
        return true;
    }
#endif
    return apteryx_set_blocking (path, value);
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
    const char *url = NULL;
    char *value = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;
    get_data_t data = {0};

    DEBUG ("GET: %s\n", path);

#ifdef USE_SHM_CACHE
    /* Check cache first */
    if (path && path[0] == '/' && (value = cache_get (path)))
    {
        DEBUG ("    = (c)%s\n", value);
        return value;
    }
#endif

    /* Check path */
    path = validate_path (path, &url);
    if (!path || path[strlen(path)-1] == '/')
    {
        ERROR ("GET: invalid path (%s)!\n", path);
        assert (!debug || path);
        return NULL;
    }

    /* IPC */
    rpc_client = rpc_connect_service (url, &apteryx__server__descriptor);
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

static inline gboolean
_node_free (GNode *node, gpointer data)
{
    free ((void *)node->data);
    return FALSE;
}

void
apteryx_free_tree (GNode* root)
{
    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_ALL, -1, _node_free, NULL);
    g_node_destroy (root);
}

static char *
_node_to_path (GNode *node, char **buf)
{
    /* don't put a trailing / on */
    char end = 0;
    if (!*buf)
    {
        *buf = strdup ("");
        end = 1;
    }

    if (node && node->parent)
        _node_to_path (node->parent, buf);

    char *tmp = NULL;
    if (asprintf (&tmp, "%s%s%s", *buf ? : "",
            node ? (char*)node->data : "/",
            end ? "" : "/") > 0)
    {
        free (*buf);
        *buf = tmp;
    }
    return tmp;
}

char *
apteryx_node_path (GNode* node)
{
    char *path = NULL;
    _node_to_path (node, &path);
    return path;
}

static gboolean
_set_multi (GNode *node, gpointer data)
{
    Apteryx__Set *set = (Apteryx__Set *)data;

    if (APTERYX_HAS_VALUE(node))
    {
        char *path = apteryx_node_path (node);
        Apteryx__PathValue *pv = calloc (1, sizeof (Apteryx__PathValue));
        DEBUG ("SET_TREE: %s = %s\n", path, APTERYX_VALUE (node));
        pv->base.descriptor = &apteryx__path_value__descriptor;
        pv->path = (char *) path;
        pv->value = (char *) APTERYX_VALUE (node);
        set->sets[set->n_sets++] = pv;
    }
    return FALSE;
}

bool
apteryx_set_tree (GNode* root)
{
    const char *path = NULL;
    const char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Set set = APTERYX__SET__INIT;
    protobuf_c_boolean is_done = 0;
    bool rc = true;
    int i;

    /* Check initialised */
    if (ref_count <= 0)
    {
        ERROR ("SET_TREE: not initialised!\n");
        assert(ref_count > 0);
        return false;
    }

    /* Check path */
    path = validate_path (APTERYX_NAME (root), &url);
    if (!path || path[strlen(path) - 1] == '/')
    {
        ERROR ("SET_TREE: invalid path (%s)!\n", path);
        assert (!debug || path);
        return false;
    }

    /* IPC */
    rpc_client = rpc_connect_service (url, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("SET_TREE: Falied to connect to server: %s\n", strerror (errno));
        return false;
    }

    /* Create the list of Paths/Value's */
    set.n_sets = g_node_n_nodes (root, G_TRAVERSE_LEAVES);
    set.sets = malloc (set.n_sets * sizeof (Apteryx__PathValue *));
    set.n_sets = 0;
    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _set_multi, &set);
    apteryx__server__set (rpc_client, &set, handle_ok_response, &is_done);
    protobuf_c_service_destroy (rpc_client);
    if (!is_done)
    {
        DEBUG ("SET_TREE: Failed %s\n", strerror(errno));
        rc = false;
    }

    /* Cleanup message */
    for (i=0; i<set.n_sets; i++)
    {
        Apteryx__PathValue *pv = set.sets[i];
        free (pv->path);
        free (pv);
    }
    free (set.sets);

    /* Return result */
    return rc;
}

static bool
_get_traverse (GNode* node, const char *path, int depth)
{
    char *_path;
    char *key = "";
    GList *children = NULL, *iter;
    char *value = NULL;

    /* Get the key */
    if (strrchr(path, '/'))
        key = strrchr(path, '/') + 1;

    /* Get value and/or children */
    if (!asprintf (&_path, "%s/", path))
        return false;
    children = apteryx_search (_path);
    free (_path);
    if (children == NULL)
        value = apteryx_get (path);

    /* Value or children */
    if (children == NULL && value)
    {
        APTERYX_LEAF (node, strdup (key), value);
    }
    else if (children)
    {
        if (node->data == NULL)
            node->data = (gpointer)strdup (path);
        else
            node = APTERYX_NODE (node, strdup (key));
        for (iter = children; iter; iter = g_list_next (iter))
        {
            _get_traverse (node, (const char *) iter->data, depth);
        }
        g_list_free_full(children, free);
    }
    return true;
}

GNode*
apteryx_get_tree (const char *path, int depth)
{
    GNode* root = NULL;

    DEBUG ("GET_TREE: %s\n", path);

    /* Check initialised */
    if (ref_count <= 0)
    {
        ERROR ("GET_TREE: not initialised!\n");
        assert(ref_count > 0);
        return false;
    }

    /* Check path */
    if (path[0] != '/' || path[strlen(path)-1] == '/')
    {
        ERROR ("GET_TREE: invalid path (%s)!\n", path);
        assert(!debug || path[0] == '/');
        return false;
    }

    /* Traverse */
    root = g_node_new (NULL);
    if (!_get_traverse (root, path, depth))
    {
        g_node_destroy (root);
        root = NULL;
    }
    return root;
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
    const char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Search search = APTERYX__SEARCH__INIT;
    search_data_t data = {0};

    DEBUG ("SEARCH: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("SEARCH: invalid root (%s)!\n", path);
        assert (!debug || path);
        return false;
    }

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
    rpc_client = rpc_connect_service (url, &apteryx__server__descriptor);
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

static bool
add_callback (const char *type, const char *path, void *cb)
{
    size_t pid = getpid ();
    char _path[PATH_MAX];

    if (sprintf (_path, "%s/%zX-%zX-%zX",
            type, (size_t)pid, (size_t)cb, (size_t)g_str_hash (path)) <= 0)
        return false;
    if (!apteryx_set_blocking (_path, path))
        return false;
    return start_client_threads ();
}

static bool
delete_callback (const char *type, const char *path,  void *cb)
{
    char _path[PATH_MAX];

    if (sprintf (_path, "%s/%zX-%zX-%zX",
            type, (size_t)getpid (), (size_t)cb, (size_t)g_str_hash (path)) <= 0)
        return false;
    if (!apteryx_set_blocking (_path, NULL))
        return false;
    return true;
}

bool
apteryx_index (const char *path, apteryx_index_callback cb)
{
    assert (cb != NULL); // use apteryx_unindex
    return add_callback (APTERYX_INDEXERS_PATH, path, (void *)cb);
}

bool
apteryx_unindex (const char *path, apteryx_index_callback cb)
{
    return delete_callback (APTERYX_INDEXERS_PATH, path, (void *)cb);
}

bool
apteryx_watch (const char *path, apteryx_watch_callback cb)
{
    assert (cb != NULL); // use apteryx_unwatch
    return add_callback (APTERYX_WATCHERS_PATH, path, (void *)cb);
}

bool
apteryx_unwatch (const char *path, apteryx_watch_callback cb)
{
    return delete_callback (APTERYX_WATCHERS_PATH, path, (void *)cb);
}

bool
apteryx_validate (const char *path, apteryx_validate_callback cb)
{
    assert (cb != NULL); // use apteryx_unvalidate
    return add_callback (APTERYX_VALIDATORS_PATH, path, (void *)cb);
}

bool
apteryx_unvalidate (const char *path, apteryx_validate_callback cb)
{
    return delete_callback (APTERYX_VALIDATORS_PATH, path, (void *)cb);
}

bool
apteryx_provide (const char *path, apteryx_provide_callback cb)
{
    assert (cb != NULL); // use apteryx_unprovide
    return add_callback (APTERYX_PROVIDERS_PATH, path, (void *)cb);
}

bool
apteryx_unprovide (const char *path, apteryx_provide_callback cb)
{
    return delete_callback (APTERYX_PROVIDERS_PATH, path, (void *)cb);
}

bool
apteryx_proxy (const char *path, const char *url)
{
    bool res = false;
    char *value = NULL;
    assert (url != NULL);
    if (asprintf (&value, "%s:%s", url, path) <= 0)
        return false;
    res = add_callback (APTERYX_PROXIES_PATH, value,
            (void *)(size_t)g_str_hash (url));
    free (value);
    return res;
}

bool
apteryx_unproxy (const char *path, const char *url)
{
    bool res = false;
    char *value = NULL;
    assert (url != NULL);
    if (asprintf (&value, "%s:%s", url, path) <= 0)
        return false;
    res = delete_callback (APTERYX_PROXIES_PATH, value,
            (void *)(size_t)g_str_hash (url));
    free (value);
    return res;
}

static void
handle_timestamp_response (const Apteryx__TimeStampResult *result, void *closure_data)
{
    uint64_t *data = (uint64_t *)closure_data;
    if (result == NULL)
    {
        ERROR ("TIMESTAMP: Error processing request.\n");
    }
    *data = result->value;
}

uint64_t
apteryx_timestamp (const char *path)
{
    const char *url = NULL;
    uint64_t value = 0;
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;

    DEBUG ("TIMESTAMP: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path || path[strlen(path)-1] == '/')
    {
        ERROR ("TIMESTAMP: invalid path (%s)!\n", path);
        assert (!debug || path);
        return 0;
    }

    /* IPC */
    rpc_client = rpc_connect_service (url, &apteryx__server__descriptor);
    if (!rpc_client)
    {
        ERROR ("TIMESTAMP: Falied to connect to server: %s\n", strerror (errno));
        return 0;
    }
    get.path = (char *) path;
    apteryx__server__timestamp (rpc_client, &get, handle_timestamp_response, &value);
    protobuf_c_service_destroy (rpc_client);

    DEBUG ("    = %"PRIu64"\n", value);
    return value;
}
