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
#include <glib.h>

/* Configuration */
bool apteryx_debug = false;                      /* Debug enabled */
static const char *default_url = APTERYX_SERVER; /* Default path to Apteryx database */
static int ref_count = 0;               /* Library reference count */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; /* Protect globals */
static rpc_instance rpc = NULL;         /* RPC Service */
static bool bound = false;              /* Do we have a listen socket open */
static bool have_callbacks = false;     /* Have we ever registered any callbacks */
static pthread_once_t once_control = PTHREAD_ONCE_INIT; /* Stuff that should only be done once */

static pthread_mutex_t pending_watches_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t no_pending_watches = PTHREAD_COND_INITIALIZER;
static int pending_watch_count = 0;

static const char *
validate_path (const char *path, char **url)
{
    /* Database path or none at all */
    if (path && path[0] == '/')
    {
        /* Use the default URL */
        if (url)
            *url = strdup(default_url);
        return path;
    }
    /* Check for a full URL */
    else if (path &&
      (strncmp (path, "unix://", 7) == 0 ||
       strncmp (path, "tcp://", 6) == 0))
    {
        if (url)
            *url = strdup (path);
        path = strstr (path + 6, ":/") + 1;
        char *tmp = strstr (*url + 6, ":/");
        if (tmp)
        {
            tmp[0] = '\0';
        }
        return path;
    }
    else if (path)
    {
        ERROR ("Invalid path (%s)!\n", path);
    }
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
                Apteryx__NoResult_Closure closure, void *closure_data)
{
    (void) service;
    char *value = NULL;

    DEBUG ("WATCH CB \"%s\" = \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
           watch->path, watch->value,
           watch->id, watch->cb);

    if (watch->value && (watch->value[0] != '\0'))
    {
        value = watch->value;
    }

    pthread_mutex_lock (&pending_watches_lock);
    ++pending_watch_count;
    pthread_mutex_unlock (&pending_watches_lock);

    /* Call callback */
    if (watch->cb)
        ((apteryx_watch_callback) (long) watch->cb) (watch->path, value);
    pthread_mutex_lock (&pending_watches_lock);
    if (--pending_watch_count == 0)
        pthread_cond_signal(&no_pending_watches);
    pthread_mutex_unlock (&pending_watches_lock);

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

static Apteryx__Client_Service apteryx_client_service = APTERYX__CLIENT__INIT (apteryx__);

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

static void
after_fork (void)
{
    if (ref_count > 0)
    {
        DEBUG ("Fork: Trying to restart Apteryx gracefully after a fork\n");

        // TODO: Handle listen socket

        /* Release any client sockets */
        rpc_client_release (rpc, NULL, false);
    }
}

static void
init_once (void)
{
    /* Try to gracefully handle a fork() */
    pthread_atfork (NULL, NULL, after_fork);
}

bool
apteryx_init (bool debug_enabled)
{
    /* Increment refcount */
    pthread_mutex_lock (&lock);
    ref_count++;
    apteryx_debug |= debug_enabled;
    if (ref_count == 1)
    {
        char * uri = NULL;

        /* Create RPC instance */
        rpc = rpc_init ((ProtobufCService *)&apteryx_client_service, &apteryx__server__descriptor, RPC_CLIENT_TIMEOUT_US);
        if (rpc == NULL)
        {
            ERROR ("Init: Failed to initialise RPC service\n");
            ref_count--;
            pthread_mutex_unlock (&lock);
            return false;
        }

        /* Only need to bind if we have previously added callbacks */
        if (have_callbacks)
        {
            /* Bind to the default uri for this client */
            if (asprintf ((char **) &uri, APTERYX_SERVER".%"PRIu64, (uint64_t) getpid ()) <= 0
                    || !rpc_server_bind (rpc, uri, uri))
            {
                ERROR ("Failed to bind uri %s\n", uri);
                ref_count--;
                pthread_mutex_unlock (&lock);
                free ((void*) uri);
                return false;
            }
            DEBUG ("Bound to uri %s\n", uri);
            bound = true;
            free ((void*) uri);
        }
    }
    pthread_mutex_unlock (&lock);

    /* Stuff that should only ever be done once */
    pthread_once (&once_control, &init_once);

    /* Ready to go */
    if (ref_count == 1)
        DEBUG ("Init: Initialised\n");
    return true;
}

bool
apteryx_shutdown (void)
{
    ASSERT ((ref_count > 0), return false, "SHUTDOWN: Not initialised\n");

    /* Decrement ref count */
    pthread_mutex_lock (&lock);
    ref_count--;
    pthread_mutex_unlock (&lock);

    /* Check if there are still other users */
    if (ref_count > 0)
    {
        DEBUG ("SHUTDOWN: More users (refcount=%d)\n", ref_count);
        return true;
    }

    /* Shutdown */
    DEBUG ("SHUTDOWN: Shutting down\n");
    rpc_shutdown (rpc);
    bound = false;
    DEBUG ("SHUTDOWN: Shutdown\n");
    return true;
}


bool
apteryx_shutdown_force (void)
{
    while (ref_count > 0)
        apteryx_shutdown ();
    return true;
}

int
apteryx_process (bool poll)
{
    ASSERT ((ref_count > 0), return false, "PROCESS: Not initialised\n");
    return rpc_server_process (rpc, poll);
}

bool
apteryx_bind (const char *url)
{
    char path[PATH_MAX];
    bool result;

    ASSERT ((ref_count > 0), return false, "BIND: Not initialised\n");
    ASSERT (url, return false, "BIND: Invalid parameters\n");

    DEBUG ("BIND: %s\n", url);

    if (sprintf (path, APTERYX_SOCKETS_PATH"/%zX",
            (size_t)g_str_hash (url)) <= 0)
        return false;
    result = apteryx_set (path, url);
    usleep (1000); /* Sockets need time to bind/unbind */
    return result;
}

bool
apteryx_unbind (const char *url)
{
    char path[PATH_MAX];

    ASSERT ((ref_count > 0), return false, "UNBIND: Not initialised\n");
    ASSERT (url, return false, "UNBIND: Invalid parameters\n");

    DEBUG ("UNBIND: %s\n", url);

    if (sprintf (path, APTERYX_SOCKETS_PATH"/%zX",
            (size_t)g_str_hash (url)) <= 0)
        return false;
    return apteryx_set (path, NULL);
}

bool
apteryx_prune (const char *path)
{
    char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Prune prune = APTERYX__PRUNE__INIT;
    protobuf_c_boolean is_done = 0;

    ASSERT ((ref_count > 0), return false, "PRUNE: Not initialised\n");
    ASSERT (path, return false, "PRUNE: Invalid parameters\n");

    DEBUG ("PRUNE: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("PRUNE: invalid path (%s)!\n", path);
        assert (!apteryx_debug || path);
        return false;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("PRUNE: Falied to connect to server: %s\n", strerror (errno));
        free (url);
        return false;
    }
    prune.path = (char *) path;
    apteryx__server__prune (rpc_client, &prune, handle_ok_response, &is_done);
    if (!is_done)
    {
        ERROR ("PRUNE: No response\n");
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return false;
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Success */
    return true;
}

bool
apteryx_dump (const char *path, FILE *fp)
{
    char *value = NULL;

    ASSERT ((ref_count > 0), return false, "DUMP: Not initialised\n");
    ASSERT (path, return false, "DUMP: Invalid parameters\n");
    ASSERT (fp, return false, "DUMP: Invalid parameters\n");

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
apteryx_cas (const char *path, const char *value, uint64_t ts)
{
    char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Set set = APTERYX__SET__INIT;
    Apteryx__PathValue _pv = APTERYX__PATH_VALUE__INIT;
    Apteryx__PathValue *pv[1] = {&_pv};
    protobuf_c_boolean result = 0;

    ASSERT ((ref_count > 0), return false, "SET: Not initialised\n");
    ASSERT (path, return false, "SET: Invalid parameters\n");

    DEBUG ("SET: %s = %s\n", path, value);

    /* Check path */
    path = validate_path (path, &url);
    if (!path || path[strlen(path) - 1] == '/')
    {
        ERROR ("SET: invalid path (%s)!\n", path);
        free (url);
        assert (!apteryx_debug || path);
        return false;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("SET: Failed to connect to server: %s\n", strerror (errno));
        free (url);
        return false;
    }
    pv[0]->path = (char *) path;
    pv[0]->value = (char *) value;
    set.n_sets = 1;
    set.sets = pv;
    set.ts = ts;
    apteryx__server__set (rpc_client, &set, handle_ok_response, &result);
    if (!result && errno == -ETIMEDOUT)
    {
        DEBUG ("SET: No response\n");
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return false;
    }
    else if (!result)
    {
        DEBUG ("SET: Error response: %s\n", strerror (errno));
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Success */
    return result;
}

bool
apteryx_set (const char *path, const char *value)
{
    return apteryx_cas (path, value, UINT64_MAX);
}

bool
apteryx_cas_string (const char *path, const char *key, const char *value, uint64_t ts)
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
        res = apteryx_cas (full_path, value, ts);
        free (full_path);
    }
    return res;
}

bool
apteryx_set_string (const char *path, const char *key, const char *value)
{
    return apteryx_cas_string (path, key, value, UINT64_MAX);
}

bool
apteryx_cas_int (const char *path, const char *key, int32_t value, uint64_t ts)
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
            res = apteryx_cas (full_path, v, ts);
            free ((void *) v);
        }
        free (full_path);
    }
    return res;
}

bool
apteryx_set_int (const char *path, const char *key, int32_t value)
{
    return apteryx_cas_int (path, key, value, UINT64_MAX);
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
    data->done = false;
    if (result == NULL)
    {
        ERROR ("GET: Error processing request.\n");
        errno = -ETIMEDOUT;
    }
    else
    {
        data->done = true;
        if (result->value && result->value[0] != '\0')
        {
            data->value = strdup (result->value);
        }
    }
}

char *
apteryx_get (const char *path)
{
    char *url = NULL;
    char *value = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;
    get_data_t data = {0};

    ASSERT ((ref_count > 0), return NULL, "GET: Not initialised\n");
    ASSERT (path, return NULL, "GET: Invalid parameters\n");

    DEBUG ("GET: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path || path[strlen(path)-1] == '/')
    {
        ERROR ("GET: invalid path (%s)!\n", path);
        free (url);
        assert (!apteryx_debug || path);
        return NULL;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("GET: Failed to connect to server: %s\n", strerror (errno));
        free (url);
        return NULL;
    }
    get.path = (char *) path;
    apteryx__server__get (rpc_client, &get, handle_get_response, &data);
    if (!data.done)
    {
        ERROR ("GET: No response\n");
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        rpc_client_release (rpc, rpc_client, true);
        value = data.value;
    }
    free (url);

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

bool
apteryx_has_value (const char *path)
{
    char *value = NULL;
    value = apteryx_get (path);
    if (value)
    {
        free (value);
        return true;
    }
    return false;
}

GNode *
apteryx_find_child (GNode *parent, char *name)
{
    GNode *node;

    for (node = g_node_first_child (parent); node; node = node->next)
    {
        if (strcmp (APTERYX_NAME (node), name) == 0)
        {
            return node;
        }
    }
    return NULL;
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
    if (root)
    {
        g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_ALL, -1, _node_free, NULL);
        g_node_destroy (root);
    }
}

static GNode *
merge (GNode *left, GNode *right, int (*cmp) (const char *a, const char *b))
{
    if (!left)
        return right;
    if (!right)
        return left;
    if (cmp (left->data, right->data) < 0)
    {
        left->next = merge (left->next, right, cmp);
        left->next->prev = left;
        left->prev = NULL;
        return left;
    }
    else
    {
        right->next = merge (left, right->next, cmp );
        right->next->prev = right;
        right->prev = NULL;
        return right;
    }
}

static GNode *
split (GNode *head)
{
    GNode *left, *right;
    left = right = head;
    while (right->next && right->next->next)
    {
        right = right->next->next;
        left = left->next;
    }
    right = left->next;
    left->next = NULL;
    return right;
}

static GNode *
merge_sort (GNode *head, int (*cmp) (const char *a, const char *b))
{
    GNode *left, *right;
    if (!head || !head->next)
        return head;
    left = head;
    right = split (left);
    left = merge_sort (left, cmp);
    right = merge_sort (right, cmp);
    return merge (left, right, cmp);
}

void
apteryx_sort_children (GNode *parent, int (*cmp) (const char *a, const char *b))
{
    if (parent)
        parent->children = merge_sort (parent->children, cmp);
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
apteryx_cas_tree (GNode* root, uint64_t ts)
{
    const char *path = NULL;
    char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Set set = APTERYX__SET__INIT;
    protobuf_c_boolean is_done = 0;
    bool rc = true;
    int i;

    ASSERT ((ref_count > 0), return false, "SET_TREE: Not initialised\n");
    ASSERT (root, return false, "SET_TREE: Invalid parameters\n");

    DEBUG ("SET_TREE: %d paths\n", g_node_n_nodes (root, G_TRAVERSE_LEAVES));

    /* Check path */
    path = validate_path (APTERYX_NAME (root), &url);
    if (!path || path[strlen(path) - 1] == '/')
    {
        ERROR ("SET_TREE: invalid path (%s)!\n", path);
        assert (!apteryx_debug || path);
        free (url);
        return false;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("SET_TREE: Falied to connect to server: %s\n", strerror (errno));
        free (url);
        return false;
    }

    /* Create the list of Paths/Value's */
    set.n_sets = g_node_n_nodes (root, G_TRAVERSE_LEAVES);
    set.sets = malloc (set.n_sets * sizeof (Apteryx__PathValue *));
    set.n_sets = 0;
    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _set_multi, &set);
    set.ts = ts;
    apteryx__server__set (rpc_client, &set, handle_ok_response, &is_done);
    if (!is_done)
    {
        DEBUG ("SET_TREE: Failed %s\n", strerror(errno));
        rpc_client_release (rpc, rpc_client, false);
        rc = false;
    }
    else
    {
        rpc_client_release (rpc, rpc_client, true);
    }
    free (url);

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

bool
apteryx_set_tree (GNode* root)
{
    return apteryx_cas_tree (root, UINT64_MAX);
}

typedef struct _traverse_data_t
{
    GNode* root;
    bool done;
} traverse_data_t;

static void
path_to_node (GNode* root, const char *path, const char *value)
{
    const char *next;
    GNode *node;

    if (path && path[0] == '/')
    {
        path++;
        next = strchr (path, '/');
        if (!next)
        {
            APTERYX_LEAF (root, strdup (path), strdup (value));
        }
        else
        {
            char *name = strndup (path, next - path);
            for (node = g_node_first_child (root); node;
                    node = g_node_next_sibling (node))
            {
                if (strcmp (APTERYX_NAME (node), name) == 0)
                {
                    root = node;
                    free (name);
                    break;
                }
            }
            if (!node)
            {
                root = APTERYX_NODE (root, name);
            }
            path_to_node (root, next, value);
        }
    }
    return;
}

static void
handle_traverse_response (const Apteryx__TraverseResult *result, void *closure_data)
{
    traverse_data_t *data = (traverse_data_t *)closure_data;
    const char *path = APTERYX_NAME (data->root);
    int i;

    data->done = false;
    if (result == NULL)
    {
        ERROR ("TRAVERSE: Error processing request.\n");
        errno = -ETIMEDOUT;
        apteryx_free_tree (data->root);
        data->root = NULL;
    }
    else if (result->pv == NULL)
    {
        DEBUG ("    = (null)\n");
        apteryx_free_tree (data->root);
        data->root = NULL;
        data->done = true;
    }
    else if (result->n_pv == 1 &&
        strcmp (path, result->pv[0]->path) == 0)
    {
        Apteryx__PathValue *pv = result->pv[0];
        DEBUG ("  %s = %s\n", pv->path, pv->value);
        g_node_append_data (data->root, (gpointer)strdup (pv->value));
        data->done = true;
    }
    else if (result->n_pv != 0)
    {
        int slen = strlen (path);
        for (i = 0; i < result->n_pv; i++)
        {
            Apteryx__PathValue *pv = result->pv[i];
            DEBUG ("  %s = %s\n", pv->path + slen, pv->value);
            path_to_node (data->root, pv->path + slen, pv->value);
        }
        data->done = true;
    }
}

GNode*
apteryx_get_tree (const char *path)
{
    char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Traverse traverse = APTERYX__TRAVERSE__INIT;
    traverse_data_t data = {0};

    ASSERT ((ref_count > 0), return NULL, "GET_TREE: Not initialised\n");
    ASSERT (path, return NULL, "GET_TREE: Invalid parameters\n");

    DEBUG ("GET_TREE: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path || path[strlen(path) - 1] == '/')
    {
        ERROR ("GET_TREE: invalid path (%s)!\n", path);
        assert (!apteryx_debug || path);
        free (url);
        return false;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("TRAVERSE: Falied to connect to server: %s\n", strerror (errno));
        free (url);
        return false;
    }
    traverse.path = (char *) path;
    data.root = g_node_new (strdup (path));
    apteryx__server__traverse (rpc_client, &traverse, handle_traverse_response, &data);
    if (!data.done)
    {
        ERROR ("TRAVERSE: No response\n");
        rpc_client_release (rpc, rpc_client, false);
        apteryx_free_tree (data.root);
        data.root = NULL;
        free (url);
        return NULL;
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);
    return data.root;
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

    data->done = false;
    data->paths = NULL;
    if (result == NULL)
    {
        ERROR ("SEARCH: Error processing request.\n");
        errno = -ETIMEDOUT;
    }
    else if (result->paths == NULL)
    {
        DEBUG ("    = (null)\n");
        data->done = true;
    }
    else if (result->n_paths != 0)
    {
        for (i = 0; i < result->n_paths; i++)
        {
            DEBUG ("    = %s\n", result->paths[i]);
            data->paths = g_list_append (data->paths,
                              (gpointer) strdup (result->paths[i]));
        }
        data->done = true;
    }
}

GList *
apteryx_search (const char *path)
{
    char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Search search = APTERYX__SEARCH__INIT;
    search_data_t data = {0};

    ASSERT ((ref_count > 0), return NULL, "SEARCH: Not initialised\n");
    ASSERT (path, return NULL, "SEARCH: Invalid parameters\n");

    DEBUG ("SEARCH: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("SEARCH: invalid root (%s)!\n", path);
        free (url);
        assert (!apteryx_debug || path);
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
        free (url);
        ERROR ("SEARCH: invalid root (%s)!\n", path);
        assert(!apteryx_debug || path[0] == '/');
        assert(!apteryx_debug || path[strlen (path) - 1] == '/');
        assert(!apteryx_debug || strstr (path, "//") == NULL);
        return NULL;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("SEARCH: Failed to connect to server: %s\n", strerror (errno));
        free (url);
        return false;
    }
    search.path = (char *) path;
    apteryx__server__search (rpc_client, &search, handle_search_response, &data);
    if (!data.done)
    {
        ERROR ("SEARCH: No response\n");
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return NULL;
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Result */
    return data.paths;
}

char *
apteryx_search_simple (const char *path)
{
    GList *paths = apteryx_search (path);
    char *tmp = NULL, *result = NULL;
    GList *iter;

    if (!paths)
    {
        return NULL;
    }
    for (iter = g_list_first (paths); iter; iter = g_list_next (iter))
    {
        if (result)
        {
            ASSERT (asprintf (&tmp, "%s\n%s", result, (char *) iter->data) > 0,
                    tmp = NULL, "SEARCH: Memory allocation failure\n");
        }
        else
        {
            ASSERT (asprintf (&tmp, "%s", (char *) iter->data) > 0, tmp = NULL,
                    tmp = NULL, "SEARCH: Memory allocation failure\n");
        }
        if (result)
            free (result);
        result = tmp;
        tmp = NULL;
    }
    g_list_free_full (paths, free);

    return result;
}


GList *
apteryx_find (const char *path, const char *value)
{
    char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Find find = APTERYX__FIND__INIT;
    search_data_t data = {0};
    Apteryx__PathValue pv = {
            .base.descriptor = &apteryx__path_value__descriptor,
            .path = (char*) path,
            .value = (char*) value
    };

    char *tmp_path = NULL;

    ASSERT ((ref_count > 0), return NULL, "FIND: Not initialised\n");
    ASSERT (path, return NULL, "FIND: Invalid parameters\n");
    ASSERT (value, return NULL, "FIND: Invalid parameters\n");

    DEBUG ("FIND: %s = %s\n", path, value);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("FIND: invalid root (%s)!\n", path);
        free (url);
        assert (!apteryx_debug || path);
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
             strstr (path, "//") != NULL)
    {
        free (url);
        ERROR ("FIND: invalid root (%s)!\n", path);
        assert(!apteryx_debug || path[0] == '/');
        assert(!apteryx_debug || strstr (path, "//") == NULL);
        return NULL;
    }

    /* Remove the trailing key */
    tmp_path = strdup (path);
    if (strrchr (tmp_path, '*'))
        *strrchr (tmp_path, '*') = '\0';

    find.path = tmp_path;
    find.n_matches = 1;
    find.matches = malloc (find.n_matches * sizeof (Apteryx__PathValue *));
    find.matches[0] = &pv;

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("FIND: Failed to connect to server: %s\n", strerror (errno));
        free (url);
        free (tmp_path);
        return false;
    }

    apteryx__server__find (rpc_client, &find, handle_search_response, &data);
    if (!data.done)
    {
        ERROR ("FIND: No response\n");
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        free (tmp_path);
        return NULL;
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    free (tmp_path);
    free (find.matches);

    /* Result */
    return data.paths;
}

static gboolean
_find_multi (GNode *node, gpointer data)
{
    Apteryx__Find *find = (Apteryx__Find *)data;

    if (APTERYX_HAS_VALUE(node))
    {
        char *path = apteryx_node_path (node);
        Apteryx__PathValue *pv = calloc (1, sizeof (Apteryx__PathValue));
        DEBUG ("FIND_TREE: %s = %s\n", path, APTERYX_VALUE (node));
        pv->base.descriptor = &apteryx__path_value__descriptor;
        pv->path = (char *) path;
        pv->value = (char *) APTERYX_VALUE (node);
        find->matches[find->n_matches++] = pv;
    }
    return FALSE;
}

GList *
apteryx_find_tree (GNode *root)
{
    char *url = NULL;
    ProtobufCService *rpc_client;
    Apteryx__Find find = APTERYX__FIND__INIT;
    search_data_t data = {0};
    const char *path = APTERYX_NAME(root);
    int i;

    ASSERT ((ref_count > 0), return NULL, "FIND: Not initialised\n");
    ASSERT (path, return NULL, "FIND: Invalid parameters\n");

    DEBUG ("FIND_TREE: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);

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
             strstr (path, "//") != NULL)
    {
        free (url);
        ERROR ("FIND: invalid root (%s)!\n", path);
        assert(!apteryx_debug || path[0] == '/');
        assert(!apteryx_debug || strstr (path, "//") == NULL);
        return NULL;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("FIND: Failed to connect to server: %s\n", strerror (errno));
        free (url);
        return false;
    }

    find.path = (char *) path;
    find.n_matches = g_node_n_nodes (root, G_TRAVERSE_LEAVES);
    find.matches = malloc (find.n_matches * sizeof (Apteryx__PathValue *));
    find.n_matches = 0;
    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _find_multi, &find);

    apteryx__server__find (rpc_client, &find, handle_search_response, &data);
    if (!data.done)
    {
        ERROR ("FIND: No response\n");
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return NULL;
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Cleanup message */
    for (i = 0; i < find.n_matches; i++)
    {
        Apteryx__PathValue *pv = find.matches[i];
        free (pv->path);
        free (pv);
    }
    free (find.matches);

    /* Result */
    return data.paths;
}

static bool
add_callback (const char *type, const char *path, void *cb)
{
    size_t pid = getpid ();
    char _path[PATH_MAX];

    ASSERT ((ref_count > 0), return false, "ADD_CB: Not initialised\n");
    ASSERT (type, return false, "ADD_CB: Invalid type\n");
    ASSERT (path, return false, "ADD_CB: Invalid path\n");
    ASSERT (cb, return false, "ADD_CB: Invalid callback\n");

    if (!bound)
    {
        char * uri = NULL;

        /* Bind to the default uri for this client */
        pthread_mutex_lock (&lock);
        if (asprintf ((char **) &uri, APTERYX_SERVER".%"PRIu64, (uint64_t) getpid ()) <= 0
                || !rpc_server_bind (rpc, uri, uri))
        {
            ERROR ("Failed to bind uri %s\n", uri);
            pthread_mutex_unlock (&lock);
            free ((void*) uri);
            return false;
        }
        DEBUG ("Bound to uri %s\n", uri);
        pthread_mutex_unlock (&lock);
        free ((void*) uri);
        bound = true;
    }

    if (sprintf (_path, "%s/%zX-%zX-%zX",
            type, (size_t)pid, (size_t)cb, (size_t)g_str_hash (path)) <= 0)
        return false;
    if (!apteryx_set (_path, path))
        return false;
    have_callbacks = true;
    return true;
}

static bool
delete_callback (const char *type, const char *path,  void *cb)
{
    char _path[PATH_MAX];

    ASSERT ((ref_count > 0), return false, "DEL_CB: Not initialised\n");
    ASSERT (type, return false, "DEL_CB: Invalid type\n");
    ASSERT (path, return false, "DEL_CB: Invalid path\n");
    ASSERT (cb, return false, "DEL_CB: Invalid callback\n");

    if (sprintf (_path, "%s/%zX-%zX-%zX",
            type, (size_t)getpid (), (size_t)cb, (size_t)g_str_hash (path)) <= 0)
        return false;
    if (!apteryx_set (_path, NULL))
        return false;
    return true;
}

bool
apteryx_index (const char *path, apteryx_index_callback cb)
{
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
        errno = -ETIMEDOUT;
    }
    else
    {
        *data = result->value;
    }
}

uint64_t
apteryx_timestamp (const char *path)
{
    char *url = NULL;
    uint64_t value = 0;
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;

    ASSERT ((ref_count > 0), return 0, "TIMESTAMP: Not initialised\n");
    ASSERT (path, return 0, "TIMESTAMP: Invalid parameters\n");

    DEBUG ("TIMESTAMP: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    /* if path is empty, or path ends in '/' but is not the root db path (ie "/") */
    if (!path ||
        ((path[strlen(path)-1] == '/') && strlen(path) > 1))
    {
        ERROR ("TIMESTAMP: invalid path (%s)!\n", path);
        free (url);
        assert (!apteryx_debug || path);
        return 0;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("TIMESTAMP: Falied to connect to server: %s\n", strerror (errno));
        free (url);
        return 0;
    }
    get.path = (char *) path;
    apteryx__server__timestamp (rpc_client, &get, handle_timestamp_response, &value);
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    DEBUG ("    = %"PRIu64"\n", value);
    return value;
}
