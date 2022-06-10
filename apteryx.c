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

static pthread_mutex_t pending_watches_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t no_pending_watches = PTHREAD_COND_INITIALIZER;
static int pending_watch_count = 0;

/* Callback */
typedef struct _cb_t
{
    uint64_t ref;
    const char *path;
    bool value;
    void *fn;
    void *data;
    uint32_t flags;
} cb_t;
static uint64_t next_ref = 0;
static GList *cb_list = NULL;

static bool
find_callback (uint64_t ref, void **fn, void **data, bool *val, uint32_t *flags)
{
    bool rc = false;
    GList *iter;
    cb_t *cb;

    pthread_mutex_lock (&lock);
    for (iter = g_list_first (cb_list); iter; iter = g_list_next (iter))
    {
        cb = (cb_t *) iter->data;
        if (cb->ref == ref)
        {
            *fn = cb->fn;
            *data = cb->data;
            *val = cb->value;
            *flags = cb->flags;
            rc = true;
        }
    }
    pthread_mutex_unlock (&lock);
    return rc;
}

static void *
call_callback (uint64_t ref, const char *path, const char *value)
{
    void *fn = NULL;
    void *data = NULL;
    bool val = false;
    uint32_t flags = 0;

    if (!find_callback (ref, &fn, &data, &val, &flags) || fn == NULL)
    {
        DEBUG ("CB[%"PRIu64"]: not found\n", ref);
        return NULL;
    }

    if (val && data)
        return ((void*(*)(const char*, const char*, void*)) fn) (path, value, data);
    else if (val)
        return ((void*(*)(const char*, const char*)) fn) (path, value);
    else if (data)
        return ((void*(*)(const char*, void*)) fn) (path, data);
    else
        return ((void*(*)(const char*)) fn) (path);
}

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
        char *tmp = strstr (path + 6, ":/");
        if (!tmp)
        {
            ERROR ("Invalid path (%s)!\n", path);
            return NULL;
        }
        path = tmp + 1;
        if (url)
        {
            tmp = strstr (*url + 6, ":/");
            if (tmp != NULL)
            {
                tmp[0] = '\0';
            }
        }
        return path;
    }
    else if (path)
    {
        ERROR ("Invalid path (%s)!\n", path);
    }
    return NULL;
}

static bool
handle_index (rpc_message msg)
{
    GList *results = NULL;
    uint64_t ref;
    const char *path;
    GList *iter = NULL;
    int i;

    /* Parse the parameters */
    ref = rpc_msg_decode_uint64 (msg);
    path = rpc_msg_decode_string (msg);
    assert (path);

    DEBUG ("INDEX CB: \"%s\" (0x%"PRIx64")\n", path, ref);

    /* Call the callback */
    results = (GList *) call_callback (ref, path, NULL);

    /* Return result */
    rpc_msg_reset (msg);
    for (i = 0, iter = results; iter; iter = g_list_next (iter), i++)
    {
        DEBUG ("         = %s\n", (char *) iter->data);
        rpc_msg_encode_string (msg, (char *)iter->data);
    }
    g_list_free_full (results, g_free);
    return true;
}

static bool
handle_watch (rpc_message msg)
{
    uint64_t ref;
    void *fn = NULL;
    void *data = NULL;
    bool val = false;
    uint32_t flags = 0;
    const char *path;
    const char *value;

    ref = rpc_msg_decode_uint64 (msg);
    if (!find_callback (ref, &fn, &data, &val, &flags) || fn == NULL)
    {
        DEBUG ("WATCH[%"PRIu64"]: cb not found\n", ref);
        /* Not much we can do but pretend we completed the callback */
        rpc_msg_reset (msg);
        return true;
    }

    pthread_mutex_lock (&pending_watches_lock);
    ++pending_watch_count;
    pthread_mutex_unlock (&pending_watches_lock);
    if (flags == 0)
    {
        path = rpc_msg_decode_string (msg);
        value = rpc_msg_decode_string (msg);
        while (path && value)
        {
            DEBUG ("WATCH CB \"%s\" = \"%s\" (0x%"PRIx64")\n", path, value, ref);
            if (value[0] == '\0')
                value = NULL;
            if (data)
                ((void*(*)(const char*, const char*, void*)) fn) (path, value, data);
            else
                ((void*(*)(const char*, const char*)) fn) (path, value);
            path = rpc_msg_decode_string (msg);
            value = rpc_msg_decode_string (msg);
        }
    }
    else
    {
        GNode *root = g_node_new (strdup ("/"));
        path = rpc_msg_decode_string (msg);
        while (path)
        {
            value = rpc_msg_decode_string (msg);
            apteryx_path_to_node (root, path, value);
            path = rpc_msg_decode_string (msg);
        }
        if (data)
            ((void*(*)(const GNode*, void*)) fn) (root, data);
        else
            ((void*(*)(const GNode*)) fn) (root);
    }
    pthread_mutex_lock (&pending_watches_lock);
    if (--pending_watch_count == 0)
        pthread_cond_signal(&no_pending_watches);
    pthread_mutex_unlock (&pending_watches_lock);
    rpc_msg_reset (msg);
    return true;
}

static bool
handle_validate (rpc_message msg)
{
    uint32_t result = 0;
    uint64_t ref;
    const char *path;
    const char *value;

    /* Parse the parameters */
    ref = rpc_msg_decode_uint64 (msg);
    path = rpc_msg_decode_string (msg);
    value = rpc_msg_decode_string (msg);
    assert (path && value);
    if (value && (value[0] == '\0'))
        value = NULL;

    DEBUG ("VALIDATE CB \"%s\" = \"%s\" (0x%"PRIx64")\n", path, value, ref);

    /* We want to wait for all pending watches to be processed */
    pthread_mutex_lock (&pending_watches_lock);
    if (pending_watch_count)
    {
        pthread_cond_wait (&no_pending_watches, &pending_watches_lock);
        pthread_mutex_unlock (&pending_watches_lock);
    }
    else
        pthread_mutex_unlock (&pending_watches_lock);

    /* Process callback */
    result = (uint32_t) (size_t) call_callback (ref, path, value);
    DEBUG (" = %d\n", result);
    rpc_msg_reset (msg);
    rpc_msg_encode_uint64 (msg, result);
    return true;
}

static bool
handle_refresh (rpc_message msg)
{
    uint64_t ref;
    const char *path;
    uint64_t timeout;

    /* Parse the parameters */
    ref = rpc_msg_decode_uint64 (msg);
    path = rpc_msg_decode_string (msg);
    assert (path);

    DEBUG ("REFRESH CB: \"%s\" (0x%"PRIx64")\n", path, ref);

    /* Process callback */
    timeout = (uint64_t) (size_t) call_callback (ref, path, NULL);
    rpc_msg_reset (msg);
    rpc_msg_encode_uint64 (msg, timeout);
    return true;
}

static bool
handle_provide (rpc_message msg)
{
    char *value;
    uint64_t ref;
    const char *path;

    /* Parse the parameters */
    ref = rpc_msg_decode_uint64 (msg);
    path = rpc_msg_decode_string (msg);
    assert (path);

    DEBUG ("PROVIDE CB: \"%s\" (0x%"PRIx64")\n", path, ref);

    /* Process callback */
    value = (char *) call_callback (ref, path, NULL);
    rpc_msg_reset (msg);
    if (value)
    {
        rpc_msg_encode_string (msg, value);
        free (value);
    }
    return true;
}

static bool
msg_handler (rpc_message msg)
{
    APTERYX_MODE mode = rpc_msg_decode_uint8 (msg);
    switch (mode)
    {
    case MODE_INDEX:
        return handle_index (msg);
    case MODE_WATCH:
    case MODE_WATCH_WITH_ACK:
        return handle_watch (msg);
    case MODE_VALIDATE:
        return handle_validate (msg);
    case MODE_REFRESH:
        return handle_refresh (msg);
    case MODE_PROVIDE:
        return handle_provide (msg);
    default:
        DEBUG ("MSG: Unexpected mode %d\n", mode);
        break;
    }
    return false;
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
        rpc = rpc_init (RPC_CLIENT_TIMEOUT_US, msg_handler);
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

    /* Ready to go */
    if (ref_count == 1)
        DEBUG ("Init: Initialised\n");
    return true;
}

bool
apteryx_shutdown (void)
{
    if (ref_count <= 0)
    {
        DEBUG ("SHUTDOWN: Not initialised\n");
        return false;
    }

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
    rpc_client rpc_client;
    rpc_message_t msg = {};
    int32_t result;

    ASSERT ((ref_count > 0), return false, "PRUNE: Not initialised\n");
    ASSERT (path, return false, "PRUNE: Invalid parameters\n");

    DEBUG ("PRUNE: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("PRUNE: invalid path!\n");
        assert (!apteryx_debug || path);
        return false;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("PRUNE: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return false;
    }
    rpc_msg_encode_uint8 (&msg, MODE_PRUNE);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("PRUNE: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return false;
    }
    result = rpc_msg_decode_uint64 (&msg);
    rpc_msg_reset (&msg);
    if (result < 0)
    {
        DEBUG ("PRUNE: Error response: %s\n", strerror (-result));
        errno = result;
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Success */
    return result == 0;
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
        fprintf (fp, "%-64s\t%s\n", path, value);
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
apteryx_set_full (const char *path, const char *value, uint64_t ts, bool ack)
{
    char *url = NULL;
    rpc_client rpc_client;
    rpc_message_t msg = {};
    int result = -ETIMEDOUT;

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
        ERROR ("SET: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return false;
    }
    rpc_msg_encode_uint8 (&msg, ack ? MODE_SET_WITH_ACK : MODE_SET);
    rpc_msg_encode_uint64 (&msg, ts);
    rpc_msg_encode_uint8 (&msg, rpc_value);
    rpc_msg_encode_string (&msg, path);
    if (value)
        rpc_msg_encode_string (&msg, value);
    else
        rpc_msg_encode_string (&msg, "");
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("SET: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return false;
    }
    result = rpc_msg_decode_uint64 (&msg);
    rpc_msg_reset (&msg);
    if (result < 0)
    {
        DEBUG ("SET: Error response: %s\n", strerror (-result));
        errno = result;
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Success */
    return result == 0;
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

char *
apteryx_get (const char *path)
{
    char *url = NULL;
    char *value = NULL;
    rpc_client rpc_client;
    rpc_message_t msg = {};

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
        ERROR ("GET: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return NULL;
    }
    rpc_msg_encode_uint8 (&msg, MODE_GET);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("GET: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return NULL;
    }
    value = rpc_msg_decode_string (&msg);
    if (value)
        value = strdup (value);
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
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

char *
apteryx_get_string_default (const char *path, const char *key, const char *deflt)
{
    char *value = NULL;
    value = apteryx_get_string (path, key);
    if (!value)
    {
        value = strdup (deflt);
    }
    return value;
}

int32_t
apteryx_get_int (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    char *v = NULL;
    char *rem = NULL;
    int32_t value = -1;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if (apteryx_debug)
        {
            errno = 0;
        }

        if ((v = apteryx_get (full_path)))
        {
            value = strtol ((char *) v, &rem, 0);

            if (*rem != '\0')
            {
                errno = -ERANGE;
                value = -1;
            }

            free (v);
        }
        else
        {
            errno = -ERANGE;
        }

        if (apteryx_debug && errno == -ERANGE)
        {
            DEBUG ("Cannot represent value as int: %s\n", v);
        }

        free (full_path);
    }
    return value;
}

int32_t
apteryx_get_int_default (const char *path, const char *key, int32_t deflt)
{
    int32_t value;
    int errno_old;

    errno_old = errno;
    errno = 0;
    value = apteryx_get_int (path, key);
    if (value == -1 && errno == -ERANGE)
    {
        value = deflt;
    }

    errno = errno_old;
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
apteryx_find_child (GNode *parent, const char *name)
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
            end ? "" : "/") >= 0)
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

static GNode *
_apteryx_path_node (GNode *parent, const char *path)
{
    char *name;
    GNode *node;
    size_t component_len = strchrnul (path, '/') - path;

    for (node = g_node_first_child (parent); node != NULL; node = node->next)
    {
        name = APTERYX_NAME (node);
        if (name != NULL && strncmp (name, path, component_len) == 0)
        {
            if (name[component_len] == '\0')
            {
                if (path[component_len] == '/')
                {
                    node = _apteryx_path_node (node, path + component_len + 1);
                }
                else if (path[component_len] != '\0')
                {
                    continue;
                }
                return node;
            }
        }
    }
    return NULL;
}

GNode *
apteryx_path_node (GNode *node, const char *path)
{
    GNode *found = NULL;
    char *node_name;
    size_t node_name_len;

    ASSERT ((ref_count > 0), return false, "PATH_NODE: Not initialised\n");
    ASSERT (node != NULL && path != NULL, return false, "PATH_NODE: Invalid parameters\n");

    /* Check path */
    path = validate_path (path, NULL);
    if (path == NULL)
    {
        ERROR ("PATH_NODE: invalid path!\n");
        assert (!apteryx_debug || path);
        return NULL;
    }

    node_name = APTERYX_NAME (node);
    if (node_name != NULL)
    {
        /* Passed node may not be a root node, skip past path slash */
        if (node_name[0] != '/')
        {
            path++;
        }

        node_name_len = strlen (node_name);
        if (strncmp (node_name, path, node_name_len - 1) == 0)
        {
            if (path[node_name_len] == '\0')
            {
                return node;
            }
            else if (path[node_name_len] == '/')
            {
                path += node_name_len;
            }
        }
        found = _apteryx_path_node (node, path + 1);
    }
    return found;
}

static void
_apteryx_print_tree (GNode *node, FILE *fp, int depth)
{
    if (node)
    {
        const char *name = APTERYX_NAME (node);
        if (depth == 0 && name[0] == '/')
            fprintf (fp, "%s\n", name + 1);
        else
            fprintf (fp, "%*s%s\n", depth * 2, " ", name);
        for (GNode *child = node->children; child; child = child->next)
        {
            _apteryx_print_tree (child, fp, depth + 1);
        }
    }
}

void
apteryx_print_tree (GNode *root, FILE *fp)
{
    _apteryx_print_tree (root, fp, 0);
}

static gboolean
_set_multi (GNode *node, gpointer data)
{
    rpc_message msg = (rpc_message) data;
    if (APTERYX_HAS_VALUE(node))
    {
        char *path = apteryx_node_path (node);
        DEBUG ("SET_TREE: %s = %s\n", path, APTERYX_VALUE (node));
        rpc_msg_encode_string (msg, path);
        /* A set-to-null is the same as setting to an empty string. */
        rpc_msg_encode_string (msg, APTERYX_VALUE (node) ? : "");
        free (path);
    }
    return FALSE;
}

bool
apteryx_set_tree_full (GNode* root, uint64_t ts, bool wait_for_completion)
{
    const char *path = NULL;
    char *old_root_name = NULL;
    char *url = NULL;
    rpc_client rpc_client;
    rpc_message_t msg = {};
    int32_t result = 0;

    ASSERT ((ref_count > 0), return false, "SET_TREE: Not initialised\n");
    ASSERT (root, return false, "SET_TREE: Invalid parameters\n");

    DEBUG ("SET_TREE: %d paths\n", g_node_n_nodes (root, G_TRAVERSE_LEAVES));

    /* Check path */
    path = validate_path (APTERYX_NAME (root), &url);
    if (path && strcmp (path, "/") == 0)
    {
        path = "";
    }
    if (!path || (strlen (path) > 0 && path[strlen(path) - 1] == '/'))
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
        ERROR ("SET_TREE: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return false;
    }

    /* Save sanitized root path (less URL) to root node */
    old_root_name = APTERYX_NAME (root);
    root->data = (char*) path;

    /* Create the list of Paths/Value's */
    rpc_msg_encode_uint8 (&msg, wait_for_completion ? MODE_SET_WITH_ACK : MODE_SET);
    rpc_msg_encode_uint64 (&msg, ts);
    rpc_msg_encode_tree (&msg, root);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("SET_TREE: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        root->data = old_root_name;
        free (url);
        return false;
    }
    result = rpc_msg_decode_uint64 (&msg);
    rpc_msg_reset (&msg);
    if (result < 0)
    {
        DEBUG ("SET_TREE: Error response: %s\n", strerror (-result));
        errno = result;
    }
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Reinstate original root name */
    root->data = old_root_name;

    /* Return result */
    return result == 0;
}

GNode*
apteryx_path_to_node (GNode* root, const char *path, const char *value)
{
    const char *next;
    GNode *node = NULL;
    GNode *rnode = NULL;
    const char *root_key = APTERYX_NAME(root);
    if (strcmp(root_key, "/") == 0)
        root_key = "";

    /* This root node has a big chunk of the key in it... */
    if (root_key[0])
    {
        if (strcmp(path, root_key) == 0)
        {
            GNode *v = g_node_new(g_strdup(value));
            g_node_prepend(root, v);
            return v;
        }
        else if (strncmp(path, root_key, strlen(root_key)) == 0 &&
                 path[strlen(root_key)] == '/')
        {
            return apteryx_path_to_node (root, path + strlen(root_key), value);
        }
    }

    if (path && path[0] == '/')
    {
        path++;
        next = strchr (path, '/');
        if (!next)
        {
            if (value)
            {
                rnode = APTERYX_LEAF (root, strdup (path), strdup (value));
            }
            else
            {
                rnode = APTERYX_NODE (root, strdup (path));
            }
        }
        else
        {
            char *name = strndup (path, next - path);
            for (node = g_node_first_child (root); node;
                    node = g_node_next_sibling (node))
            {
                if (g_strcmp0 (APTERYX_NAME (node), name) == 0)
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
            rnode = apteryx_path_to_node (root, next, value);
        }
    }
    return rnode;
}

static GNode *
parse_field (const char *path)
{
    GNode *rnode = NULL;
    GNode *child = NULL;
    const char *next = NULL;
    const char *sublist = NULL;
    char *name;

    /* Find name */
    sublist = strchr (path, '(');
    next = strchr (path, '/');
    if (sublist && (!next || sublist < next))
        name = strndup (path, sublist - path);
    else if (next)
        name = strndup (path, next - path);
    else
        name = strdup (path);

    /* Create the node */
    rnode = APTERYX_NODE (NULL, name);

    /* Process subpath */
    if (next)
    {
        child = parse_field (next + 1);
        if (!child)
        {
            free ((void *)rnode->data);
            g_node_destroy (rnode);
            return NULL;
        }
        g_node_prepend (rnode, child);
    }
    else if (sublist)
    {
        char *fields = g_strndup (sublist + 1, strlen (sublist) - 2);
        if (!apteryx_query_to_node (rnode, fields))
        {
            free ((void *)rnode->data);
            g_node_destroy (rnode);
            free (fields);
            return false;
        }
        free (fields);
    }

    return rnode;
}

static void
merge_node_into_parent (GNode *parent, GNode *node)
{
    for (GNode *pchild = parent->children; pchild; pchild = pchild->next)
    {
        if (g_strcmp0 (pchild->data, node->data) == 0)
        {
            /* Unlink all the children and add to the original parent */
            GList *children = NULL;
            for (GNode *nchild = node->children; nchild; nchild = nchild->next)
            {
                children = g_list_append (children, nchild);
            }
            for (GList *nchild = children; nchild; nchild = nchild->next)
            {
                g_node_unlink (nchild->data);
                merge_node_into_parent (pchild, nchild->data);
            }
            g_list_free (children);
            node->children = NULL;
            free ((void *)node->data);
            g_node_destroy (node);
            return;
        }
    }
    g_node_prepend (parent, node);
}

bool
apteryx_query_to_node (GNode *root, const char *query)
{
    const char *h, *t;
    bool skip = false;

    h = t = query;
    while (*h)
    {
        if (*(h + 1) == '(')
            skip = true;
        else if (*(h + 1) == '\0' || (!skip && *(h + 1) == ';'))
        {
            char *field = strndup (t, (h - t + 1));
            GNode *node = parse_field (field);
            free (field);
            if (!node)
                return false;
            merge_node_into_parent (root, node);
            t = h + 2;
        }
        else if (*(h + 1) == ')')
            skip = false;

        h++;
    }
    return true;
}

GNode*
apteryx_get_tree (const char *path)
{
    char *url = NULL;
    rpc_client rpc_client;
    rpc_message_t msg = {};
    GNode *root = NULL;

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
        return NULL;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("GET_TREE: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return NULL;
    }
    rpc_msg_encode_uint8 (&msg, MODE_TRAVERSE);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("GET_TREE: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return NULL;
    }

    /* Read tree from client */
    root = rpc_msg_decode_tree (&msg);

    /* rpc_msg_decode_tree compresses the trunk of the tree to be as short as possible,
     * reset the root node key here to match the request */
    if (root &&
        strlen(APTERYX_NAME(root)) > strlen(path) &&
        strncmp(APTERYX_NAME(root), path, strlen(path)) == 0)
    {
        char *ptr = NULL;
        char *chunk;
        char *broken_key = g_strdup(APTERYX_NAME(root) + strlen(path));
        GNode *old_root = root;
        GNode *new_root = APTERYX_NODE (NULL, g_strdup(path));
        root = new_root;

        chunk = strtok_r (broken_key, "/", &ptr);
        while (chunk)
        {
            /* Got something left after this chunk - add an intermediate node */
            if (strlen(ptr))
            {
                new_root = APTERYX_NODE (new_root, g_strdup(chunk));
            }
            else
            {
                /* Replace key in the old root (which now has parents) */
                g_free(old_root->data);
                old_root->data = g_strdup(chunk);
                g_node_prepend(new_root, old_root);
            }
            chunk = strtok_r (NULL, "/", &ptr);
        }
        g_free(broken_key);
    }
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    free (url);
    return root;
}


static gboolean
add_null_data (GNode *node, gpointer data)
{
    /* This turns the end of this tree into leaves */
    if (node->data)
        g_node_prepend_data(node, NULL);
    return false;
}

GNode *
apteryx_query (GNode *root)
{
    char *url = NULL;
    rpc_client rpc_client;
    rpc_message_t msg = { };
    const char *path = NULL;
    char *old_root_name = NULL;
    GNode *rroot = NULL;

    ASSERT ((ref_count > 0), return NULL, "QUERY: Not initialised\n");
    ASSERT (root, return NULL, "QUERY: Invalid parameters\n");

    DEBUG ("QUERY\n");

    /* Check path */
    path = validate_path (APTERYX_NAME (root), &url);
    if (path && strcmp (path, "/") == 0)
    {
        path = "";
    }
    else if (!path ||
             ((strlen (path) > 0) &&
              ((path[strlen (path) - 1] == '/') || path[0] != '/' ||
               strstr (path, "//") != NULL)))
    {
        free (url);
        ERROR ("QUERY: invalid root (%s)!\n", path);
        assert (!apteryx_debug || path[0] == '/');
        assert (!apteryx_debug || strstr (path, "//") == NULL);
        return NULL;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("QUERY: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return NULL;
    }

    /* Save sanitized root path (less URL) to query node */
    old_root_name = APTERYX_NAME (root);
    root->data = (char *) path;

    /* the g_node tree that gets passed in here it's a legal apteryx tree - leaf
     * nodes don't get created. We need them for the encode tree, so add them now
     */
    g_node_traverse (root, G_IN_ORDER, G_TRAVERSE_LEAVES, -1, add_null_data, NULL);

    rpc_msg_encode_uint8 (&msg, MODE_QUERY);
    rpc_msg_encode_tree (&msg, root);

    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("QUERY: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return NULL;
    }

    rroot = rpc_msg_decode_tree(&msg);
    char *chopped_path = g_strdup(path ?: "");
    char *first_asterisk = strstr(chopped_path, "/*");
    if (first_asterisk)
    {
        *first_asterisk = '\0';
    }

    /* Reset the root node to match the query. */
    if (rroot &&
        strlen(APTERYX_NAME(rroot)) > strlen(chopped_path) &&
        strncmp(APTERYX_NAME(rroot), chopped_path, strlen(chopped_path)) == 0)
    {
        char *ptr = NULL;
        char *chunk;
        char *broken_key = g_strdup(APTERYX_NAME(rroot) + strlen(chopped_path));
        GNode *old_root = rroot;
        GNode *new_root = APTERYX_NODE (NULL, g_strdup(chopped_path));
        rroot = new_root;

        chunk = strtok_r (broken_key, "/", &ptr);
        while (chunk)
        {
            /* Got something left after this chunk - add an intermediate node */
            if (strlen(ptr))
            {
                new_root = APTERYX_NODE (new_root, g_strdup(chunk));
            }
            else
            {
                /* Replace key in the old root (which now has parents) */
                g_free(old_root->data);
                old_root->data = g_strdup(chunk);
                g_node_prepend(new_root, old_root);
            }
            chunk = strtok_r (NULL, "/", &ptr);
        }
        g_free(broken_key);
    }

    /* Put the original root (query tree) name back */
    root->data = old_root_name;
    g_free(chopped_path);

    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    free (url);
    return rroot;
}

GList *
apteryx_search (const char *path)
{
    char *url = NULL;
    rpc_client rpc_client;
    rpc_message_t msg = {};
    GList *paths = NULL;

    ASSERT ((ref_count > 0), return NULL, "SEARCH: Not initialised\n");
    ASSERT (path, return NULL, "SEARCH: Invalid parameters\n");

    DEBUG ("SEARCH: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("SEARCH: invalid path!\n");
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
        ERROR ("SEARCH: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return NULL;
    }
    rpc_msg_encode_uint8 (&msg, MODE_SEARCH);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("SEARCH: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return NULL;
    }
    while ((path = rpc_msg_decode_string (&msg)) != NULL)
    {
        DEBUG ("    = %s\n", path);
        paths = g_list_prepend (paths, (gpointer) strdup (path));
    }
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Result */
    return paths;
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
		    "SEARCH: Memory allocation failure\n");
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
    rpc_client rpc_client;
    rpc_message_t msg = {};
    GList *paths = NULL;
    char *tmp_path = NULL;

    ASSERT ((ref_count > 0), return NULL, "FIND: Not initialised\n");
    ASSERT (path, return NULL, "FIND: Invalid parameters\n");
    ASSERT (value, return NULL, "FIND: Invalid parameters\n");

    DEBUG ("FIND: %s = %s\n", path, value);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("FIND: invalid path!\n");
        free (url);
        assert (!apteryx_debug || path);
        return NULL;
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
    tmp_path = g_strdup (path);
    if (strrchr (tmp_path, '*'))
        *strrchr (tmp_path, '*') = '\0';

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("FIND: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        free (tmp_path);
        return NULL;
    }
    rpc_msg_encode_uint8 (&msg, MODE_FIND);
    rpc_msg_encode_string (&msg, tmp_path);
    rpc_msg_encode_string (&msg, path);
    rpc_msg_encode_string (&msg, value);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("FIND: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (tmp_path);
        free (url);
        return NULL;
    }
    while ((path = rpc_msg_decode_string (&msg)) != NULL)
    {
        DEBUG ("    = %s\n", path);
        paths = g_list_prepend (paths, (gpointer) strdup (path));
    }
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    free (tmp_path);
    free (url);

    /* Result */
    return paths;
}

GList *
apteryx_find_tree (GNode *root)
{
    char *url = NULL;
    rpc_client rpc_client;
    rpc_message_t msg = {};
    const char *path = APTERYX_NAME (root);
    GList *paths = NULL;

    ASSERT ((ref_count > 0), return NULL, "FIND_TREE: Not initialised\n");
    ASSERT (path, return NULL, "FIND_TREE: Invalid parameters\n");

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
        ERROR ("FIND_TREE: invalid root (%s)!\n", path);
        assert(!apteryx_debug || path[0] == '/');
        assert(!apteryx_debug || strstr (path, "//") == NULL);
        return NULL;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("FIND_TREE: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return NULL;
    }
    rpc_msg_encode_uint8 (&msg, MODE_FIND);
    rpc_msg_encode_string (&msg, path);
    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _set_multi, &msg);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("FIND_TREE: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return NULL;
    }
    while ((path = rpc_msg_decode_string (&msg)) != NULL)
    {
        DEBUG ("    = %s\n", path);
        paths = g_list_prepend (paths, (gpointer) strdup (path));
    }
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    /* Result */
    return paths;
}

bool
add_callback (const char *type, const char *path, void *fn, bool value, void *data, uint32_t flags)
{
    size_t pid = getpid ();
    char _path[PATH_MAX];
    cb_t *cb;

    ASSERT ((ref_count > 0), return false, "ADD_CB: Not initialised\n");
    ASSERT (type, return false, "ADD_CB: Invalid type\n");
    ASSERT (path, return false, "ADD_CB: Invalid path\n");
    ASSERT (fn, return false, "ADD_CB: Invalid callback\n");

    pthread_mutex_lock (&lock);
    cb = g_malloc0 (sizeof (cb_t));
    cb->ref = next_ref++;
    cb->path = strdup (path);
    cb->fn = fn;
    cb->value = value;
    cb->data = data;
    cb->flags = flags;
    cb_list = g_list_prepend (cb_list, (void *) cb);
    if (!bound)
    {
        char * uri = NULL;

        /* Bind to the default uri for this client */
        if (asprintf ((char **) &uri, APTERYX_SERVER".%"PRIu64, (uint64_t) getpid ()) <= 0
                || !rpc_server_bind (rpc, uri, uri))
        {
            ERROR ("Failed to bind uri %s\n", uri);
            pthread_mutex_unlock (&lock);
            free ((void*) uri);
            return false;
        }
        DEBUG ("Bound to uri %s\n", uri);
        free ((void*) uri);
        bound = true;
    }
    pthread_mutex_unlock (&lock);

    if (sprintf (_path, "%s/%zX-%"PRIX64"-%zX",
            type, (size_t)pid, cb->ref, (size_t)g_str_hash (path)) <= 0)
        return false;
    if (!apteryx_set (_path, path))
        return false;
    have_callbacks = true;
    return true;
}

bool
delete_callback (const char *type, const char *path, void *fn, void *data)
{
    char _path[PATH_MAX];
    uint64_t ref;
    GList *iter;
    cb_t *cb;

    ASSERT ((ref_count > 0), return false, "DEL_CB: Not initialised\n");
    ASSERT (type, return false, "DEL_CB: Invalid type\n");
    ASSERT (path, return false, "DEL_CB: Invalid path\n");
    ASSERT (fn, return false, "DEL_CB: Invalid callback\n");

    pthread_mutex_lock (&lock);
    for (iter = g_list_first (cb_list); iter; iter = g_list_next (iter))
    {
        cb = (cb_t *) iter->data;
        if (cb->fn == fn && strcmp (cb->path, path) == 0 && cb->data == data)
        {
            cb_list = g_list_remove (cb_list, cb);
            break;
        }
        cb = NULL;
    }
    pthread_mutex_unlock (&lock);
    ASSERT (cb, return false, "CB: not found (%s)\n", path);
    ref = cb->ref;
    free ((void *) cb->path);
    free (cb);

    if (sprintf (_path, "%s/%zX-%"PRIX64"-%zX",
            type, (size_t)getpid (), ref, (size_t)g_str_hash (path)) <= 0)
        return false;
    if (!apteryx_set (_path, NULL))
        return false;
    return true;
}

bool
apteryx_index (const char *path, apteryx_index_callback cb)
{
    return add_callback (APTERYX_INDEXERS_PATH, path, (void *)cb, false, NULL, 0);
}

bool
apteryx_unindex (const char *path, apteryx_index_callback cb)
{
    return delete_callback (APTERYX_INDEXERS_PATH, path, (void *)cb, NULL);
}

bool
apteryx_watch (const char *path, apteryx_watch_callback cb)
{
    return add_callback (APTERYX_WATCHERS_PATH, path, (void *)cb, true, NULL, 0);
}

bool
apteryx_unwatch (const char *path, apteryx_watch_callback cb)
{
    return delete_callback (APTERYX_WATCHERS_PATH, path, (void *)cb, NULL);
}

bool
apteryx_watch_tree (const char *path, apteryx_watch_tree_callback cb)
{
    return add_callback (APTERYX_WATCHERS_PATH, path, (void *)cb, true, NULL, 1);
}

bool
apteryx_unwatch_tree (const char *path, apteryx_watch_tree_callback cb)
{
    return delete_callback (APTERYX_WATCHERS_PATH, path, (void *)cb, NULL);
}

bool
apteryx_validate (const char *path, apteryx_validate_callback cb)
{
    return add_callback (APTERYX_VALIDATORS_PATH, path, (void *)cb, true, NULL, 0);
}

bool
apteryx_unvalidate (const char *path, apteryx_validate_callback cb)
{
    return delete_callback (APTERYX_VALIDATORS_PATH, path, (void *)cb, NULL);
}

bool
apteryx_refresh (const char *path, apteryx_refresh_callback cb)
{
    return add_callback (APTERYX_REFRESHERS_PATH, path, (void *)cb, false, NULL, 0);
}

bool
apteryx_unrefresh (const char *path, apteryx_refresh_callback cb)
{
    return delete_callback (APTERYX_REFRESHERS_PATH, path, (void *)cb, NULL);
}

bool
apteryx_provide (const char *path, apteryx_provide_callback cb)
{
    return add_callback (APTERYX_PROVIDERS_PATH, path, (void *)cb, false, NULL, 0);
}

bool
apteryx_unprovide (const char *path, apteryx_provide_callback cb)
{
    return delete_callback (APTERYX_PROVIDERS_PATH, path, (void *)cb, NULL);
}

bool
apteryx_proxy (const char *path, const char *url)
{
    bool res = false;
    char *value = NULL;

    if (asprintf (&value, "%s:%s", url, path) <= 0)
        return false;
    res = add_callback (APTERYX_PROXIES_PATH, value,
            (void *)(size_t)g_str_hash (url), false, NULL, 0);
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
            (void *)(size_t)g_str_hash (url), NULL);
    free (value);
    return res;
}

uint64_t
apteryx_timestamp (const char *path)
{
    char *url = NULL;
    uint64_t value = 0;
    rpc_client rpc_client;
    rpc_message_t msg = {};

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
        ERROR ("TIMESTAMP: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return 0;
    }
    rpc_msg_encode_uint8 (&msg, MODE_TIMESTAMP);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("TIMESTAMP: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return 0;
    }
    value = rpc_msg_decode_uint64 (&msg);
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    DEBUG ("    = %"PRIu64"\n", value);
    return value;
}

uint64_t
apteryx_memuse (const char *path)
{
    char *url = NULL;
    uint64_t value = 0;
    rpc_client rpc_client;
    rpc_message_t msg = {};

    ASSERT ((ref_count > 0), return 0, "MEMUSE: Not initialised\n");
    ASSERT (path, return 0, "MEMUSE: Invalid parameters\n");

    DEBUG ("MEMUSE: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    /* if path is empty, or path ends in '/' but is not the root db path (ie "/") */
    if (!path ||
        ((path[strlen(path)-1] == '/') && strlen(path) > 1))
    {
        ERROR ("MEMUSE: invalid path (%s)!\n", path);
        free (url);
        assert (!apteryx_debug || path);
        return 0;
    }

    /* IPC */
    rpc_client = rpc_client_connect (rpc, url);
    if (!rpc_client)
    {
        ERROR ("MEMUSE: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
        free (url);
        return 0;
    }
    rpc_msg_encode_uint8 (&msg, MODE_MEMUSE);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("MEMUSE: No response Path(%s)\n", path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        free (url);
        return 0;
    }
    value = rpc_msg_decode_uint64 (&msg);
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    free (url);

    DEBUG ("    = %"PRIu64"\n", value);
    return value;
}
