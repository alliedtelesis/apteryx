/**
 * @file apteryx.c
 * Server application for Apteryx.
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
#include <ctype.h>
#include <errno.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include "apteryx.h"
#include "apteryx.pb-c.h"
#include "internal.h"

/* Debug */
bool debug = false;

/* Run while true */
static bool running = true;
static int stopfd = -1;

/* Statistics and debug */
static counters_t counters = {};

/* Watch and provide callbacks */
static GList *watch_list = NULL;
static GList *provide_list = NULL;
static pthread_mutex_t list_lock;

/* Callback */
typedef struct _cb_info_t
{
    const char *path;
    uint64_t id;
    uint64_t cb;
    uint64_t priv;
    uint64_t count;
} cb_info_t;

/* Free cb info */
static void
cb_info_destroy (gpointer data)
{
    cb_info_t *info = (cb_info_t*)data;
    free ((void *) info->path);
    free (info);
}

static gpointer
cb_info_copy (cb_info_t *cb)
{
    cb_info_t *copy = calloc (1, sizeof (*copy));
    *copy = *cb;
    if (cb->path)
        copy->path = strdup (cb->path);
    return (gpointer)copy;
}

static cb_info_t *
cb_info_find (GList *list, const char *path, uint64_t id)
{
    GList *iter = NULL;
    cb_info_t *info;
    for (iter = list; iter; iter = iter->next)
    {
        /* We only allow a single watcher per table/key pair per socket */
        info = (cb_info_t *) iter->data;
        if (info->id == id && strcmp (info->path, path) == 0)
            break;
        info = NULL;
    }
    return info;
}

static void
handle_set_response (const Apteryx__OKResult *result, void *closure_data)
{
    *(protobuf_c_boolean *) closure_data = (result != NULL);
}

static void
notify_watchers (const char *path)
{
    GList *watchers = NULL;
    GList *iter = NULL;
    unsigned char *value = NULL;
    size_t vsize = 0;

    /* Make sure we have at least one watcher */
    if (g_list_length (watch_list) == 0)
        return;

    /* Check each watcher */
    pthread_mutex_lock (&list_lock);
    for (iter = watch_list; iter; iter = g_list_next (iter))
    {
        cb_info_t *watcher = iter->data;
        const char *ptr = NULL;
        size_t len;
        bool match = false;

        /* exact path match */
        if (strcmp (watcher->path, path) == 0)
        {
            match = true;
        }
        else
        {
            len = strlen (watcher->path);
            ptr = watcher->path + len - 1;

            /* wildcard path match (recursive) */
            if (*ptr == '*')
            {
                if (strncmp (path, watcher->path, len - 1) == 0)
                {
                    match = true;
                }

            }
            /* one-level-deep path match (non recursive) */
            else if (*ptr == '/')
            {

                if ((strncmp (path, watcher->path, len - 1) == 0) &&
                    !strchr (path + len, '/'))
                {
                    match = true;
                }
            }
        }

        if (match)
        {
            watchers = g_list_append (watchers, cb_info_copy (watcher));
            watcher->count++;
        }
    }
    pthread_mutex_unlock (&list_lock);

    /* Make sure we have at least one matched watcher */
    if (g_list_length (watchers) == 0)
    {
        counters.watched_no_match++;
        return;
    }

    /* Find the new value for this path */
    value = NULL;
    vsize = 0;
    db_get (path, &value, &vsize);

    /* Call each watcher */
    for (iter = watchers; iter; iter = g_list_next (iter))
    {
        cb_info_t *watcher = iter->data;
        ProtobufCService *rpc_client;
        protobuf_c_boolean is_done = false;
        Apteryx__Watch watch = APTERYX__WATCH__INIT;
        char service_name[64];

        /* Check for local provider */
        if (watcher->id == getpid ())
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) (long) watcher->cb;
            DEBUG ("PROVIDE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                    watcher->path, watcher->id, watcher->cb, watcher->priv);
            cb (path, (void *) (long) watcher->priv, value, vsize);
            continue;
        }

        DEBUG ("WATCH CB %s (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
               watcher->path, watcher->id, watcher->cb, watcher->priv);

        /* Setup IPC */
        sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", watcher->id);
        rpc_client = rpc_connect_service (service_name, &apteryx__client__descriptor);
        if (!rpc_client)
        {
            ERROR ("Invalid WATCH CB %s (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                   watcher->path, watcher->id, watcher->cb, watcher->priv);
            pthread_mutex_lock (&list_lock);
            watcher = cb_info_find (watch_list, watcher->path, watcher->id);
            if (watcher)
            {
                watch_list = g_list_remove (watch_list, watcher);
                cb_info_destroy ((gpointer) watcher);
            }
            pthread_mutex_unlock (&list_lock);
            counters.watched_no_handler++;
            continue;
        }

        /* Do remote watch */
        watch.path = (char *)path;
        watch.value.data = value;
        watch.value.len = vsize;
        watch.id = watcher->id;
        watch.cb = watcher->cb;
        watch.priv = watcher->priv;
        apteryx__client__watch (rpc_client, &watch, handle_set_response, &is_done);
        if (!is_done)
        {
            ERROR ("Failed to notify watcher for path \"%s\"\n", (char *)path);
        }

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);
        counters.watched++;
    }
    g_list_free_full (watchers, cb_info_destroy);

    /* Free memory if allocated */
    if (value)
        free (value);
}

static unsigned char *_get_value = NULL;
static size_t _get_length = 0;
static void
handle_get_response (const Apteryx__GetResult *result, void *closure_data)
{
    if (result == NULL)
    {
        ERROR ("GET: Error processing request.\n");
    }
    else if (result->value.len != 0)
    {
        if (_get_value)
            free (_get_value);
        _get_length = result->value.len;
        _get_value = malloc (_get_length);
        memcpy (_get_value, result->value.data, _get_length);
    }
    *(protobuf_c_boolean *) closure_data = 1;
}

static bool
provide_get (const char *path, unsigned char **value, size_t *vsize)
{
    GList *iter = NULL;

    for (iter = provide_list; iter; iter = g_list_next (iter))
    {
        cb_info_t *provider = iter->data;
        int len = strlen (provider->path);
        const char *ptr = provider->path + len - 1;

        if (strcmp (provider->path, path) == 0 ||
            (*ptr == '*' && strncmp (path, provider->path, len - 1) == 0))
        {
            ProtobufCService *rpc_client;
            protobuf_c_boolean is_done = false;
            Apteryx__Provide provide = APTERYX__PROVIDE__INIT;
            char service_name[64];

            /* Counters */
            counters.provided++;
            provider->count++;

            /* Start clear */
            if (_get_value)
                free (_get_value);
            _get_value = NULL;

            /* Check for local provider */
            if (provider->id == getpid ())
            {
                apteryx_provide_callback cb = (apteryx_provide_callback) (long) provider->cb;
                DEBUG ("PROVIDE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                                           provider->path, provider->id, provider->cb, provider->priv);
                cb (path, (void *) (long) provider->priv, value, vsize);
                break;
            }

            DEBUG ("PROVIDE CB \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                   provider->path, provider->id, provider->cb, provider->priv);

            /* Setup IPC */
            sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", provider->id);
            rpc_client = rpc_connect_service (service_name, &apteryx__client__descriptor);
            if (!rpc_client)
            {
                ERROR ("Invalid PROVIDE CB %s (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                       provider->path, provider->id, provider->cb, provider->priv);
                provide_list = g_list_remove (provide_list, provider);
                cb_info_destroy ((gpointer) provider);
                counters.provided_no_handler++;
                continue;
            }

            /* Do remote get */
            provide.path = (char *) path;
            provide.id = provider->id;
            provide.cb = provider->cb;
            provide.priv = provider->priv;
            apteryx__client__provide (rpc_client, &provide,
                                      handle_get_response, &is_done);
            if (!is_done)
            {
                ERROR ("No response from provider\n");
            }

            /* Destroy the service */
            protobuf_c_service_destroy (rpc_client);

            /* Result */
            if (_get_value)
            {
                *vsize = _get_length;
                *value = _get_value;
                _get_value = NULL;
                break;
            }
        }
    }
    return true;
}

static void
apteryx__set (Apteryx__Server_Service *service,
              const Apteryx__Set *set,
              Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;

    /* Check parameters */
    if (set == NULL || set->path == NULL)
    {
        ERROR ("SET: Invalid parameters.\n");
        closure (NULL, closure_data);
        counters.set_invalid++;
        return;
    }
    counters.set++;

    DEBUG ("SET: %s = %s\n", set->path, bytes_to_string (set->value.data, set->value.len));

    /* Add/Delete to/from database */
    if (set->value.len)
        db_add (set->path, set->value.data, set->value.len);
    else
        db_delete (set->path);

    /* Return result */
    closure (&result, closure_data);

    /* Notify watchers */
    notify_watchers (set->path);
    return;
}

static void
apteryx__get (Apteryx__Server_Service *service,
              const Apteryx__Get *get,
              Apteryx__GetResult_Closure closure, void *closure_data)
{
    Apteryx__GetResult result = APTERYX__GET_RESULT__INIT;
    unsigned char *value = NULL;
    size_t vsize = 0;

    /* Check parameters */
    if (get == NULL || get->path == NULL)
    {
        ERROR ("GET: Invalid parameters.\n");
        closure (NULL, closure_data);
        counters.get_invalid++;
        return;
    }
    counters.get++;

    DEBUG ("GET: %s\n", get->path);

    /* Lookup value */
    value = NULL;
    vsize = 0;
    if (!db_get (get->path, &value, &vsize))
    {
        if (!provide_get (get->path, &value, &vsize))
        {
            DEBUG ("GET: not in database or provided\n");
        }
    }

    /* Send result */
    DEBUG ("     = %s\n", bytes_to_string (value, vsize));
    result.value.data = value;
    result.value.len = vsize;
    closure (&result, closure_data);
    if (value)
        free (value);
    return;
}

static void
apteryx__search (Apteryx__Server_Service *service,
                 const Apteryx__Search *search,
                 Apteryx__SearchResult_Closure closure, void *closure_data)
{
    Apteryx__SearchResult result = APTERYX__SEARCH_RESULT__INIT;
    GList *results = NULL;
    GList *iter = NULL;
    int i;
    (void) service;

    /* Check parameters */
    if (search == NULL || search->path == NULL)
    {
        ERROR ("SEARCH: Invalid parameters.\n");
        closure (NULL, closure_data);
        counters.search_invalid++;
        return;
    }
    counters.search++;

    DEBUG ("SEARCH: %s\n", search->path);

    /* Lookup search */
    results = db_search (search->path);
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

    /* Send result */
    closure (&result, closure_data);
    g_list_free_full (results, free);
    if (result.paths)
        free (result.paths);
    return;
}

static void
apteryx__watch (Apteryx__Server_Service *service,
                const Apteryx__Watch *watch,
                Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    cb_info_t *info = NULL;

    /* Check parameters */
    if (watch == NULL || watch->path == NULL)
    {
        ERROR ("WATCH: Invalid parameters.\n");
        closure (NULL, closure_data);
        counters.watch_invalid++;
        return;
    }
    counters.watch++;

    DEBUG ("WATCH %s (0x%"PRIx64",0x%"PRIx64")\n", watch->path, watch->id, watch->cb);

    /* Find an existing watcher */
    pthread_mutex_lock (&list_lock);
    info = cb_info_find (watch_list, watch->path, watch->id);

    /* Create */
    if (info == NULL && watch->cb != 0)
    {
        /* Add a new entry to our list */
        info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
        info->path = strdup (watch->path);
        info->id = watch->id;
        info->cb = watch->cb;
        info->priv = watch->priv;
        watch_list = g_list_prepend (watch_list, info);
    }
    /* Update */
    else if (info != NULL && watch->cb != 0)
    {
        /* Set the new cb and private pointer */
        info->id = watch->id;
        info->cb = watch->cb;
        info->priv = watch->priv;
    }
    /* Remove */
    else if (info != NULL)
    {
        /* Remove from list and free */
        watch_list = g_list_remove (watch_list, info);
        cb_info_destroy ((gpointer) info);
    }
    pthread_mutex_unlock (&list_lock);

    /* Return result */
    closure (&result, closure_data);
    return;
}

static void
apteryx__provide (Apteryx__Server_Service *service,
                  const Apteryx__Provide *provide,
                  Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    cb_info_t *info = NULL;

    /* Check parameters */
    if (provide == NULL || provide->path == NULL)
    {
        ERROR ("PROVIDE: Invalid parameters.\n");
        closure (NULL, closure_data);
        counters.provide_invalid++;
        return;
    }
    counters.provide++;

    DEBUG ("PROVIDE %s (0x%"PRIx64",0x%"PRIx64")\n", provide->path, provide->id, provide->cb);

    /* Find an existing provider */
    pthread_mutex_lock (&list_lock);
    info = cb_info_find (provide_list, provide->path, provide->id);

    /* Create */
    if (info == NULL && provide->cb != 0)
    {
        /* Add a new entry to our list */
        info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
        info->path = strdup (provide->path);
        info->id = provide->id;
        info->cb = provide->cb;
        info->priv = provide->priv;
        provide_list = g_list_prepend (provide_list, info);
    }
    /* Update */
    else if (info != NULL && provide->cb != 0)
    {
        /* Set the new cb and private pointer */
        info->id = provide->id;
        info->cb = provide->cb;
        info->priv = provide->priv;
    }
    /* Remove */
    else if (info != NULL)
    {
        /* Remove from list and free */
        provide_list = g_list_remove (provide_list, info);
        cb_info_destroy ((gpointer) info);
    }
    pthread_mutex_unlock (&list_lock);

    /* Return result */
    closure (&result, closure_data);
    return;
}

static void
_search_paths (GList **paths, const char *path)
{
    GList *children, *iter;
    children = db_search (path);
    for (iter = children; iter; iter = g_list_next (iter))
    {
        _search_paths (paths, (const char *) iter->data);
    }
    *paths = g_list_concat (*paths, children);
}

static void
apteryx__prune (Apteryx__Server_Service *service,
                const Apteryx__Prune *prune,
                Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    GList *paths = NULL, *iter;
    (void) service;

    /* Check parameters */
    if (prune == NULL || prune->path == NULL)
    {
        ERROR ("PRUNE: Invalid parameters.\n");
        closure (NULL, closure_data);
        counters.prune_invalid++;
        return;
    }
    counters.prune++;

    DEBUG ("PRUNE: %s\n", prune->path);

    /* Collect the list of deleted paths for notification */
    _search_paths (&paths, prune->path);

    /* Prune from database */
    db_delete (prune->path);

    /* Return result */
    closure (&result, closure_data);

    /* Call watchers for each pruned path */
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        notify_watchers ((const char *) iter->data);
    }
    g_list_free_full (paths, free);
    return;
}

static Apteryx__Server_Service apteryx_service = APTERYX__SERVER__INIT (apteryx__);

void
termination_handler (void)
{
    uint8_t dummy = 1;
    running = false;
    if (write (stopfd, &dummy, 1) !=1)
        ERROR ("Failed to stop server %s\n", strerror (errno));
}

void
help (void)
{
    printf ("Usage: apteryxd [-h] [-b] [-d] [-p <pidfile>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -p   use <pidfile> instead of /var/run/apteryxd.pid\n");
}

int
main (int argc, char **argv)
{
    const char *pid_file = "/var/run/apteryxd.pid";
    bool background = false;
    int pipefd[2];
    FILE *fp;
    int i;

    /* Parse options */
    while ((i = getopt (argc, argv, "hdbp:")) != -1)
    {
        switch (i)
        {
        case 'd':
            debug = true;
            background = false;
            break;
        case 'b':
            background = true;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case '?':
        case 'h':
        default:
            help ();
            return 0;
        }
    }

    /* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
    signal (SIGTERM, (__sighandler_t) termination_handler);
    signal (SIGINT, (__sighandler_t) termination_handler);
    signal (SIGPIPE, SIG_IGN);

    /* Daemonize */
    if (background && fork () != 0)
    {
        /* Parent */
        return 0;
    }

    /* Create pid file */
    if (background)
    {
        fp = fopen (pid_file, "w");
        fprintf (fp, "%d\n", getpid ());
        fclose (fp);
    }

    /* Initialise the database */
    db_init ();

    /* Create a lock for the shared lists */
    pthread_mutex_init (&list_lock, NULL);

    /* Create fd to stop server */
    if (pipe (pipefd) != 0)
    {
        ERROR ("Failed to create pipe\n");
        goto exit;
    }
    stopfd = pipefd[1];

    /* Create server and process requests - 4 threads */
    if (!rpc_provide_service (APTERYX_SERVER, (ProtobufCService *)&apteryx_service, 8, pipefd[0]))
    {
        ERROR ("Failed to start rpc service\n");
    }

exit:
    DEBUG ("Exiting\n");

    /* Close the pipe */
    close (pipefd[0]);
    close (pipefd[1]);

    /* Cleanup watchers and providers */
    g_list_free_full (watch_list, cb_info_destroy);
    g_list_free_full (provide_list, cb_info_destroy);

    /* Clean up the database */
    db_shutdown ();

    /* Remove the pid file */
    if (background)
        unlink (pid_file);

    return 0;
}
