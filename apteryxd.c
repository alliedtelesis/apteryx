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
counters_t counters = {};

/* Watch and provide callbacks */
GList *watch_list = NULL;
GList *validation_list = NULL;
GList *provide_list = NULL;
pthread_mutex_t list_lock;
static pthread_mutex_t validating;

static void
handle_validate_response (const Apteryx__ValidateResult *result, void *closure_data)
{
    *(int32_t *) closure_data = result->result;
}

static int
validate_set (const char *path, const char *value)
{
    GList *validators = NULL;
    GList *iter = NULL;
    int32_t result = 0;

    /* Make sure we have at least one watcher */
    if (g_list_length (validation_list) == 0)
    {
        return 0;
    }

    /* Check each watcher */
    pthread_mutex_lock (&list_lock);
    for (iter = validation_list; iter; iter = g_list_next (iter))
    {
        cb_info_t *validator = iter->data;
        const char *ptr = NULL;
        size_t len;
        bool match = false;

        /* exact path match */
        if (strcmp (validator->path, path) == 0)
        {
            match = true;
        }
        else
        {
            len = strlen (validator->path);
            ptr = validator->path + len - 1;

            /* wildcard path match (recursive) */
            if (*ptr == '*')
            {
                if (strncmp (path, validator->path, len - 1) == 0)
                {
                    match = true;
                }

            }
            /* one-level-deep path match (non recursive) */
            else if (*ptr == '/')
            {

                if ((strncmp (path, validator->path, len - 1) == 0) &&
                    !strchr (path + len, '/'))
                {
                    match = true;
                }
            }
        }

        if (match)
        {
            validators = g_list_append (validators, cb_info_copy (validator));
            validator->count++;
        }
    }
    pthread_mutex_unlock (&list_lock);

    /* Make sure we have at least one matched watcher */
    if (g_list_length (validators) == 0)
    {
        return 0;
    }

    /* Protect sensitive values with this lock - released in apteryx_set */
    DEBUG("SET: locking mutex\n");
    pthread_mutex_lock(&validating);
    DEBUG("SET: lock taken\n");

    /* Call each validator */
    for (iter = validators; iter; iter = g_list_next (iter))
    {
        cb_info_t *validator = iter->data;
        ProtobufCService *rpc_client;
        Apteryx__Validate validate = APTERYX__VALIDATE__INIT;
        char service_name[64];

        /* Check for local provider */
        if (validator->id == getpid ())
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) (long) validator->cb;
            DEBUG ("PROVIDE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                    validator->path, validator->id, validator->cb, validator->priv);
            cb (path, (void *) (long) validator->priv, value);
            continue;
        }

        DEBUG ("VALIDATE CB %s = %s (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                 validator->path, value,validator->id, validator->cb, validator->priv);

        /* Setup IPC */
        sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", validator->id);
        DEBUG ("VALIDATE CB - connecting to %s\n", service_name);
        rpc_client = rpc_connect_service (service_name, &apteryx__client__descriptor);
        if (!rpc_client)
        {
            ERROR ("Invalid VALIDATE CB %s (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                    validator->path, validator->id, validator->cb, validator->priv);
            pthread_mutex_lock (&list_lock);
            validator = cb_info_find (watch_list, validator->path, validator->cb, validator->id);
            if (validator)
            {
                watch_list = g_list_remove (validation_list, validator);
                cb_info_destroy ((gpointer) validator);
            }
            pthread_mutex_unlock (&list_lock);
            continue;
        }
        DEBUG ("VALIDATE CB - connected to %s\n", service_name);
        /* Do remote validate */
        validate.path = (char *)path;
        validate.value = value ? strdup(value) : NULL;
        validate.id = validator->id;
        validate.cb = validator->cb;
        apteryx__client__validate (rpc_client, &validate, handle_validate_response, &result);
        if (result < 0)
        {
            DEBUG ("Set of %s to %s rejected by process %"PRIu64" (%d)\n", (char *)path, (char*)value, validator->id, result);
            /* exit, cleaning up on the way out */
            /* Destroy the service */
            protobuf_c_service_destroy (rpc_client);
            INC_COUNTER (counters.validation_failed);
            break;
        }
        else
        {
            DEBUG("callback returned %d\n", result);
        }

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);
        INC_COUNTER (counters.validation);
    }
    g_list_free_full (validators, cb_info_destroy);

    DEBUG("returning %d\n", result < 0 ? result : 1);

    /* this one is fine, but lock is still held */
    return result < 0 ? result : 1;
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
    char *value = NULL;
    size_t vsize;

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
        INC_COUNTER (counters.watched_no_match);
        return;
    }

    /* Find the new value for this path */
    value = NULL;
    vsize = 0;
    db_get (path, (unsigned char**)&value, &vsize);

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
            DEBUG ("WATCH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                    watcher->path, watcher->id, watcher->cb, watcher->priv);
            cb (path, (void *) (long) watcher->priv, value);
            continue;
        }

        DEBUG ("WATCH CB %s = %s (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                value, watcher->path, watcher->id, watcher->cb, watcher->priv);

        /* Setup IPC */
        sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", watcher->id);
        rpc_client = rpc_connect_service (service_name, &apteryx__client__descriptor);
        if (!rpc_client)
        {
            ERROR ("Invalid WATCH CB %s (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                   watcher->path, watcher->id, watcher->cb, watcher->priv);
            pthread_mutex_lock (&list_lock);
            watcher = cb_info_find (watch_list, watcher->path, watcher->id, watcher->cb);
            if (watcher)
            {
                watch_list = g_list_remove (watch_list, watcher);
                cb_info_destroy ((gpointer) watcher);
            }
            pthread_mutex_unlock (&list_lock);
            INC_COUNTER (counters.watched_no_handler);
            continue;
        }

        /* Do remote watch */
        watch.path = (char *)path;
        watch.value = value;
        watch.id = watcher->id;
        watch.cb = watcher->cb;
        watch.priv = watcher->priv;
        apteryx__client__watch (rpc_client, &watch, handle_set_response, &is_done);
        if (!is_done)
        {
            INC_COUNTER (counters.watched_timeout);
            ERROR ("Failed to notify watcher for path \"%s\"\n", (char *)path);
        }

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);
        INC_COUNTER (counters.watched);
    }
    g_list_free_full (watchers, cb_info_destroy);

    /* Free memory if allocated */
    if (value)
        free (value);
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
    }
    else if (result->value && result->value[0] != '\0')
    {
        data->value = strdup (result->value);
    }
    data->done = true;
}

static char *
provide_get (const char *path)
{
    char *value = NULL;
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
            get_data_t data = {0};
            Apteryx__Provide provide = APTERYX__PROVIDE__INIT;
            char service_name[64];

            /* Counters */
            INC_COUNTER (counters.provided);
            INC_COUNTER (provider->count);

            /* Check for local provider */
            if (provider->id == getpid ())
            {
                apteryx_provide_callback cb = (apteryx_provide_callback) (long) provider->cb;
                DEBUG ("PROVIDE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64",0x%"PRIx64")\n",
                                           provider->path, provider->id, provider->cb, provider->priv);
                value = cb (path, (void *) (long) provider->priv);
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
                INC_COUNTER (counters.provided_no_handler);
                continue;
            }

            /* Do remote get */
            provide.path = (char *) path;
            provide.id = provider->id;
            provide.cb = provider->cb;
            provide.priv = provider->priv;
            apteryx__client__provide (rpc_client, &provide,
                                      handle_get_response, &data);
            if (!data.done)
            {
                ERROR ("No response from provider\n");
            }

            /* Destroy the service */
            protobuf_c_service_destroy (rpc_client);

            /* Result */
            if (data.value)
            {
                value = data.value;
                break;
            }
        }
    }
    return value;
}

static void
apteryx__set (Apteryx__Server_Service *service,
              const Apteryx__Set *set,
              Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    result.result = 0;
    int validation_result = 0;

    /* Check parameters */
    if (set == NULL || set->path == NULL)
    {
        ERROR ("SET: Invalid parameters.\n");
        result.result = -EINVAL;
        closure (&result, closure_data);
        INC_COUNTER (counters.set_invalid);
        return;
    }
    INC_COUNTER (counters.set);

    DEBUG ("SET: %s = %s\n", set->path, set->value);

    /* Validate new data */
    validation_result = validate_set (set->path, set->value);
    if (validation_result < 0)
    {
        DEBUG ("SET: %s = %s REFUSED\n", set->path, set->value);
        result.result = validation_result;
        goto exit;
    }

    /* Add/Delete to/from database */
    if (set->value && set->value[0] != '\0')
        db_add (set->path, (unsigned char*)set->value, strlen (set->value) + 1);
    else
        db_delete (set->path);

#ifdef USE_SHM_CACHE
    if (set->value && set->value[0] != '\0')
        cache_set (set->path, set->value);
    else
        cache_set (set->path, NULL);
#endif

    /* Notify watchers */
    notify_watchers (set->path);

    /* Set succeeded */
    result.result = 0;

exit:
    /* Release validation lock - this is a sensitive value */
    if (validation_result)
    {
        DEBUG("SET: unlocking mutex\n");
        pthread_mutex_unlock (&validating);
    }

    /* Return result */
    closure (&result, closure_data);
    return;
}

static void
apteryx__get (Apteryx__Server_Service *service,
              const Apteryx__Get *get,
              Apteryx__GetResult_Closure closure, void *closure_data)
{
    Apteryx__GetResult result = APTERYX__GET_RESULT__INIT;
    char *value = NULL;
    size_t vsize = 0;

    /* Check parameters */
    if (get == NULL || get->path == NULL)
    {
        ERROR ("GET: Invalid parameters.\n");
        closure (NULL, closure_data);
        INC_COUNTER (counters.get_invalid);
        return;
    }
    INC_COUNTER (counters.get);

    DEBUG ("GET: %s\n", get->path);

    /* Lookup value */
    value = NULL;
    vsize = 0;
    if (!db_get (get->path, (unsigned char**)&value, &vsize))
    {
        if ((value = provide_get (get->path)) == NULL)
        {
            DEBUG ("GET: not in database or provided\n");
        }
    }
#ifdef USE_SHM_CACHE
    else
    {
        cache_set (get->path, value);
    }
#endif

    /* Send result */
    DEBUG ("     = %s\n", value);
    result.value = value;
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
        INC_COUNTER (counters.search_invalid);
        return;
    }
    INC_COUNTER (counters.search);

    DEBUG ("SEARCH: %s\n", search->path);

    /* Search database */
    results = db_search (search->path);
    /* Search providers */
    for (iter = provide_list; iter; iter = g_list_next (iter))
    {
        cb_info_t *provider = iter->data;
        int len = strlen (search->path);
        if (strncmp (provider->path, search->path, len) == 0 &&
            provider->path[len] != '*' &&
            strncmp (provider->path, APTERYX_SETTINGS, strlen (APTERYX_SETTINGS)) != 0)
        {
            char *ptr, *path = strdup (provider->path);
            if ((ptr = strchr (&path[len ? len : len+1], '/')) != 0)
                *ptr = '\0';
            if (!g_list_find_custom (results, path, (GCompareFunc) strcmp))
                results = g_list_append (results, path);
            else
                free (path);
        }
    }
    /* Prepare the results */
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
    result.result = 0;
    GList *paths = NULL, *iter;
    (void) service;

    /* Check parameters */
    if (prune == NULL || prune->path == NULL)
    {
        ERROR ("PRUNE: Invalid parameters.\n");
        result.result = -EINVAL;
        closure (&result, closure_data);
        INC_COUNTER (counters.prune_invalid);
        return;
    }
    INC_COUNTER (counters.prune);

    DEBUG ("PRUNE: %s\n", prune->path);

    /* Collect the list of deleted paths for notification */
    paths = g_list_append(paths, strdup(prune->path));
    _search_paths (&paths, prune->path);

    /* Prune from database */
    db_delete (prune->path);

    /* Return result */
    closure (&result, closure_data);

    /* Call watchers for each pruned path */
#ifdef USE_SHM_CACHE
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        cache_set ((const char *) iter->data, NULL);
    }
#endif
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        notify_watchers ((const char *) iter->data);
    }

    g_list_free_full (paths, free);
    return;
}

static void
apteryx__get_timestamp (Apteryx__Server_Service *service,
                        const Apteryx__Get *get,
                        Apteryx__GetTimeStampResult_Closure closure, void *closure_data)
{
    Apteryx__GetTimeStampResult result = APTERYX__GET_TIME_STAMP_RESULT__INIT;
    uint64_t value = 0;

    /* Check parameters */
    if (get == NULL || get->path == NULL)
    {
        ERROR ("GET: Invalid parameters.\n");
        closure (NULL, closure_data);
        INC_COUNTER (counters.get_ts_invalid);
        return;
    }
    INC_COUNTER (counters.get_ts);

    DEBUG ("GET: %s\n", get->path);

    /* Lookup value */
    value = db_get_timestamp (get->path);

    /* Send result */
    DEBUG ("     = %"PRIu64"\n", value);
    result.value = value;
    closure (&result, closure_data);
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
    /* Configuration Set/Get */
    config_init ();

#ifdef USE_SHM_CACHE
    /* Init cache */
    cache_init ();
#endif

    /* Create a lock for the shared lists */
    pthread_mutex_init (&list_lock, NULL);

    /* Create a lock for currently-validating */
    pthread_mutex_init (&validating, NULL);

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

#ifdef USE_SHM_CACHE
    /* Shut cache */
    cache_shutdown (true);
#endif

    /* Clean up the database */
    db_shutdown ();

    /* Remove the pid file */
    if (background)
        unlink (pid_file);

    return 0;
}
