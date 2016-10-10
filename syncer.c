#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <apteryx.h>
#include <glib-unix.h>
#include "common.h"

#define APTERYX_SYNC_PID "/var/run/apteryx-sync.pid"
#define APTERYX_SYNC_CONFIG_DIR "/etc/apteryx/sync/"

/* Debug */
bool apteryx_debug = false;

/* Run while true */
static GMainLoop *g_loop = NULL;

typedef struct sync_partner_s
{
    char *socket;
    char *path;
    bool new_joiner;
} sync_partner;

/* keep a list of the partners we are syncing paths to */
GList *partners = NULL;
pthread_rwlock_t partners_lock = PTHREAD_RWLOCK_INITIALIZER;

/* keep pending changes (not yet pushed to clients)... */
static GNode *pending = NULL;
static guint pending_timer = 0;
static uint64_t oldest_pending = 0;
#define PENDING_HOLD_OFF 1000   /* 1 second */

/* periodic sync timer */
static guint sync_timer = 0;
#define SYNC_HOLD_OFF 30 * 1000 /* 30 seconds */

/* keep a list of the paths we are syncing */
GList *paths = NULL;
GList *excluded_paths = NULL;
pthread_rwlock_t paths_lock = PTHREAD_RWLOCK_INITIALIZER;

static uint64_t
now (void)
{
    struct timespec tms;
    uint64_t micros = 0;
    if (clock_gettime (CLOCK_MONOTONIC, &tms))
    {
        return 0;
    }

    micros = ((uint64_t) tms.tv_sec) * 1000000;
    micros += tms.tv_nsec / 1000;
    return micros;
}

static bool
flush ()
{
    pthread_rwlock_wrlock (&partners_lock);
    DEBUG ("Flushing...\n");
    for (GList * iter = partners; iter; iter = iter->next)
    {
        if (pending)
        {
            /* Dirty hack to do set tree without a deep copy */
            char *next_path = NULL;

            if (asprintf (&next_path, "%s:/", ((sync_partner *) iter->data)->socket) > 0)
            {
                free (pending->data);
                pending->data = next_path;
                apteryx_set_tree (pending);
            }
        }
    }
    apteryx_free_tree (pending);
    pending = NULL;

    oldest_pending = 0;

    if (pending_timer)
    {
        g_source_remove (pending_timer);
    }
    pending_timer = 0;
    pthread_rwlock_unlock (&partners_lock);

    return false;
}

static void
add_data_point (const char *path, const char *value)
{
    pthread_rwlock_wrlock (&partners_lock);

    if (apteryx_find_child (pending, path + 1))
    {
        DEBUG ("Flushing due to collision\n");
        pthread_rwlock_unlock (&partners_lock);
        flush ();
        pthread_rwlock_wrlock (&partners_lock);
    }

    uint64_t n = now ();

    if (pending == NULL)
    {
        pending = APTERYX_NODE (NULL, strdup ("/"));
        oldest_pending = n;
    }
    APTERYX_LEAF (pending, strlen (path) > 0 ? strdup (path + 1) : strdup (""),
                  value ? strdup (value) : NULL);

    /* Convert 5 seconds to micro seconds... */
    if (oldest_pending + (5 * 1000 * 1000) < n)
    {
        NOTICE ("Pending changes waiting in excess of 5 seconds\n");
        oldest_pending = n;
    }

    if (pending_timer)
    {
        g_source_remove (pending_timer);
    }
    pending_timer = g_timeout_add (PENDING_HOLD_OFF, (GSourceFunc) flush, NULL);

    pthread_rwlock_unlock (&partners_lock);

}

bool
syncer_add (sync_partner *sp)
{
    partners = g_list_append (partners, sp);
    return true;
}

gint
syncer_match_path (gconstpointer a, gconstpointer b)
{
    sync_partner *sp = (sync_partner *) a;
    const char *path = (const char *) b;
    return strcmp (sp->path, path);
}

sync_partner *
syncer_find_path (const char *path)
{
    GList *list_pt;

    list_pt = g_list_find_custom (partners, path, syncer_match_path);

    return list_pt ? (sync_partner *) list_pt->data : NULL;
}

bool
syncer_del (sync_partner *sp)
{
    partners = g_list_remove (partners, sp);
    free (sp->socket);
    free (sp->path);
    free (sp);
    return true;
}

static bool
new_syncer (const char *path, const char *value)
{
    pthread_rwlock_wrlock (&partners_lock);
    if (value)
    {
        sync_partner *sp = syncer_find_path (path);
        if (sp)
        {
            /* partner already exists. update it */
            DEBUG ("Updating syncer. path %s, value %s\n", path, value);
            free (sp->socket);
            free (sp->path);
        }
        else
        {
            /* new partner so get memory and add to the list now.
             * fill in the details afterwards (while we still hold the lock).
             */
            DEBUG ("Adding new syncer. path %s, value %s\n", path, value);
            sp = malloc (sizeof (sync_partner));
            syncer_add (sp);
        }
        sp->socket = strdup (value);
        sp->path = strdup (path);
        sp->new_joiner = true;
    }
    else
    {
        DEBUG ("Deleting syncer. path %s\n", path);
        sync_partner *sp = syncer_find_path (path);
        if (sp)
        {
            syncer_del (sp);
        }
    }
    pthread_rwlock_unlock (&partners_lock);
    return true;
}

bool
sync_path_check (const char *path)
{
    /* as a sanity check, make sure the path to sync isn't something crazy */
    if ((strncmp (path, "/apteryx", 8) == 0) ||
        (strcmp (path, "/") == 0))
    {
        return false;
    }
    return true;
}

bool
sync_path_excluded (const char *path)
{
    pthread_rwlock_rdlock (&paths_lock);
    for (GList *iter = excluded_paths; iter; iter = iter->next)
    {
        if (strcmp (path, iter->data) == 0)
        {
            pthread_rwlock_unlock (&paths_lock);
            return true;
        }
    }
    pthread_rwlock_unlock (&paths_lock);
    return false;
}

char *
sp_path (sync_partner *sp, const char *path)
{
    char *full_path = NULL;
    if (asprintf (&full_path, "%s:%s", sp->socket, path) < 0)
    {
        return NULL;
    }
    return full_path;
}

bool
apteryx_prune_sp (sync_partner *sp, const char *path)
{
    bool res = false;
    char *full_path = sp_path (sp, path);
    if (!full_path)
    {
        return false;
    }
    res = apteryx_prune (full_path);
    free (full_path);
    return res;
}

bool
apteryx_set_sp (sync_partner *sp, const char *path, const char *value)
{
    bool res = false;
    char *full_path = sp_path (sp, path);
    if (!full_path)
    {
        return false;
    }
    res = apteryx_set (full_path, value);
    free (full_path);
    return res;
}

bool
sync_recursive (GNode *root, uint64_t timestamp, const char *path)
{
    if (sync_path_excluded (path))
    {
        /* Skip excluded paths */
        return true;
    }

    uint64_t ts = apteryx_timestamp (path);
    if (ts <= timestamp || ts == 0)
    {
        /* Skip anything that hasn't changed since last sync */
        return true;
    }

    /* make sure the path doesn't end in '/' for the get */
    char *get_path = strdup (path);
    if (get_path[strlen (get_path) - 1] == '/')
    {
        get_path[strlen (get_path) - 1] = '\0';
    }

    /* now make sure the path ends in '/' for the search */
    char *search_path = NULL;
    if (path[strlen (path) - 1] != '/')
    {
        if (asprintf (&search_path, "%s/", path) == -1)
        {
            ERROR ("SYNC couldn't allocate search path!\n");
            search_path = NULL;
            free (get_path);
            return false;
        }
    }
    else
    {
        search_path = strdup (path);
    }

    /* Update this node */
    char *value = apteryx_get (get_path);
    if (value)
    {
        /* only sync non-null values or you'll inadvertently prune */
        APTERYX_LEAF (root, strdup (get_path + 1), value);
    }
    free (get_path);

    /* Update all children */
    GList *sync_paths = apteryx_search (search_path);
    free (search_path);
    for (GList * iter = sync_paths; iter; iter = iter->next)
    {
        sync_recursive (root, timestamp, iter->data);
    }
    g_list_free_full (sync_paths, free);
    // TODO: Update remote children that weren't already covered above
    // Specifically, look for local deletes that haven't propagated
    return true;
}

void
sync_gather (GNode *root, uint64_t timestamp)
{
    GList *iter = NULL;

    pthread_rwlock_rdlock (&paths_lock);
    for (iter = paths; iter; iter = iter->next)
    {
        sync_recursive (root, timestamp, (char *) iter->data);
    }
    pthread_rwlock_unlock (&paths_lock);
}

bool
resync ()
{
    /* Called under a lock */
    GList *iter;
    GNode *data = NULL;
    static uint64_t last_sync_local = 0;

    uint64_t local_ts = apteryx_timestamp ("/");

    for (iter = partners; iter; iter = iter->next)
    {
        sync_partner *sp = iter->data;
        if (sp->new_joiner)
        {
            if (data == NULL)
            {
                data = APTERYX_NODE (NULL, strdup ("/"));
                /* Get everything */
                sync_gather (data, 0);
            }
            if (APTERYX_NUM_NODES (data) > 0)
            {
                char *next_path = NULL;

                if (asprintf (&next_path, "%s:/", sp->socket) > 0)
                {
                    free (data->data);
                    data->data = next_path;
                    apteryx_set_tree (data);
                }
            }
        }
    }

    if (data)
    {
        apteryx_free_tree (data);
        data = NULL;
    }

    /* Grab all the data that has been added since the last update... */
    data = APTERYX_NODE (NULL, strdup ("/"));
    sync_gather (data, last_sync_local);

    if (APTERYX_NUM_NODES (data) > 0)
    {
        for (iter = partners; iter; iter = iter->next)
        {
            sync_partner *sp = iter->data;
            if (!sp->new_joiner)
            {
                char *next_path = NULL;

                if (asprintf (&next_path, "%s:/", sp->socket) > 0)
                {
                    free (data->data);
                    data->data = next_path;
                    apteryx_set_tree (data);
                }
            }
            else
            {
                /* These ones will have got all the data above */
                sp->new_joiner = false;
            }
        }
    }

    if (data)
    {
        apteryx_free_tree (data);
        data = NULL;
    }

    last_sync_local = local_ts;
    return true;
}

static bool
periodic_syncer_thread (void *ign)
{
    pthread_rwlock_rdlock (&partners_lock);
    /* If we are already busy, wait for a quiet spell */
    if (pending_timer)
    {
        g_source_remove (sync_timer);
        sync_timer =
            g_timeout_add (PENDING_HOLD_OFF * 1.1, (GSourceFunc) periodic_syncer_thread,
                           NULL);
    }
    else
    {
        resync ();
        g_source_remove (sync_timer);
        sync_timer =
            g_timeout_add (SYNC_HOLD_OFF, (GSourceFunc) periodic_syncer_thread, NULL);
    }
    pthread_rwlock_unlock (&partners_lock);
    return false;
}

bool
new_change (const char *path, const char *value)
{
    DEBUG ("Pushing NEW_CHANGE on path %s, value %s to cache\n", path, value);
    add_data_point (path, value);
    return true;
}

void
register_existing_partners (void)
{
    GList *iter = NULL;
    char *value = NULL;
    char *path = NULL;
    /* get all paths under the APTERYX_SYNC_PATH node
     * note: need to add a "/" on the end for search to work
     */
    GList *existing_partners = apteryx_search (APTERYX_SYNC_PATH "/");
    /* for each path in the search result, get the value and create a new syncer */
    iter = existing_partners;
    while (iter != NULL)
    {
        DEBUG ("Adding existing partner %s\n", (char *) iter->data);
        /* the path is a char* in the iter->data. need to add "/*" to the end */
        if (asprintf (&path, "%s/*", (char *) iter->data) <= 0)
        {
            /* shouldn't fail, but if it does we can't do any more with it */
            continue;
        }
        value = apteryx_get (path);
        new_syncer (path, value);
        free (value);
        free (path);
        /* finished with this entry. move along, nothing to see here. */
        iter = iter->next;
    }
    /* finally, clean up the list */
    g_list_free_full (existing_partners, free);
    existing_partners = NULL;
}

bool
add_path_to_sync (const char *path)
{
    /* Note: it is required that the path in the file ends with "/*" */
    if (sync_path_check (path))
    {
        DEBUG ("SYNC INIT: about to watch path: %s\n", path);
        apteryx_watch (path, new_change);
        /* Lastly, add the path to our list for the resyncer thread.
        /* note: because we need to do a few things to this later,
         * remove the trailing '/*'
         */
        char *new_path = strdup (path);
        char *end_ptr = NULL;
        if ((end_ptr = strstr (new_path, "/*")) != NULL)
        {
            end_ptr[0] = '\0';
        }
        pthread_rwlock_wrlock (&paths_lock);
        paths = g_list_append (paths, new_path);
        pthread_rwlock_unlock (&paths_lock);
    }
    else
    {
        ERROR ("Path %s is not valid for syncing\n", path);
    }
    return TRUE;
}

bool
add_excluded_path (const char *path)
{
    if (sync_path_check (path))
    {
        DEBUG ("SYNC INIT: Adding exclusion for: %s\n", path);
        char *new_path = strdup (path);
        pthread_rwlock_wrlock (&paths_lock);
        excluded_paths = g_list_append (excluded_paths, new_path);
        pthread_rwlock_unlock (&paths_lock);
    }
    return true;
}

bool
parse_config_files (const char* config_dir)
{
    FILE *fp = NULL;
    struct dirent *config_file;
    DIR *dp = NULL;
    char *config_file_name = NULL;

    /* open the sync config dir and read all the files in it to get sync paths */
    dp = opendir (config_dir);
    if (!dp)
    {
        ERROR ("Couldn't open sync config directory \"%s\"\n", config_dir);
        return FALSE;
    }
    /* Now read the config file(s) to know which paths should be synced */
    while ((config_file = readdir(dp)) != NULL)
    {
        if ((strcmp(config_file->d_name, ".") == 0) ||
            (strcmp(config_file->d_name, "..") == 0))
        {
            /* skip the directory entries */
            continue;
        }
        if (asprintf (&config_file_name, "%s%s", config_dir, config_file->d_name) == -1)
        {
            /* this shouldn't fail, but can't do anything if it does */
            continue;
        }
        fp = fopen (config_file_name, "r");
        if (!fp)
        {
            ERROR ("Couldn't open sync config file \"%s\"\n", config_file_name);
        }
        else
        {
            char *sync_path = NULL;
            char *newline = NULL;
            size_t n = 0;
            while (getline (&sync_path, &n, fp) != -1)
            {
                /* ignore lines starting with '#' */
                if (sync_path[0] == '#')
                {
                    free (sync_path);
                    sync_path = NULL;
                    continue;
                }
                if ((newline = strchr (sync_path, '\n')) != NULL)
                {
                    newline[0] = '\0'; // remove the trailing newline char
                }

                if (sync_path[0] == '!')
                {
                    // Add an exclusion to syncing
                    add_excluded_path (sync_path + 1);
                }
                else
                {
                    add_path_to_sync (sync_path);
                }

                free (sync_path);
                sync_path = NULL;
            }
            fclose (fp);
        }
        free (config_file_name);
    }
    closedir (dp);
    return TRUE;
}

static gboolean
termination_handler (gpointer arg1)
{
    g_main_loop_quit (g_loop);
    return false;
}

void
help (char *app_name)
{
    printf ("Usage: %s [-h] [-b] [-d] [-p <pidfile>] [-c <configdir>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -p   use <pidfile> (defaults to "APTERYX_SYNC_PID")\n"
            "  -c   use <configdir> (defaults to "APTERYX_SYNC_CONFIG_DIR")\n",
            app_name);
}

int
main (int argc, char *argv[])
{
    const char *pid_file = APTERYX_SYNC_PID;
    const char *config_dir = APTERYX_SYNC_CONFIG_DIR;
    int i = 0;
    bool background = false;
    FILE *fp = NULL;

    apteryx_init (false);

    /* Parse options */
    while ((i = getopt (argc, argv, "hdbp:c:")) != -1)
    {
        switch (i)
        {
        case 'd':
            apteryx_debug = true;
            background = false;
            break;
        case 'b':
            background = true;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case 'c':
            config_dir = optarg;
            break;
        case '?':
        case 'h':
        default:
            help (argv[0]);
            return 0;
        }
    }

    /* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
    g_unix_signal_add (SIGINT, termination_handler, g_loop);
    g_unix_signal_add (SIGTERM, termination_handler, g_loop);
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
        if (!fp)
        {
            ERROR ("Failed to create PID file %s\n", pid_file);
            goto exit;
        }
        fprintf (fp, "%d\n", getpid ());
        fclose (fp);
    }

    /* The sync path is how applications can register the nodes to sync to */
    apteryx_watch (APTERYX_SYNC_PATH "/*", new_syncer);

    /* next, we need to check for any existing nodes and setup syncers for them */
    register_existing_partners ();

    /* and finally, read the list of paths we should sync */
    parse_config_files (config_dir);

    /* Now we have done the setup, we can start running */
    sync_timer = g_timeout_add (SYNC_HOLD_OFF, (GSourceFunc) periodic_syncer_thread, NULL);

    g_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (g_loop);
    g_main_loop_unref (g_loop);

    exit:
    /* Remove the pid file */
    if (background)
    {
        unlink (pid_file);
    }
}
