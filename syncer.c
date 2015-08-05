#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <apteryx.h>
#include "common.h"

#define APTERYX_SYNC_PID "/var/run/apteryx-sync.pid"
#define APTERYX_SYNC_CONFIG_DIR "/etc/apteryx/sync/"

/* Debug */
bool debug = false;

/* Run while true */
static bool running = true;

typedef struct sync_partner_s
{
    char *socket;
    char *path;
    uint64_t last_sync_local;
    uint64_t last_sync_remote;
} sync_partner;

GList *partners = NULL;
pthread_rwlock_t partners_lock = PTHREAD_RWLOCK_INITIALIZER;

bool
syncer_add (sync_partner *sp)
{
    partners = g_list_append (partners, sp);
    return true;
}

gint
syncer_match_path (gconstpointer a, gconstpointer b)
{
    sync_partner *sp = (sync_partner *)a;
    const char *path = (const char *)b;
    return strcmp (sp->path, path);
}

sync_partner *
syncer_find_path (const char *path)
{
    sync_partner *res = (sync_partner *) g_list_find_custom (partners, path, syncer_match_path);
    return res;
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
        sync_partner *sp = malloc (sizeof (sync_partner));
        if (sp)
        {
            sp->socket = strdup (value);
            sp->path = strdup (path);
            sp->last_sync_local = 0;
            sp->last_sync_remote = 0;
            syncer_add (sp);
        }
    }
    else
    {
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
    if (strncmp (path, "/apteryx", 8) == 0)
    {
        return false;
    }
    // should check other data for other paths we shouldn't sync
    // like the schema files ...
    return true;
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
    char *full_path = sp_path (sp, path);
    if (!full_path)
    {
        return false;
    }
    apteryx_prune (full_path);
    free (full_path);
    return true;
}

bool
apteryx_set_sp (sync_partner *sp, const char *path, const char *value)
{
    char *full_path = sp_path (sp, path);
    if (!full_path)
    {
        return false;
    }
    apteryx_set (full_path, value);
    free (full_path);
    return true;
}

uint64_t
apteryx_get_timestamp_sp (sync_partner *sp, const char *path)
{
    char *full_path = sp_path (sp, path);
    if (!full_path)
    {
        return false;
    }
    uint64_t res = apteryx_timestamp (full_path);
    free (full_path);
    return res;
}

bool
sync_recursive (sync_partner *sp, const char *path)
{
    uint64_t ts = apteryx_timestamp (path);
    if (!sync_path_check (path))
    {
        return true;
    }
    if (ts < sp->last_sync_local)
    {
        if (ts == 0)
        {
            /* Prune anything that is deleted */
            apteryx_prune_sp (sp, path);
        }
        /* Skip anything that hasn't changed since last sync */
        return true;
    }
    /* Update this node */
    char *value = apteryx_get (path);
    apteryx_set_sp (sp, path, value);
    free (value);
    /* Update all children */
    GList *paths = apteryx_search (path);
    for (GList *iter = paths; iter; iter = iter->next)
    {
        sync_recursive (sp, iter->data);
    }
    g_list_free_full (paths, free);
    // Update remote children that weren't already covered above
    // Specifically, look for local deletes that haven't propogated
    return true;
}

bool
resync (sync_partner *sp)
{
    uint64_t local_ts = apteryx_timestamp ("/");
    if (local_ts > sp->last_sync_local)
    {
        sync_recursive (sp, "/");
    }
    sp->last_sync_local = local_ts;
    sp->last_sync_remote = apteryx_get_timestamp_sp (sp, "/");
    return true;
}

static void *
periodic_syncer_thread (void *ign)
{
    while (1)
    {
        pthread_rwlock_rdlock (&partners_lock);
        for (GList *iter = partners; iter; iter = iter->next)
        {
            sync_partner *sp = iter->data;
            resync (sp);
        }
        pthread_rwlock_unlock (&partners_lock);
        sleep (30);
    }
    return NULL;
}

bool
new_change (const char *path, const char *value)
{
    pthread_rwlock_rdlock (&partners_lock);
    DEBUG ("NEW_CHANGE on path %s, value %s.", path, value);
    for (GList *iter = partners; iter; iter = iter->next)
    {
        sync_partner *sp = iter->data;
        apteryx_set_sp (sp, path, value);
    }
    pthread_rwlock_unlock (&partners_lock);
    return true;
}

void
register_existing_partners (void)
{
	GList *iter = NULL;
	char *value = NULL;
    /* get all paths under the APTERYX_SYNC_PATH node
	 * note: need to add a "/" on the end for search to work
	 */
	char *base_path = NULL;
	if (asprintf (&base_path, "%s/", APTERYX_SYNC_PATH) <= 0)
	{
		/* shouldn't fail, but if it does we can't continue */
		return;
	}
	GList *existing_partners = apteryx_search (base_path);
	free (base_path);
	/* for each path in the search result, get the value and create a new syncer */
	iter = existing_partners;
	while (iter != NULL)
	{
		DEBUG ("Adding existing partner %s\n", (char *)iter->data);
		/* the path is a char* in the iter->data. need to add "/*" to the end */
		if (asprintf (&base_path, "%s/*", (char *)iter->data) <= 0)
        {
            /* shouldn't fail, but if it does we can't do any more with it */
            continue;
        }
		value = apteryx_get (base_path);
		new_syncer (base_path, value);
		free (value);
		free (base_path);
		/* finished with this entry. move along, nothing to see here. */
		iter = iter->next;
	}
	/* finally, clean up the list */
	g_list_free_full (existing_partners, free);
	existing_partners = NULL;
}

void
termination_handler (void)
{
    running = false;
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
    struct dirent *config_file;
    DIR *dp = NULL;
    char *config_file_name = NULL;

    apteryx_init (false);

    /* Parse options */
    while ((i = getopt (argc, argv, "hdbp:c:")) != -1)
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
        if (!fp)
        {
            ERROR ("Failed to create PID file %s\n", pid_file);
            goto exit;
        }
        fprintf (fp, "%d\n", getpid ());
        fclose (fp);
    }

    /* open the sync config dir and read all the files in it to get sync paths */
    dp = opendir (config_dir);
    if (!dp)
    {
    	ERROR ("Couldn't open sync config directory \"%s\"\n", config_dir);
    	goto exit;
    }

    /* The sync path is how applications can register the nodes to sync to */
    /* we need to check for any existing nodes and setup syncers for them */
    register_existing_partners ();
    /* next, watch the sync path for any new nodes we need to sync to. */
    apteryx_watch (APTERYX_SYNC_PATH, new_syncer);

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
            int i = 0;
            size_t n = 0;
            while (getline (&sync_path, &n, fp) != -1)
            {
                i++;
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
                /* Note: it is required that the path in the file ends with "/*" */
                DEBUG ("SYNC INIT: about to watch path: %s\n", sync_path);
                apteryx_watch (sync_path, new_change);
                free (sync_path);
                sync_path = NULL;
            }
            fclose (fp);
        }
        free (config_file_name);
    }
    closedir (dp);

    pthread_t timer;
    pthread_create (&timer, NULL, periodic_syncer_thread, NULL);

    while (running)
    {
        pause ();
    }

    pthread_cancel (timer);
    pthread_join (timer, NULL);

exit:
    /* Remove the pid file */
    if (background)
    {
        unlink (pid_file);
    }
}
