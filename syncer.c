#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <apteryx.h>

#define SYNC_PATH "/apteryx/sync"

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
    if (asprintf (&full_path, "%s:%s", sp->socket, sp->path) < 0)
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
    uint64_t res = apteryx_get_timestamp (full_path);
    free (full_path);
    return res;
}

bool
sync_recursive (sync_partner *sp, const char *path)
{
    uint64_t ts = apteryx_get_timestamp (path);
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
    uint64_t local_ts = apteryx_get_timestamp ("/");
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
    for (GList *iter = partners; iter; iter = iter->next)
    {
        sync_partner *sp = iter->data;
        apteryx_set_sp (sp, path, value);
    }
    pthread_rwlock_unlock (&partners_lock);
    return true;
}

int
main (int argc, char *argv[])
{
    apteryx_init (false);

    apteryx_watch (SYNC_PATH "/", new_syncer);

    apteryx_watch ("/*", new_change);

    pthread_t timer;
    pthread_create (&timer, NULL, periodic_syncer_thread, NULL);


    while (1)
    {
        pause ();
    }
    pthread_cancel (timer);
    pthread_join (timer, NULL);
}
