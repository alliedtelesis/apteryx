/**
 * @file cache.c
 * Used for a cache for apteryx_get.
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
#include "internal.h"
#ifdef USE_SHM_CACHE
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <errno.h>
#define MAX_PATH                256
#define MAX_VALUE               128
#define NUM_BUCKETS             1024

typedef struct hash_entry_t
{
    uint8_t path[MAX_PATH];
    uint8_t value[MAX_VALUE];
} hash_entry_t;

typedef struct cache_t
{
    pthread_rwlock_t rwlock;
    sem_t ref;
    int shmid;
    int length;
    uint32_t hit;
    uint32_t miss;
    hash_entry_t table[0];
} cache_t;
static cache_t *cache = NULL;

void
cache_init (void)
{
    int already_init = 0;
    pthread_rwlockattr_t attr;
    int length;
    int shmid;

    if (cache)
        return;

    /* Create/attach to the shared memory block */
    length = sizeof (cache_t) + (NUM_BUCKETS * sizeof (hash_entry_t));
    shmid = shmget (APTERYX_SHM_KEY, length, 0644 | IPC_CREAT | IPC_EXCL);
    if (shmid < 0)
    {
        /* Another process is initializing this memory */
        shmid = shmget (APTERYX_SHM_KEY, length, 0644);
        already_init = 1;
    }
    /* shmat has the quite bizzare failure mode of returning -1 */
    if ((cache = (cache_t *) shmat (shmid, NULL, 0)) == (void*)-1)
    {
        cache = NULL;
        ERROR ("Failed to attach to SHM cache (%s).\n", strerror(errno));
        return;
    }

    /* Check if someone else has already initialised the cache */
    if (already_init)
    {
        /* Wait for the other process to finish if required */
        while (shmid != cache->shmid)
            usleep (10);
        if (cache->length != length)
        {
            /* Incompatible shared memory segments! */
            ERROR ("SHM Cache != %d bytes\n", length);
            shmdt (cache);
            cache = NULL;
            return;
        }
        sem_post (&cache->ref);
        return;
    }

    /* Initialise the cache */
    cache->shmid = 0;
    cache->length = length;
    pthread_rwlockattr_init (&attr);
    pthread_rwlockattr_setpshared (&attr, PTHREAD_PROCESS_SHARED);
    pthread_rwlock_init (&cache->rwlock, &attr);
    pthread_rwlock_wrlock (&cache->rwlock);
    pthread_rwlockattr_destroy (&attr);
    sem_init (&cache->ref, 1, 1);
    memset (cache->table, 0, NUM_BUCKETS * sizeof (hash_entry_t));
    cache->shmid = shmid;
    pthread_rwlock_unlock (&cache->rwlock);
    return;
}

void
cache_shutdown (bool force)
{
    int count;
    int shmid;

    if (cache == NULL || cache->shmid == 0)
        return;

    /* Decrement the ref count */
    sem_wait (&cache->ref);

    /* Check if we are the last user of the cache */
    if (force || (sem_getvalue (&cache->ref, &count) == 0 && count == 0))
    {
        /* Destroy the cache */
        shmid = cache->shmid;
        cache->shmid = 0;
        sem_destroy (&cache->ref);
        pthread_rwlock_destroy (&cache->rwlock);
        shmdt (cache);
        shmctl (shmid, IPC_RMID, 0);
    }
    else
    {
        /* Detach */
        shmdt (cache);
    }
    cache = NULL;
    return;
}

void
cache_set (const char *path, const char *value)
{
    hash_entry_t *entry;

    if (!cache || strlen (path) + 1 > MAX_PATH ||
        (value && strlen (value) + 1 > MAX_VALUE))
        return;

    pthread_rwlock_wrlock (&cache->rwlock);
    entry = &cache->table[g_str_hash (path) % NUM_BUCKETS];
    if (value)
    {
        strcpy ((char *) entry->path, path);
        strcpy ((char *) entry->value, value);
    }
    else if (strcmp (path, (char *) entry->path) == 0)
    {
        entry->path[0] = 0;
    }
    pthread_rwlock_unlock (&cache->rwlock);

    return;
}

char *
cache_get (const char *path)
{
    char *value = NULL;
    hash_entry_t *entry;

    if (!cache)
        return NULL;

    pthread_rwlock_rdlock (&cache->rwlock);
    entry = &cache->table[g_str_hash (path) % NUM_BUCKETS];
    if (strcmp (path, (char *) entry->path) == 0)
    {
        value = strdup ((char *) entry->value);
        INC_COUNTER (cache->hit);
    }
    else
    {
        INC_COUNTER (cache->miss);
    }
    pthread_rwlock_unlock (&cache->rwlock);
    return value;
}

char *
cache_dump_table (void)
{
    int length = (NUM_BUCKETS * (2 * MAX_PATH + 2 * MAX_VALUE + 12)) + 64;
    char *buffer = malloc (length);
    char *pt = buffer;
    int count = 0;
    int i;

    pthread_rwlock_rdlock (&cache->rwlock);
    for (i = 0; i < NUM_BUCKETS; i++)
    {
        if (cache->table[i].path[0] != 0)
        {
            count++;
            pt += sprintf (pt, "[%04d] %s = %s\n",
                           i, cache->table[i].path,
                           cache->table[i].value);
        }
    }
    sprintf (pt, "%d/%d buckets, %" PRIu32 " hits, %" PRIu32" misses",
             count, NUM_BUCKETS, cache->hit, cache->miss);
    pthread_rwlock_unlock (&cache->rwlock);
    return buffer;
}
#endif /* USE_SHM_CACHE */
