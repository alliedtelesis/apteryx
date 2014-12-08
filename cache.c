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
#define MAX_PATH                256
#define MAX_VALUE               128
#define NUM_BUCKETS             512

typedef struct hash_entry_t {
    uint8_t path[MAX_PATH];
    uint8_t value[MAX_VALUE];
    uint32_t length;
} hash_entry_t;

typedef struct cache_t {
    pthread_rwlock_t rwlock;
    sem_t ref;
    int shmid;
    int length;
    hash_entry_t table[0];
} cache_t;
static cache_t *cache = NULL;

void
cache_init (void)
{
    int already_init = 0;
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
    if ((cache = (cache_t *) shmat (shmid, NULL, 0)) == NULL)
    {
        ERROR ("Failed to attach to SHM cache.\n");
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
    pthread_rwlock_init (&cache->rwlock, NULL);
    pthread_rwlock_wrlock (&cache->rwlock);
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

bool
cache_set (const char *path, unsigned char *value, size_t size)
{
    hash_entry_t *entry;

    if (!cache || strlen (path) > MAX_PATH || size > MAX_VALUE)
        return false;

    pthread_rwlock_wrlock (&cache->rwlock);
    entry = &cache->table[g_str_hash (path) % NUM_BUCKETS];
    if (value)
    {
        strcpy ((char*)entry->path, path);
        entry->length = size;
        memcpy (entry->value, value, size);
    }
    else if (strcmp (path, (char*)entry->path) == 0)
    {
        entry->path[0] = 0;
    }
    pthread_rwlock_unlock (&cache->rwlock);

    return false;
}

bool
cache_get (const char *path, unsigned char **value, size_t *size)
{
    hash_entry_t *entry;
    bool result = false;

    if (!cache)
        return false;

    pthread_rwlock_rdlock (&cache->rwlock);
    entry = &cache->table[g_str_hash (path) % NUM_BUCKETS];
    if (strcmp (path, (char*)entry->path) == 0)
    {
        *size = entry->length;
        *value = malloc (entry->length);
        memcpy (*value, entry->value, entry->length);
        result = true;
    }
    pthread_rwlock_unlock (&cache->rwlock);
    return result;
}

char *
cache_dump_table (void)
{
    int  length = (NUM_BUCKETS * (2*MAX_PATH + 2*MAX_VALUE + 12)) + 20;
    char *buffer = malloc (length);
    char *pt = buffer;
    int count = 0;
    int i;

    pthread_rwlock_rdlock (&cache->rwlock);
    for (i=0; i<NUM_BUCKETS; i++)
    {
        if (cache->table[i].path[0] != 0)
        {
            count++;
            pt += sprintf (pt, "[%04d] %s = %s\n",
               i, cache->table[i].path,
               bytes_to_string (cache->table[i].value, cache->table[i].length));
        }
    }
    pthread_rwlock_unlock (&cache->rwlock);
    sprintf (pt, "%d/%d buckets\n", count, NUM_BUCKETS);
    return buffer;
}
#endif /* USE_SHM_CACHE */
