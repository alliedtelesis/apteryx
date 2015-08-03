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

#define NUM_BUCKETS     16381 /* Must be prime (e.g. 4093, 8191, 16381, 32771, 65537) */
#define BM_LENGTH       ((NUM_BUCKETS/BPB) + 1) /* Bit-Mask with 1 bit per bucket */
#define NUM_STEPS       5    /* Number of checks for free buckets */
#define MAX_PATH        128
#define MAX_VALUE       64

/* Bit-Mask utilities */
#define BPB             (uint32_t)(8 * sizeof (uint32_t)) /* Bits Per Block */
#define bm_set(A,k)     ( A[(k/BPB)] |= (1 << (k%BPB)) )
#define bm_clear(A,k)   ( A[(k/BPB)] &= ~(1 << (k%BPB)) )
#define bm_test(A,k)    ( A[(k/BPB)] & (1 << (k%BPB)) )
static inline int bm_ff (uint32_t *bm, int len)
{
    int B, b;
    for (B=0; B<len; B++) {
        if (bm[B] && (b = ffsl (bm[B])) > 0) {
            return (B*BPB) + (b - 1);
        }
    }
    return -1;
}

typedef struct hash_entry_t
{
    char path[MAX_PATH];
    char value[MAX_VALUE];
} hash_entry_t;

typedef struct cache_t
{
    pthread_rwlock_t rwlock;
    sem_t ref;
    int shmid;
    int length;
    bool enabled;

    bool monitor;
    pthread_mutex_t flock;
    pthread_cond_t flush;
    pthread_t thread;

    uint32_t set_hit;
    uint32_t set_miss;
    uint32_t get_hit;
    uint32_t get_miss;
    uint32_t bitmask[BM_LENGTH];
    hash_entry_t table[0];
} cache_t;
static cache_t *cache = NULL;

/* Robert Sedgewick's string hashing algorithm */
static inline uint32_t
hash_fn (const char* key)
{
    int len = strlen (key);
    uint32_t a = 63689;
    uint32_t b = 378551;
    uint32_t hash = 0;
    int i;

    for (i = 0; i < len; key++, i++)
    {
        hash = hash * a + (*key);
        a *= b;
    }
    return hash;
}

/* Open addressing indexing with quadratic probing
 * and a fixed number of steps */
static int
hash_index (const char *key, bool flushed)
{
    int hash = hash_fn (key) % NUM_BUCKETS;
    int rindex = -1;
    int index;
    int i = 0;

    index = hash;
    while (i < NUM_STEPS)
    {
        if (strcmp (key, (char *) cache->table[index].path) == 0)
        {
            if (!flushed || !bm_test (cache->bitmask, index))
                return index;
            return -1;
        }
        else if (rindex == -1 && cache->table[index].path[0] == '\0')
        {
            if (!flushed || !bm_test (cache->bitmask, index))
                rindex = index;
        }
        i++;
        index = (hash + i * i) % NUM_BUCKETS;
    }
    rindex = rindex == -1 ? hash : rindex;
    if (!flushed || !bm_test (cache->bitmask, rindex))
        return rindex;
    return -1;
}

void
cache_init (void)
{
    int already_init = 0;
    pthread_rwlockattr_t rwmutexattr;
    pthread_mutexattr_t mutexattr;
    pthread_condattr_t condattr;
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
    memset (cache, 0, length);
    cache->length = length;
    cache->enabled = true;
    pthread_rwlockattr_init (&rwmutexattr);
    pthread_rwlockattr_setpshared (&rwmutexattr, PTHREAD_PROCESS_SHARED);
    pthread_rwlock_init (&cache->rwlock, &rwmutexattr);
    pthread_rwlock_wrlock (&cache->rwlock);
    pthread_rwlockattr_destroy (&rwmutexattr);
    sem_init (&cache->ref, 1, 1);
    cache->enabled = true;

    pthread_mutexattr_init (&mutexattr);
    pthread_mutexattr_setpshared (&mutexattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init (&cache->flock, &mutexattr);
    pthread_mutexattr_destroy (&mutexattr);
    pthread_condattr_init (&condattr);
    pthread_condattr_setpshared (&condattr, PTHREAD_PROCESS_SHARED);
    pthread_cond_init (&cache->flush, &condattr);
    pthread_condattr_destroy (&condattr);
    cache->thread = -1;
    cache->monitor = false;

    cache->shmid = shmid;
    pthread_rwlock_unlock (&cache->rwlock);
    return;
}

void
cache_disable (void)
{
    pthread_rwlock_wrlock (&cache->rwlock);
    cache->enabled = false;
    pthread_rwlock_unlock (&cache->rwlock);
}

void
cache_enable (void)
{
    pthread_rwlock_wrlock (&cache->rwlock);
    cache->enabled = true;
    pthread_rwlock_unlock (&cache->rwlock);
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
        pthread_cond_destroy (&cache->flush);
        pthread_mutex_destroy (&cache->flock);
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
cache_set (const char *path, const char *value, bool dirty)
{
    int index;
    hash_entry_t *entry;

    if (!cache || !cache->enabled ||
        strlen (path) + 1 > MAX_PATH ||
        (value && strlen (value) + 1 > MAX_VALUE))
        return false;

    pthread_rwlock_wrlock (&cache->rwlock);
    index = hash_index (path, true);
    if (index < 0) {
        if (dirty)
            INC_COUNTER (cache->set_miss);
        pthread_rwlock_unlock (&cache->rwlock);
        return false;
    }
    entry = &cache->table[index];
    if (dirty)
        bm_set (cache->bitmask, index);
    if (value)
    {
        strcpy ((char *) entry->path, path);
        strcpy ((char *) entry->value, value);
    }
    else if (strcmp (path, (char *) entry->path) == 0)
    {
        if (!dirty)
            entry->path[0] = 0;
        entry->value[0] = 0;
    }
    if (dirty)
    {
        INC_COUNTER (cache->set_hit);
    }
    pthread_rwlock_unlock (&cache->rwlock);

    if (dirty)
    {
        pthread_mutex_lock (&cache->flock);
        pthread_cond_signal (&cache->flush);
        pthread_mutex_unlock (&cache->flock);
    }

    return true;
}

char *
cache_get (const char *path)
{
    char *value = NULL;
    int index;
    hash_entry_t *entry;

    if (!cache || !cache->enabled)
        return NULL;

    pthread_rwlock_rdlock (&cache->rwlock);
    index = hash_index (path, false);
    entry = &cache->table[index];
    if (strcmp (path, (char *) entry->path) == 0)
    {
        value = strdup ((char *) entry->value);
        INC_COUNTER (cache->get_hit);
    }
    else
    {
        INC_COUNTER (cache->get_miss);
    }
    pthread_rwlock_unlock (&cache->rwlock);
    return value;
}

static int (*_set)(const char *path, const char *value) = NULL;

void
cache_flush (void)
{
    GQueue* queue = NULL;
    hash_entry_t *entry;
    int index;

    if (!cache || _set == NULL)
        return;

    /* Prevent more than one flush at once */
    pthread_mutex_lock (&cache->flock);

    /* Get all the entries that need flushing */
    pthread_rwlock_wrlock (&cache->rwlock);
    while ((index = bm_ff (cache->bitmask, BM_LENGTH)) >= 0)
    {
        entry = malloc (sizeof (hash_entry_t));
        strcpy (entry->path, cache->table[index].path);
        entry->value[0] = '\0';
        if (cache->table[index].value[0] != '\0')
            strcpy (entry->value, cache->table[index].value);
        else
            cache->table[index].path[0] = '\0';
        bm_clear (cache->bitmask, index);
        if (queue == NULL)
            queue = g_queue_new ();
        g_queue_push_tail (queue, entry);
    }
    pthread_rwlock_unlock (&cache->rwlock);
    DEBUG ("Cache: flush %d entries\n", queue ? g_queue_get_length (queue) : 0);

    /* Process each entry */
    while (queue && (entry = g_queue_pop_head (queue)) != NULL)
    {
        DEBUG ("Cache: writing %s\n", entry->path);
        if (entry->value[0] == '\0')
            _set (entry->path, NULL);
        else
            _set (entry->path, entry->value);
        free (entry);
    }

    /* Unblock flushing */
    pthread_mutex_unlock (&cache->flock);
}

static void*
_monitor_thread (void *data)
{
    struct timespec ts;
    int rc;

    DEBUG ("Cache Monitor: New thread (%lu)\n", (unsigned long)pthread_self());

    /* Loop while running */
    pthread_mutex_lock (&cache->flock);
    while (cache && cache->monitor)
    {
        /* Wait for some data to flush */
        clock_gettime (CLOCK_REALTIME, &ts);
        ts.tv_sec++;
        rc = pthread_cond_timedwait (&cache->flush, &cache->flock, &ts);
        if (rc != 0)
        {
            continue;
        }
        pthread_mutex_unlock (&cache->flock);

        /* Flush the cache - yield to batch up a bit */
        DEBUG ("Cache: Monitor\n");
        usleep (0);
        cache_flush ();

        /* Re-lock before waiting for signal */
        pthread_mutex_lock (&cache->flock);
    }
    pthread_mutex_unlock (&cache->flock);

    DEBUG ("Cache Monitor: End thread (%lu)\n", (unsigned long)pthread_self());
    cache->thread = -1;
    return NULL;
}

void
cache_start_monitor (int (*set)(const char *path, const char *value))
{
    if (!cache || cache->monitor)
        return;

    DEBUG ("Cache: Started monitoring cache\n");
    cache->monitor = true;
    _set = set;
    pthread_create (&cache->thread, NULL, _monitor_thread, NULL);
}

void
cache_stop_monitor (void)
{
    int i;

    if (!cache || !cache->monitor)
        return;

    DEBUG ("Cache: Finished monitoring cache\n");
    cache->monitor = false;
    for (i=0; i < 5000 && cache->thread != -1; i++)
        usleep (1000);
    if (cache->thread != -1)
    {
        DEBUG ("Shutdown: Killing Cache monitor\n");
        pthread_cancel (cache->thread);
        pthread_join (cache->thread, NULL);
    }
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
            pt += sprintf (pt, "%c[%04d] %s = %s\n",
                    bm_test (cache->bitmask, i) ? '*' : ' ',
                    i, cache->table[i].path,
                    cache->table[i].value);
        }
    }
    sprintf (pt, "%d/%d buckets, set:get %"PRIu32":%"PRIu32" hits %"PRIu32":%"PRIu32" misses",
            count, NUM_BUCKETS,
            cache->set_hit, cache->get_hit, cache->set_miss, cache->get_miss);
    pthread_rwlock_unlock (&cache->rwlock);
    return buffer;
}
#endif /* USE_SHM_CACHE */
