/**
 * @file database.c
 * Used for back-end storage of AWP Info data.
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
#include <semaphore.h>
//#include <sys/shm.h>
#include "rszshm.h"
#ifdef TEST
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#endif

/* Shared memory */
#define APTERYX_SHM_KEY    0xda7aba5e
#define NUM_BUCKETS     16381 /* Must be prime (e.g. 4093, 8191, 16381, 32771, 65537) */
#define NUM_STEPS       5    /* Number of checks for free buckets */
#define MAX_PATH        128
#define MAX_VALUE       64

typedef struct hash_entry_t
{
    uint64_t ts;
    uint8_t path[MAX_PATH];
    uint32_t length;
    uint8_t value[MAX_VALUE];
} hash_entry_t;

typedef struct db_t
{
    pthread_rwlock_t rwlock;
    sem_t ref;
    int shmid;
    int length;
    uint32_t hit;
    uint32_t miss;
    hash_entry_t table[0];
} db_t;
static db_t *db = NULL;
static struct rszshm r = {};

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
static uint32_t
hash_index (const char *key)
{
    uint32_t hash = hash_fn (key) % NUM_BUCKETS;
    uint32_t rindex = NUM_BUCKETS;
    uint32_t index;
    int i = 0;

    index = hash;
    while (i < NUM_STEPS)
    {
        if (strcmp (key, (char *) db->table[index].path) == 0)
        {
            return index;
        }
        if (rindex == NUM_BUCKETS && db->table[index].path[0] == '\0')
        {
            rindex = index;
        }
        i++;
        index = (hash + i * i) % NUM_BUCKETS;
    }
    return rindex == NUM_BUCKETS ? hash : rindex;
}

void
db_init (void)
{
//    int already_init = 0;
    pthread_rwlockattr_t attr;
    int length;
//    int shmid;

    if (db)
        return;

    /* Create/attach to the shared memory block */
    length = sizeof (db_t) + (NUM_BUCKETS * sizeof (hash_entry_t));
    if (!rszshm_mk(&r, length, "./apteryx.dat"))
    {
        ERROR ("Failed to attach to SHM db.\n");
        return;
    }
    db = (db_t *) (r.dat + sizeof (int));

//    length = sizeof (db_t) + (NUM_BUCKETS * sizeof (hash_entry_t));
//    shmid = shmget (APTERYX_SHM_KEY, length, 0644 | IPC_CREAT | IPC_EXCL);
//    if (shmid < 0)
//    {
//        /* Another process is initializing this memory */
//        shmid = shmget (APTERYX_SHM_KEY, length, 0644);
//        already_init = 1;
//    }
//    if ((db = (db_t *) shmat (shmid, NULL, 0)) == NULL)
//    {
//        ERROR ("Failed to attach to SHM db.\n");
//        return;
//    }

//    /* Check if someone else has already initialised the db */
//    if (already_init)
//    {
//        /* Wait for the other process to finish if required */
//        while (shmid != db->shmid)
//            usleep (10);
//        if (db->length != length)
//        {
//            /* Incompatible shared memory segments! */
//            ERROR ("SHM DB != %d bytes\n", length);
//            shmdt (db);
//            db = NULL;
//            return;
//        }
//        sem_post (&db->ref);
//        return;
//    }

    /* Initialise the DB */
    db->shmid = 0;
    db->length = length;
    pthread_rwlockattr_init (&attr);
    pthread_rwlockattr_setpshared (&attr, PTHREAD_PROCESS_SHARED);
    pthread_rwlock_init (&db->rwlock, &attr);
    pthread_rwlock_wrlock (&db->rwlock);
    pthread_rwlockattr_destroy (&attr);
    sem_init (&db->ref, 1, 1);
    memset (db->table, 0, NUM_BUCKETS * sizeof (hash_entry_t));
//    db->shmid = shmid;
    pthread_rwlock_unlock (&db->rwlock);
    return;
}

void
db_shutdown (bool force)
{
    int count;
//    int shmid;

    if (db == NULL)
        return;

    /* Decrement the ref count */
    sem_wait (&db->ref);

    /* Check if we are the last user of the cache */
    if (force || (sem_getvalue (&db->ref, &count) == 0 && count == 0))
    {
        /* Destroy the cache */
        //shmid = db->shmid;
        //db->shmid = 0;
        sem_destroy (&db->ref);
        pthread_rwlock_destroy (&db->rwlock);
        //shmdt (db);
        //shmctl (shmid, IPC_RMID, 0);
        rszshm_dt (&r);
        rszshm_unlink (&r);
    }
    else
    {
        /* Detach */
        rszshm_dt (&r);
        //shmdt (db);
    }
    db = NULL;
    return;
}

static uint64_t
db_calculate_timestamp (void)
{
    struct timespec tms;
    uint64_t micros = 0;
    if (clock_gettime(CLOCK_REALTIME, &tms)) {
        return 0;
    }

    micros = ((uint64_t)tms.tv_sec) * 1000000;
    micros += tms.tv_nsec/1000;
    return micros;
}

static uint64_t
db_timestamp_no_lock (const char *path)
{
    uint64_t timestamp = 0;
    hash_entry_t *entry;

    if (!db)
        return 0;

    entry = &db->table[hash_index (path)];
    if (strcmp (path, (char *) entry->path) == 0)
    {
        timestamp = entry->ts;
    }
    return timestamp;
}

uint64_t
db_timestamp (const char *path)
{
    uint64_t timestamp = 0;

    if (!db)
        return 0;

    pthread_rwlock_rdlock (&db->rwlock);
    timestamp = db_timestamp_no_lock (path);
    pthread_rwlock_unlock (&db->rwlock);
    return timestamp;
}

static bool
db_set (const char *path, const unsigned char *value, size_t length, uint64_t ts)
{
    hash_entry_t *entry;

    if (!db || strlen (path) + 1 > MAX_PATH ||
        (value && length > MAX_VALUE))
        return false;

    if (ts != UINT64_MAX && ts < db_timestamp (path))
        return false;

    entry = &db->table[hash_index (path)];
    if (value)
    {
        entry->ts = db_calculate_timestamp ();
        strcpy ((char *) entry->path, path);
        entry->length = length;
        memcpy (entry->value, value, length);
    }
    else if (strcmp (path, (char *) entry->path) == 0)
    {
        entry->path[0] = 0;
    }

    return true;
}


bool
db_add_no_lock (const char *path, const unsigned char *value, size_t length, uint64_t ts)
{
    return db_set (path, value, length, ts);
}

bool
db_add (const char *path, const unsigned char *value, size_t length, uint64_t ts)
{
    bool ret = false;
    pthread_rwlock_wrlock (&db->rwlock);
    ret = db_add_no_lock (path, value, length, ts);
    pthread_rwlock_unlock (&db->rwlock);
    return ret;
}

bool
db_delete_no_lock (const char *path, uint64_t ts)
{
    return db_set (path, NULL, 0, ts);
}

bool
db_delete (const char *path, uint64_t ts)
{
    bool ret = false;

    if (!db)
        return false;

    pthread_rwlock_rdlock (&db->rwlock);
    ret = db_delete_no_lock (path, ts);
    pthread_rwlock_unlock (&db->rwlock);
    return ret;
}

bool
db_get (const char *path, unsigned char **value, size_t *length)
{
    hash_entry_t *entry;

    if (!db)
        return false;

    pthread_rwlock_rdlock (&db->rwlock);
    entry = &db->table[hash_index (path)];
    if (strcmp (path, (char *) entry->path) != 0)
    {
        pthread_rwlock_unlock (&db->rwlock);
        return false;
    }
    *value = g_malloc (entry->length);
    memcpy (*value, entry->value, entry->length);
    *length = entry->length;
    pthread_rwlock_unlock (&db->rwlock);
    return true;
}

GList *
db_search (const char *path)
{
    GList *paths = NULL;
    int i;

    if (!db)
        return NULL;

    pthread_rwlock_rdlock (&db->rwlock);
    for (i = 0; i < NUM_BUCKETS; i++)
    {
        char *_path = (char *) db->table[i].path;
        if (_path && strncmp (_path, path, strlen (path)) == 0)
        {
            int len = strlen (_path);
            char *key = _path + strlen (path);
            if (*key == '/')
                key++;
            if (strchr (key, '/'))
                len -= ((_path + len) - strchr (key, '/'));
            paths = g_list_prepend (paths, g_strndup (_path, len));
        }
    }
    pthread_rwlock_unlock (&db->rwlock);
    return paths;
}

bool
db_prune (const char *path)
{
    int i;

    if (!db)
        return false;

    pthread_rwlock_wrlock (&db->rwlock);
    for (i = 0; i < NUM_BUCKETS; i++)
    {
        char *_path = (char *) db->table[i].path;
        if (_path && strncmp (_path, path, strlen (path)) == 0)
        {
            db->table[i].path[0] = 0;
        }
    }
    pthread_rwlock_unlock (&db->rwlock);

    return true;
}

#ifdef TEST
#define TEST_DB_MAX_ENTRIES 10000
#define TEST_DB_MAX_ITERATIONS 1000

void
test_db_internal_init ()
{
    db_init ();
    CU_ASSERT (db != NULL);
    db_shutdown (true);
}

void
test_db_internal_delete ()
{
    CU_ASSERT ("not done yet" == NULL);
//    struct database_node *node = db_node_add (NULL, "test_node");
//    db_node_delete (node);
}


void
test_db_path_to_node ()
{
    CU_ASSERT ("not done yet" == NULL);
//    db_init ();
//    pthread_rwlock_wrlock (&db_lock);
//    struct database_node *one = db_node_add (root, "one");
//    struct database_node *two = db_node_add (one, "two");
//    struct database_node *rua = db_node_add (one, "rua");
//    struct database_node *three = db_node_add (two, "three");
//    struct database_node *dos = db_node_add (two, "dos");
//    struct database_node *toru = db_node_add (two, "toru");
//
//    CU_ASSERT (db_path_to_node ("", 0) == root);
//    CU_ASSERT (db_path_to_node ("/", 0) == root);
//    CU_ASSERT (db_path_to_node ("/one", 0) == one);
//    CU_ASSERT (db_path_to_node ("/one/two", 0) == two);
//    CU_ASSERT (db_path_to_node ("/one/rua", 0) == rua);
//    CU_ASSERT (db_path_to_node ("/one/two/three", 0) == three);
//    CU_ASSERT (db_path_to_node ("/one/two/dos", 0) == dos);
//    CU_ASSERT (db_path_to_node ("/one/two/toru", 0) == toru);
//    CU_ASSERT (db_path_to_node ("/uno", 0) == NULL);
//    CU_ASSERT (db_path_to_node ("/uno/two", 0) == NULL);
//    CU_ASSERT (db_path_to_node ("/one/", 0) == one);
//
//    // nodes not in this list get destroyed as their children are deleted
//    db_node_delete (three);
//    db_node_delete (dos);
//    db_node_delete (toru);
//    db_node_delete (rua);
//
//    pthread_rwlock_unlock (&db_lock);
}

void
test_db_init_shutdown ()
{
    db_init ();
    db_shutdown (true);
}

void
test_db_add_delete ()
{
    const char *path = "/database/test";
    db_init ();
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown (true);
}

void
test_db_add_delete_perf ()
{
    char *path = NULL;
    uint64_t start;
    int i;

    db_init ();

    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        g_free (path);
    }

    start = get_time_us ();
    path = g_strdup_printf ("/database/test%d/test%d",
            TEST_DB_MAX_ENTRIES - 1, TEST_DB_MAX_ENTRIES - 1);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        CU_ASSERT (db_delete (path, UINT64_MAX));
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / 1000);

    g_free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_delete (path, UINT64_MAX));
        g_free (path);
    }
    db_delete ("", UINT64_MAX);
}

void
test_db_long_path ()
{
    char *path = NULL;
    char *value = NULL;
    size_t length;
    int i;

    path = g_strdup_printf ("%s", "/database/test");
    for (i=0; i<1024; i++)
    {
        char *old = path;
        path = g_strdup_printf ("%s/%08x", old, rand ());
        g_free (old);
    }
    db_init ();
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) != true);
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test") + 1));
    CU_ASSERT (value && strcmp (value, "test") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path, UINT64_MAX));
    g_free ((void *) path);
    db_shutdown (true);
}

void
_path_perf (int path_length, bool full)
{
    char *path = NULL;
    int count = TEST_DB_MAX_ITERATIONS / path_length;
    uint64_t start;
    int i;

    path = g_strdup_printf ("%s", "/database");
    for (i=0; i<(path_length - 1); i++)
    {
        char *old = path;
        path = g_strdup_printf ("%s/%08x", old, rand ());
        g_free (old);
    }
    db_init ();
    if (!full)
    {
        db_add (path, (const unsigned char *) "placeholder", strlen ("placeholder") + 1, UINT64_MAX);
        path[strlen (path) - 1]++;
    }
    start = get_time_us ();
    for (i = 0; i < count; i++)
    {
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        CU_ASSERT (db_delete (path, UINT64_MAX));
    }
    printf ("%d=%"PRIu64"us ", path_length, (get_time_us () - start) / count);
    if (!full)
    {
        path[strlen (path) - 1]--;
        db_delete (path, UINT64_MAX);
    }
    g_free (path);
    db_shutdown (true);
}

void test_db_path_perf ()
{
    _path_perf (5, true);
    _path_perf (10, true);
//    _path_perf (100, true);
//    _path_perf (1000, true);
    printf ("... ");
}

void test_db_path_exists_perf ()
{
    _path_perf (5, false);
    _path_perf (10, false);
//    _path_perf (100, false);
//    _path_perf (1000, false);
    printf (" ... ");
}

void
test_db_large_value ()
{
    const char *path = "/database/test";
    char *large;
    int len = 1024*1024;
    char *value = NULL;
    size_t length;

    large = g_malloc0 (len);
    memset (large, 'a', len-1);
    db_init ();
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) != true);
    CU_ASSERT (db_add (path, (const unsigned char *) large, len, UINT64_MAX));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == len);
    CU_ASSERT (value && strcmp (value, large) == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path, UINT64_MAX));
    g_free ((void *) large);
    db_shutdown (true);
}

void
test_db_get ()
{
    const char *path = "/database/test";
    char *value;
    size_t length;
    db_init ();
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) != true);
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test") + 1));
    CU_ASSERT (value && strcmp (value, "test") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown (true);
}

void
test_db_get_perf ()
{
    char *path = NULL;
    char *value = NULL;
    size_t length;
    uint64_t start;
    int i;
    bool res;

    db_init ();
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        g_free (path);
    }

    start = get_time_us ();
    path = g_strdup_printf ("/database/test%d/test%d",
            TEST_DB_MAX_ENTRIES - 1, TEST_DB_MAX_ENTRIES - 1);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT ((res = db_get (path, (unsigned char **) &value, &length)) == true);
        CU_ASSERT (value != NULL);
        if (!res || !value)
            goto exit;
        g_free ((void *) value);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / 1000);
  exit:
    g_free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_delete (path, UINT64_MAX));
        g_free (path);
    }
    db_shutdown (true);
}

void
test_db_replace ()
{
    const char *path = "/database/test";
    char *value;
    size_t length;
    int i;
    db_init ();
    for (i=0; i<10; i++)
    {
        char value[64];
        sprintf (value, "test%d", i);
        CU_ASSERT (db_add (path, (const unsigned char *) value, strlen (value) + 1, UINT64_MAX));
    }
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test9") + 1));
    CU_ASSERT (value && strcmp (value, "test9") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown (true);
}

void
test_db_search ()
{
    const char *path = "/database/test";
    GList *paths = NULL;
    db_init ();
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT ((paths = db_search ("/database/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, "/database/test", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, g_free);

    CU_ASSERT ((paths = db_search ("/database")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, "/database/test", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, g_free);

    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown (true);
}

void
test_db_search_perf ()
{
    char *path = NULL;
    GList *paths = NULL;
    uint64_t start;
    int i;
    db_init ();

    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        g_free (path);
    }

    start = get_time_us ();
    path = g_strdup_printf ("/database/test%d/", TEST_DB_MAX_ENTRIES - 1);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT ((paths = db_search (path)) != NULL);
        CU_ASSERT (g_list_length (paths) == 1);
        if (g_list_length (paths) != 1)
            goto exit;
        g_list_free_full (paths, g_free);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / 1000);
  exit:
  g_free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_delete (path, UINT64_MAX));
        g_free (path);
    }
    db_shutdown (true);
}

void
test_db_timestamping ()
{
    char *path = "/test/timestamps";
    char *path2 = "/test/timestamp2";
    char *ppath = "/test";

    uint64_t last_ts;

    db_init ();

    CU_ASSERT (db_add (path, (const unsigned char *) "test", 5, UINT64_MAX));
    last_ts = db_timestamp (path);
    sleep (1);
    CU_ASSERT (db_add (path2, (const unsigned char *) "test", 5, UINT64_MAX));
    CU_ASSERT (db_timestamp (path2) > last_ts);
    last_ts = db_timestamp (path2);
    CU_ASSERT (db_timestamp (path) < db_timestamp (path2));
    CU_ASSERT (db_timestamp (ppath) >= db_timestamp (path2));
    CU_ASSERT (db_timestamp ("/") >= db_timestamp (ppath));

    CU_ASSERT (db_delete (path2, UINT64_MAX));
    CU_ASSERT (db_timestamp (ppath) > last_ts);
    CU_ASSERT (db_timestamp ("/") >= db_timestamp (ppath));

    CU_ASSERT (db_delete (path, UINT64_MAX));

    db_shutdown (true);
}

CU_TestInfo tests_database_internal[] = {
    { "delete", test_db_internal_delete },
    { "path_to_node", test_db_path_to_node },
    { "init", test_db_internal_init },
    CU_TEST_INFO_NULL,
};

CU_TestInfo tests_database[] = {
    { "init/shutdown", test_db_init_shutdown },
    { "add/delete", test_db_add_delete },
    { "add/delete performance", test_db_add_delete_perf },
//    { "large value", test_db_large_value },
//    { "long path", test_db_long_path },
    { "path performance", test_db_path_perf },
    { "path exists perf", test_db_path_exists_perf },
    { "get", test_db_get },
    { "get performance", test_db_get_perf },
    { "replace", test_db_replace },
    { "search", test_db_search },
    { "search performance", test_db_search_perf },
    { "timestamping", test_db_timestamping },
    CU_TEST_INFO_NULL,
};
#endif
