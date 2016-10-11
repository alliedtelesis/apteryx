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
#include "apteryx.h"
#include "rszshm.h"
#ifdef TEST
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#endif

#define MAX_KEY             128
#define MAX_VALUE           128
#define NUM_BUCKETS         4096
#define NUM_NODES           10000
#define NUM_STEPS           5
typedef uint32_t            offset_t;

/* Hash table */
typedef struct db_hash_t
{
    int length;
    offset_t buckets[NUM_BUCKETS];
} db_hash_t;

/* Node structure */
typedef struct db_node_t
{
    offset_t parent;
    uint64_t timestamp;
    char key[MAX_KEY];
    uint32_t length;
    uint8_t value[MAX_VALUE];
    db_hash_t children;
    unsigned int removing;

    /* Callback */
    size_t cb;
} db_node_t;

/* Database structure */
typedef struct db_t
{
    pthread_rwlock_t rwlock;
    sem_t ref;
    int length;
    /* Nodes */
    int num_nodes;
    offset_t first_free;
    db_node_t nodes[NUM_NODES];
} db_t;

#define NODE_TO_OFFSET(node) (((size_t)node - (size_t)db->nodes) / sizeof (db_node_t))
#define OFFSET_TO_NODE(offset) ((db_node_t*)(&db->nodes[offset]))

/* Globals */
static sem_t local_ref;
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
static offset_t
hash_index (db_hash_t *ht, const char *key)
{
    uint32_t hash = hash_fn (key) % NUM_BUCKETS;
    uint32_t rindex = NUM_BUCKETS;
    uint32_t index;
    int i = 0;

    index = hash;
    while (i < NUM_STEPS)
    {
        db_node_t *node = OFFSET_TO_NODE (ht->buckets[index]);
        if (ht->buckets[index] && strcmp (key, node->key) == 0)
        {
            return index;
        }
        if (rindex == NUM_BUCKETS && ht->buckets[index] == 0)
        {
            rindex = index;
        }
        i++;
        index = (hash + i * i) % NUM_BUCKETS;
    }
    //printf("HASH: %s=%d\n", key, rindex == NUM_BUCKETS ? hash : rindex);
    return rindex == NUM_BUCKETS ? hash : rindex;
}

static guint
db_hash_table_size (db_hash_t *ht)
{
    return ht->length;
}

static bool
db_hash_table_insert (db_hash_t *ht, const char *key, offset_t data)
{
    ht->buckets[hash_index (ht, key)] = data;
    ht->length++;
    return true;
}

static bool
db_hash_table_remove (db_hash_t *ht, const char *key)
{
    ht->buckets[hash_index (ht, key)] = 0;
    ht->length--;
    return true;
}

static offset_t
db_hash_table_lookup (db_hash_t *ht, const char *key)
{
    return ht->buckets[hash_index (ht, key)];
}

static db_node_t *
db_path_to_node (const char *path, uint64_t timestamp)
{
    char *key = g_strdup (path);
    char *start = key;
    int path_length;
    db_node_t *node = NULL;
    db_node_t *current = &db->nodes[0];

    /* Trim trailing '/' */
    if (strlen (key) && key[strlen (key) - 1] == '/')
        key[strlen (key) - 1] = '\0';
    path_length = strlen (key);

    if (strchr (key, '/'))
        *strchr (key, '/') = '\0';

    while (current)
    {
        if (key + strlen (key) == start + path_length)
        {
            if (strcmp (key, current->key) == 0)
            {
                node = current;
                break;
            }
        }

        /* look down a level */
        if (db_hash_table_size (&current->children) == 0)
        {
            node = NULL;
            break;
        }

        key += strlen (key) + 1;
        if (strchr (key, '/'))
            *strchr (key, '/') = '\0';

        /* This node is in a path that is being updated */
        if (timestamp)
            current->timestamp = timestamp;

        offset_t offset = db_hash_table_lookup (&current->children, key);
        if (!offset)
        {
            current = NULL;
            break;
        }
        current = OFFSET_TO_NODE (offset);
    }

    /* This node is in a path that is being updated */
    if (node && timestamp)
        node->timestamp = timestamp;

    g_free (start);
    return node;
}

static void
db_node_delete (db_node_t *node)
{
    if (!node)
        return;

    node->removing++;

    if (node->removing <= 1 && node->parent &&
        db_hash_table_size (&db->nodes[node->parent].children))
    {
        db_hash_table_remove (&db->nodes[node->parent].children, node->key);
        if (db_hash_table_size (&db->nodes[node->parent].children) == 0 && db->nodes[node->parent].length == 0)
        {
            db_node_delete (&db->nodes[node->parent]);
        }
    }

    if (node->removing == 1)
    {
        if (db_hash_table_size (&node->children))
        {
            db_hash_t *ht = &node->children;
            int i;

            for (i=0; i<NUM_BUCKETS; i++)
            {
                if (ht->buckets[i])
                {
                    db_node_t *child = OFFSET_TO_NODE (ht->buckets[i]);
                    db_node_delete (child);
                }
            }
        }
        node->key[0] = '\0';
        node->value[0] = '\0';
    }
    else
    {
        node->removing--;
    }

}

static db_node_t *
db_node_add (db_node_t *parent, const char *key)
{
    //TEMP
    if (strlen (key) + 1 > MAX_KEY)
        return NULL;

    db_node_t *new_node = &db->nodes[db->first_free];
    memset (new_node, 0, sizeof (db_node_t));
    db->first_free++;
    strcpy (new_node->key, key);
    new_node->parent = parent ? NODE_TO_OFFSET (parent) : 0;
    if (parent)
    {
        db_hash_table_insert (&parent->children, new_node->key, NODE_TO_OFFSET (new_node));
    }
    return new_node;
}

static db_node_t *
db_parent_get (const char *path)
{
    db_node_t *node = NULL;
    char *parent = g_strdup (path);

    if (strlen (parent) == 0)
    {
        /* found the root node */
        //root = db_node_add (NULL, "");
        g_free (parent);
        return NULL;
    }
    if (strchr (parent, '/') != NULL)
        *strrchr (parent, '/') = '\0';

    if ((node = db_path_to_node (parent, 0)) == NULL)
    {
        db_add_no_lock (parent, NULL, 0, UINT64_MAX);
        node = db_path_to_node (parent, 0);
    }
    g_free (parent);
    return node;
}

void
db_init (void)
{
//    int already_init = 0;
    pthread_rwlockattr_t attr;
    int length;

    if (db)
    {
        DEBUG ("DB: Init - already initialised\n");
        sem_post (&local_ref);
        return;
    }
    sem_init (&local_ref, 1, 1);

    DEBUG ("DB: Init - creating\n");

    /* Create/attach to the shared memory block */
    length = sizeof (db_t);
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
    db->length = length;
    db->num_nodes = NUM_NODES;
    db->first_free = 1;
    pthread_rwlockattr_init (&attr);
    pthread_rwlockattr_setpshared (&attr, PTHREAD_PROCESS_SHARED);
    pthread_rwlock_init (&db->rwlock, &attr);
    pthread_rwlock_wrlock (&db->rwlock);
    pthread_rwlockattr_destroy (&attr);
    sem_init (&db->ref, 1, 1);
    memset (db->nodes, 0, NUM_NODES * sizeof (db_node_t));
    pthread_rwlock_unlock (&db->rwlock);
    return;
}

void
db_shutdown (bool force)
{
    int count;

    if (db == NULL)
        return;

    /* Decrement the local ref count */
    sem_wait (&local_ref);
    if (sem_getvalue (&local_ref, &count) == 0 && count != 0)
    {
        DEBUG ("DB: Shutdown - more local users\n");
        return;
    }

    /* Decrement the ref count */
    sem_wait (&db->ref);

    /* Check if we are the last user of the DB */
    if (force || (sem_getvalue (&db->ref, &count) == 0 && count == 0))
    {
        /* Destroy the cache */
        sem_destroy (&db->ref);
        pthread_rwlock_destroy (&db->rwlock);
        rszshm_dt (&r);
        rszshm_unlink (&r);
        DEBUG ("DB: Shutdown and destroy\n");
    }
    else
    {
        DEBUG ("DB: Detach from the DB\n");
        /* Detach */
        rszshm_dt (&r);
    }
    db = NULL;
    return;
}

static uint64_t
db_calculate_timestamp (void)
{
    struct timespec tms;
    uint64_t micros = 0;
    if (clock_gettime(CLOCK_REALTIME, &tms))
        return 0;
    micros = ((uint64_t)tms.tv_sec) * 1000000;
    micros += tms.tv_nsec/1000;
    return micros;
}

static uint64_t
db_timestamp_no_lock (const char *path)
{
    uint64_t timestamp = 0;
    db_node_t *new_value = db_path_to_node (path, 0);
    if (new_value)
    {
        timestamp = new_value->timestamp;
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

bool
db_add_no_lock (const char *path, const unsigned char *value, size_t length, uint64_t ts)
{
    uint64_t timestamp = db_calculate_timestamp();

    //TEMP
    if (length > MAX_VALUE)
        return false;

    if (ts != UINT64_MAX && ts < db_timestamp_no_lock (path))
        return false;

    db_node_t *new_value = db_path_to_node (path, timestamp);
    if (!new_value)
    {
        db_node_t *parent = db_parent_get (path);
        const char *key = NULL;

        if (strchr (path, '/') != NULL)
            key = strrchr (path, '/') + 1;
        else
            key = path;
        new_value = db_node_add (parent, key);
        new_value->timestamp = timestamp;
    }
    new_value->value[0] = '\0';
    if (length > 0)
    {
        //new_value->value = g_malloc (length);
        memcpy (new_value->value, value, length);
        if (new_value->cb != 0)
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) new_value->cb;
            uint64_t id = getpid ();

            DEBUG ("WATCH \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                            path, id, new_value->cb);

            cb (path, (char *)value);
        }
    }
    new_value->length = length;

    return true;
}

bool
db_add (const char *path, const unsigned char *value, size_t length, uint64_t ts)
{
    bool ret = false;

    if (!db)
        return false;

    pthread_rwlock_wrlock (&db->rwlock);
    ret = db_add_no_lock (path, value, length, ts);
    pthread_rwlock_unlock (&db->rwlock);
    return ret;
}

bool
db_delete_no_lock (const char *path, uint64_t ts)
{
    bool ret = false;
    if (ts == UINT64_MAX || ts >= db_timestamp_no_lock (path))
    {
        db_node_t *node = db_path_to_node (path, db_calculate_timestamp ());
        if (node)
            db_node_delete (node);
        ret = true;
    }
    return ret;
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
    db_node_t *node;

    if (!db)
        return false;

    pthread_rwlock_rdlock (&db->rwlock);
    node = db_path_to_node (path, 0);
    if (!node)
    {
        pthread_rwlock_unlock (&db->rwlock);
        return false;
    }
    *value = g_malloc (node->length);
    memcpy (*value, node->value, node->length);
    *length = node->length;
    pthread_rwlock_unlock (&db->rwlock);
    return true;
}

GList *
db_search (const char *path)
{
    bool end_with_slash = strlen (path) > 0 ? path[strlen (path)-1] == '/' : false;
    GList *paths = NULL;
    db_hash_t *ht;
    int i;

    if (!db)
        return NULL;

    pthread_rwlock_rdlock (&db->rwlock);
    db_node_t *node = db_path_to_node (path, 0);
    if (node == NULL || db_hash_table_size (&node->children) == 0)
    {
        pthread_rwlock_unlock (&db->rwlock);
        return NULL;
    }

    ht = &node->children;
    for (i=0; i<NUM_BUCKETS; i++)
    {
        if (ht->buckets[i])
        {
            db_node_t *child = OFFSET_TO_NODE (ht->buckets[i]);
            paths = g_list_prepend (paths,
                        g_strdup_printf("%s%s%s", path, end_with_slash ? "" : "/",
                                child->key));
        }
    }

    pthread_rwlock_unlock (&db->rwlock);
    return paths;
}

bool
db_prune (const char *path)
{
    return db_delete (path, UINT64_MAX);
}

bool
db_watch (const char *path, size_t cb)
{
    if (!db)
        return false;

    pthread_rwlock_wrlock (&db->rwlock);
    db_node_t *new_value = db_path_to_node (path, 0);
    if (!new_value)
    {
        db_node_t *parent = db_parent_get (path);
        const char *key = NULL;

        if (strchr (path, '/') != NULL)
            key = strrchr (path, '/') + 1;
        else
            key = path;
        new_value = db_node_add (parent, key);
        new_value->cb = cb;
        new_value->timestamp = 0;
    }
    else
    {
        new_value->cb = cb;
    }
    pthread_rwlock_unlock (&db->rwlock);
    return true;
}

bool
db_unwatch (const char *path, size_t cb)
{
    db_node_t *node = db_path_to_node (path, 0);
    if (node)
    {
        node->cb = 0;
        if (node->value[0] == '\0')
        {
            db_node_delete (node);
        }
    }
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
    db_shutdown (false);
}

void
test_db_internal_delete ()
{
    db_init ();
    db_node_t *node = db_node_add (NULL, "test_node");
    db_node_delete (node);
    db_shutdown (false);
}


void
test_db_path_to_node ()
{
    db_init ();
    pthread_rwlock_wrlock (&db->rwlock);
    db_node_t *one = db_node_add (&db->nodes[0], "one");
    db_node_t *two = db_node_add (one, "two");
    db_node_t *rua = db_node_add (one, "rua");
    db_node_t *three = db_node_add (two, "three");
    db_node_t *dos = db_node_add (two, "dos");
    db_node_t *toru = db_node_add (two, "toru");

    CU_ASSERT (db_path_to_node ("", 0) == &db->nodes[0]);
    CU_ASSERT (db_path_to_node ("/", 0) == &db->nodes[0]);
    CU_ASSERT (db_path_to_node ("/one", 0) == one);
    CU_ASSERT (db_path_to_node ("/one/two", 0) == two);
    CU_ASSERT (db_path_to_node ("/one/rua", 0) == rua);
    CU_ASSERT (db_path_to_node ("/one/two/three", 0) == three);
    CU_ASSERT (db_path_to_node ("/one/two/dos", 0) == dos);
    CU_ASSERT (db_path_to_node ("/one/two/toru", 0) == toru);
    CU_ASSERT (db_path_to_node ("/uno", 0) == NULL);
    CU_ASSERT (db_path_to_node ("/uno/two", 0) == NULL);
    CU_ASSERT (db_path_to_node ("/one/", 0) == one);

    // nodes not in this list get destroyed as their children are deleted
    db_node_delete (three);
    db_node_delete (dos);
    db_node_delete (toru);
    db_node_delete (rua);

    pthread_rwlock_unlock (&db->rwlock);
    db_shutdown (false);
}

void
test_db_init_shutdown ()
{
    db_init ();
    db_shutdown (false);
}

void
test_db_add_delete ()
{
    const char *path = "/database/test";
    db_init ();
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown (false);
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
    db_shutdown (false);
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
    db_shutdown (false);
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
    db_shutdown (false);
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
    db_shutdown (false);
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
    db_shutdown (false);
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
    db_shutdown (false);
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
    db_shutdown (false);
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
    db_shutdown (false);
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
    db_shutdown (false);
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

    db_shutdown (false);
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
    { "large value", test_db_large_value },
    { "long path", test_db_long_path },
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
