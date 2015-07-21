/**
 * @file fastpath.c
 * Used for a shared memory fastpath for set and get.
 *
 * Copyright 2015, Allied Telesis Labs New Zealand, Ltd
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
#ifdef USE_SHM_FASTPATH
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <errno.h>
#ifdef TEST
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#define TEST_NUM_ITERATIONS 10000
static bool test_dont_wait_locked = false;
static bool test_dont_wait_unlocked = false;
#endif

#define NUM_CHANNELS            1
#define MAX_PATH                256
#define MAX_VALUE               128

typedef enum
{
    STATE_FREE,
    STATE_READY,
    STATE_DONE,
    STATE_ABORT,
} FP_STATE;

typedef struct fastpath_shm_t
{
    /* Shared memory */
    pthread_mutex_t lock;
    sem_t ref;
    int shmid;
    int length;

    /* Channels */
    struct {
        pthread_mutex_t lock;
        FP_STATE state;
        pthread_cond_t ready;
        pthread_cond_t done;
        /* Data */
        APTERYX_MODE mode;
        char path[MAX_PATH];
        char value[MAX_VALUE];
        uint32_t result;
    } channels[NUM_CHANNELS];
} fastpath_shm_t;

typedef struct fastpath_t
{
    fastpath_shm_t *shm;
    int timeout_us;
    bool running;
    pthread_t thread;
    int (*do_set)(const char *path, const char *value);
    char* (*do_get)(const char *path);
} fastpath_t;

static inline void
_timespec_addus (struct timespec *ts, long us)
{
    int sec = us / 1000000;
    us = us - sec * 1000000;
    ts->tv_nsec += us * 1000;
    ts->tv_sec += ts->tv_nsec/1000000000 + sec;
    ts->tv_nsec = ts->tv_nsec%1000000000;
}

static fastpath_t*
_fastpath_init (int key)
{
    fastpath_t *fp;
    pthread_mutexattr_t mutexattr;
    pthread_condattr_t condattr;
    int already_init = 0;
    int length;
    int shmid;
    int channel;

    /* Allocate the fastpath configuration structure */
    fp = calloc (1, sizeof (*fp));
    if (!fp)
    {
        ERROR ("Failed to allocate fastpath (%u:%s)\n", errno, strerror (errno));
        return NULL;
    }
    fp->timeout_us = RPC_TIMEOUT_US;

    /* Create/attach to the shared memory block */
    length = sizeof (fastpath_shm_t);
    shmid = shmget (key, length, 0644 | IPC_CREAT | IPC_EXCL);
    if (shmid < 0)
    {
        /* Another process is initializing this memory */
        shmid = shmget (key, length, 0644);
        already_init = 1;
    }
    if ((fp->shm = (fastpath_shm_t *) shmat (shmid, NULL, 0)) == (void*)-1)
    {
        ERROR ("Failed to attach to SHM fastpath (%u:%s)\n", errno, strerror (errno));
        free (fp);
        return NULL;
    }

    /* Check if someone else has already initialised the fastpath */
    if (already_init)
    {
        /* Wait for the other process to finish if required */
        while (shmid != fp->shm->shmid)
            usleep (10);
        if (fp->shm->length != length)
        {
            /* Incompatible shared memory segments! */
            ERROR ("SHM fastpath != %d bytes\n", length);
            shmdt (fp->shm);
            free (fp);
            return NULL;
        }
        sem_post (&fp->shm->ref);
        DEBUG ("FP(%x): Attaching to an existing fastpath\n", key);
        return fp;
    }

    /* Initialise the fastpath */
    DEBUG ("FP(%x): Initialising a new fastpath\n", key);
    memset (fp->shm, 0, sizeof (*fp->shm));
    fp->shm->shmid = 0;
    fp->shm->length = length;
    pthread_mutexattr_init (&mutexattr);
    pthread_mutexattr_setpshared (&mutexattr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init (&fp->shm->lock, &mutexattr);
    pthread_mutex_lock (&fp->shm->lock);
    sem_init (&fp->shm->ref, 1, 1);
    pthread_condattr_init (&condattr);
    pthread_condattr_setpshared (&condattr, PTHREAD_PROCESS_SHARED);
    for (channel=0; channel<NUM_CHANNELS; channel++)
    {
        pthread_mutex_init (&fp->shm->channels[channel].lock, &mutexattr);
        fp->shm->channels[channel].state = STATE_FREE;
        pthread_cond_init (&fp->shm->channels[channel].ready, &condattr);
        pthread_cond_init (&fp->shm->channels[channel].done, &condattr);
    }
    pthread_mutexattr_destroy (&mutexattr);
    pthread_condattr_destroy (&condattr);
    fp->shm->shmid = shmid;
    pthread_mutex_unlock (&fp->shm->lock);
    return fp;
}

static void
_fastpath_shutdown (fastpath_t *fp, bool force)
{
    struct timespec abs_time;
    int count;
    int shmid;
    int channel;

    if (fp == NULL || fp->shm == NULL || fp->shm->shmid == 0)
        return;

    /* Stop processing messages if required */
    fastpath_stop ();

    /* Lock and clear the global pointer to prevent further use */
    clock_gettime (CLOCK_MONOTONIC , &abs_time);
    abs_time.tv_sec += 5;
    if (pthread_mutex_timedlock (&fp->shm->lock, &abs_time) != 0)
    {
        ERROR ("FP: Ignoring failed attempt to lock fastpath\n");
    }

    /* Decrement the ref count and check if we are the last user */
    sem_wait (&fp->shm->ref);
    if (force || (sem_getvalue (&fp->shm->ref, &count) == 0 && count == 0))
    {
        /* Destroy the fastpath */
        DEBUG ("FP: Destroy fastpath\n");
        shmid = fp->shm->shmid;
        fp->shm->shmid = 0;
        sem_destroy (&fp->shm->ref);
        for (channel=0; channel<NUM_CHANNELS; channel++)
        {
            clock_gettime (CLOCK_MONOTONIC , &abs_time);
            abs_time.tv_sec += 5;
            if (pthread_mutex_timedlock (&fp->shm->channels[channel].lock, &abs_time) != 0)
            {
                ERROR ("FP: Ignoring failed attempt to lock channel %d\n", channel);
            }
            fp->shm->channels[channel].state = STATE_FREE;
            pthread_cond_destroy (&fp->shm->channels[channel].ready);
            pthread_cond_destroy (&fp->shm->channels[channel].done);
            pthread_mutex_unlock (&fp->shm->channels[channel].lock);
            pthread_mutex_destroy (&fp->shm->channels[channel].lock);
        }
        pthread_mutex_unlock (&fp->shm->lock);
        pthread_mutex_destroy (&fp->shm->lock);
        shmdt (fp->shm);
        shmctl (shmid, IPC_RMID, 0);
    }
    else
    {
        /* Detach */
        DEBUG ("FP: Detach from fastpath\n");
        pthread_mutex_unlock (&fp->shm->lock);
        shmdt (fp->shm);
    }

    free (fp);
    return;
}

static void*
_fastpath_process (void *data)
{
    fastpath_t *fp = (fastpath_t *)data;
    int channel = 0;

    DEBUG ("FP(%d): New thread (%lu)\n", channel, (unsigned long)pthread_self());

    /* Loop while running */
    while (fp && fp->shm && fp->running)
    {
        int result = -EOPNOTSUPP;
        char *value = NULL;

        /* Wait for some data - wake every 5 rpc timeouts */
        pthread_mutex_lock (&fp->shm->channels[channel].lock);
        while (fp->shm->channels[channel].state != STATE_READY)
            pthread_cond_wait (&fp->shm->channels[channel].ready,
                          &fp->shm->channels[channel].lock);

//        /* Check if the client has aborted */
//        if (fp->shm->channels[channel].state != STATE_READY)
//        {
//            ERROR ("FP(%d): Client aborted\n", channel);
//            fp->shm->channels[channel].state = STATE_FREE;
//            pthread_mutex_unlock (&fp->shm->channels[channel].lock);
//            continue;
//        }

        /* Process data */
        pthread_mutex_unlock (&fp->shm->channels[channel].lock);
        switch (fp->shm->channels[channel].mode)
        {
            case MODE_SET:
            {
                if (fp->do_set == NULL)
                {
                    DEBUG ("FP(%d): SET not implemented\n", channel);
                    break;
                }
                result = (fp->do_set) (fp->shm->channels[channel].path,
                        fp->shm->channels[channel].value[0] == '\0' ? NULL :
                                fp->shm->channels[channel].value);
                break;
            }
            case MODE_GET:
            {
                if (fp->do_get == NULL)
                {
                    DEBUG ("FP(%d): GET not implemented\n", channel);
                    break;
                }
                value = (fp->do_get) (fp->shm->channels[channel].path);
                result = 0;
                break;
            }
            default:
                ERROR ("FP(%d): Unsupported mode %d\n", channel, fp->shm->channels[channel].mode);
                break;
        }
        pthread_mutex_lock (&fp->shm->channels[channel].lock);

        /* Check for failure case */
        if (fp->shm->channels[channel].state == STATE_ABORT)
        {
            ERROR ("FP(%d): Client aborted\n", channel);
            fp->shm->channels[channel].state = STATE_FREE;
        }
        else
        {
            /* Indicate result ready */
            if (value)
            {
                if (strlen (value) < MAX_VALUE-1)
                    strcpy (fp->shm->channels[channel].value, value);
                else
                    result = -ENOMEM;
                free (value);
            }
            fp->shm->channels[channel].result = result;
            fp->shm->channels[channel].state = STATE_DONE;
            pthread_cond_signal (&fp->shm->channels[channel].done);
        }
        pthread_mutex_unlock (&fp->shm->channels[channel].lock);
    }

    DEBUG ("FP(%d): End thread (%lu)\n", channel, (unsigned long)pthread_self());
    fp->thread = 0;
    return NULL;
}

void
_fastpath_start (fastpath_t *fp, int (*set)(const char *path, const char *value),
        char* (*get)(const char *path))
{
    if (!fp || fp->running)
        return;

    DEBUG ("FP: Started monitoring fastpath\n");
    fp->do_set = set;
    fp->do_get = get;
    fp->running = true;
    pthread_create (&fp->thread, NULL, _fastpath_process, (void*)fp);
    return;
}

void
_fastpath_stop (fastpath_t *fp)
{
    int i;

    if (!fp || !fp->running)
        return;

    ERROR ("FP: Finished monitoring fastpath\n");
    fp->running = false;
    for (i=0; i < 5000 && fp->thread != 0; i++)
        usleep (1000);
    if (fp->thread != 0)
    {
        DEBUG ("Shutdown: Killing FP thread\n");
        pthread_cancel (fp->thread);
        pthread_join (fp->thread, NULL);
    }
}

bool
_fastpath_get (fastpath_t *fp, const char *path, char **value)
{
    int channel;
    bool rc = true;

    /* Check if we can use the fastpath */
    if (!fp  ||
        strlen (path) + 1 > MAX_PATH)
    {
        DEBUG ("GET(f): data not suitable\n");
        return false;
    }
    *value = NULL;

    /* Find an available channel */
    for (channel=0; channel<NUM_CHANNELS; channel++)
    {
        if (pthread_mutex_trylock (&fp->shm->channels[channel].lock) != 0)
            continue;
        if (fp->shm->channels[channel].state == STATE_FREE)
            break;
        pthread_mutex_unlock (&fp->shm->channels[channel].lock);
    }
    if (channel >= NUM_CHANNELS)
    {
        DEBUG ("GET(f): no free channels\n");
        return false;
    }

    /* Post the message */
    fp->shm->channels[channel].mode = MODE_GET;
    strncpy (fp->shm->channels[channel].path, path, MAX_PATH);
    fp->shm->channels[channel].value[0] = '\0';
    fp->shm->channels[channel].state = STATE_READY;
    pthread_cond_signal (&fp->shm->channels[channel].ready);

#ifdef TEST
    if (test_dont_wait_locked)
        return false;
    if (test_dont_wait_unlocked)
    {
        pthread_mutex_unlock (&fp->shm->channels[channel].lock);
        return false;
    }
#endif

    /* Wait for the result */
    while (fp->shm->channels[channel].state == STATE_READY)
        pthread_cond_wait (&fp->shm->channels[channel].done,
                           &fp->shm->channels[channel].lock);
    if (fp->shm->channels[channel].state != STATE_DONE)
    {
        ERROR ("GET(f:%d): Server abort\n", channel);
        pthread_mutex_unlock (&fp->shm->channels[channel].lock);
        return false;
    }

    if (fp->shm->channels[channel].result)
    {
        errno = fp->shm->channels[channel].result;
        rc = false;
    }
    else
    {
        *value = fp->shm->channels[channel].value[0] != '\0' ?
                strdup (fp->shm->channels[channel].value) : NULL;
    }

    /* Done with the channel */
    fp->shm->channels[channel].state = STATE_FREE;
    pthread_mutex_unlock (&fp->shm->channels[channel].lock);
    return rc;
}

bool
_fastpath_set (fastpath_t *fp, const char *path, const char *value, bool *rc)
{
    int channel;

    /* Check if we can use the fastpath */
    if (!fp  ||
        strlen (path) + 1 > MAX_PATH ||
        (value && strlen (value) + 1 > MAX_VALUE))
    {
        DEBUG ("SET(f): data not suitable\n");
        return false;
    }

    /* Find an available channel */
    for (channel=0; channel<NUM_CHANNELS; channel++)
    {
        if (pthread_mutex_trylock (&fp->shm->channels[channel].lock) != 0)
            continue;
        if (fp->shm->channels[channel].state == STATE_FREE)
            break;
        pthread_mutex_unlock (&fp->shm->channels[channel].lock);
    }
    if (channel >= NUM_CHANNELS)
    {
        DEBUG ("SET(f): no free channels\n");
        return false;
    }

    DEBUG ("SET(f:%d): %s = %s\n", channel, path, value);

    /* Post the message */
    fp->shm->channels[channel].mode = MODE_SET;
    strncpy (fp->shm->channels[channel].path, path, MAX_PATH);
    if (value)
        strncpy (fp->shm->channels[channel].value, value, MAX_VALUE);
    else
        fp->shm->channels[channel].value[0] = '\0';
    fp->shm->channels[channel].state = STATE_READY;
    pthread_cond_signal (&fp->shm->channels[channel].ready);

#ifdef TEST
    if (test_dont_wait_locked)
        return false;
    if (test_dont_wait_unlocked)
    {
        pthread_mutex_unlock (&fp->shm->channels[channel].lock);
        return false;
    }
#endif

    /* Wait for the result */
    while (fp->shm->channels[channel].state == STATE_READY)
        pthread_cond_wait (&fp->shm->channels[channel].done,
                           &fp->shm->channels[channel].lock);
    if (fp->shm->channels[channel].state != STATE_DONE)
    {
        ERROR ("SET(f:%d): Server abort\n", channel);
        pthread_mutex_unlock (&fp->shm->channels[channel].lock);
        return false;
    }

    if (fp->shm->channels[channel].result)
    {
        errno = fp->shm->channels[channel].result;
        *rc = false;
    }
    else
    {
        *rc = true;
    }

    /* Done with the channel */
    fp->shm->channels[channel].state = STATE_FREE;
    pthread_mutex_unlock (&fp->shm->channels[channel].lock);
    return true;
}

#ifdef TEST
static fastpath_t *test_fastpath = NULL;

void
test_check_integrity (void)
{
    int count;
    int channel;

    CU_ASSERT (test_fastpath != NULL);
    CU_ASSERT (test_fastpath->shm != NULL);
    CU_ASSERT (test_fastpath->running);
    CU_ASSERT (test_fastpath->thread != -1);
    //test_fastpath->shm->lock
    CU_ASSERT (test_fastpath->shm->length == sizeof (*test_fastpath->shm));
    CU_ASSERT ((sem_getvalue (&test_fastpath->shm->ref, &count) == 0 && count == 1));
    for (channel=0; channel<NUM_CHANNELS; channel++)
    {
        //test_fastpath->shm->channels[channel].lock;
        CU_ASSERT (test_fastpath->shm->channels[channel].state == STATE_FREE);
        //test_fastpath->shm->channels[channel].ready;
        //test_fastpath->shm->channels[channel].done;
    }
    return;
}

void
test_fp_init (void)
{
    /* Initialise an alternative fastpath */
    test_fastpath = _fastpath_init (0x01234567);
    test_fastpath->timeout_us = 100000;
    _fastpath_start (test_fastpath, NULL, NULL);
    usleep (TEST_SLEEP_TIMEOUT);
}

void
test_fp_do_get_null (void)
{
    char *value = NULL;
    test_fastpath->do_get = NULL;
    CU_ASSERT (!_fastpath_get (test_fastpath, TEST_PATH"/entity/zones/private/name", &value));
    CU_ASSERT (value == NULL);
    test_check_integrity ();
}

void
test_fp_do_set_null (void)
{
    bool rc = false;
    test_fastpath->do_set = NULL;
    CU_ASSERT (_fastpath_set (test_fastpath, TEST_PATH"/entity/zones/private/name", NULL, &rc));
    CU_ASSERT (rc == false);
    test_check_integrity ();
}

char*
_test_do_get_timeout (const char *path)
{
    DEBUG ("TEST: Get timeout\n");
    usleep (2*test_fastpath->timeout_us);
    return NULL;
}

void
test_fp_get_client_timeout (void)
{
    char *value = NULL;
    test_fastpath->do_get = _test_do_get_timeout;
    CU_ASSERT (!_fastpath_get (test_fastpath, TEST_PATH"/entity/zones/private/name", &value));
    CU_ASSERT (value == NULL);
    usleep (3*test_fastpath->timeout_us);
    test_check_integrity ();
}

int
_test_do_set_timeout (const char *path, const char *value)
{
    DEBUG ("TEST: Set timeout\n");
    usleep (2*test_fastpath->timeout_us);
    return 0;
}

void
test_fp_set_client_timeout (void)
{
    bool rc = false;
    test_fastpath->do_set = _test_do_set_timeout;
    CU_ASSERT (!_fastpath_set (test_fastpath, TEST_PATH"/entity/zones/private/name", NULL, &rc));
    CU_ASSERT (rc == false);
    usleep (3*test_fastpath->timeout_us);
    test_check_integrity ();
}

void
test_fp_get_client_disappear_locked (void)
{
    char *value = NULL;
    test_fastpath->do_get = _test_do_get_timeout;
    test_dont_wait_locked = true;
    CU_ASSERT (!_fastpath_get (test_fastpath, TEST_PATH"/entity/zones/private/name", &value));
    CU_ASSERT (value == NULL);
    usleep (2*test_fastpath->timeout_us);
    test_dont_wait_locked = false;
    test_check_integrity ();
}

void
test_fp_get_client_disappear_unlocked (void)
{
    char *value = NULL;
    test_fastpath->do_get = _test_do_get_timeout;
    test_dont_wait_unlocked = true;
    CU_ASSERT (!_fastpath_get (test_fastpath, TEST_PATH"/entity/zones/private/name", &value));
    CU_ASSERT (value == NULL);
    usleep (2*test_fastpath->timeout_us);
    test_dont_wait_unlocked = false;
    test_check_integrity ();
}

char*
_test_do_get (const char *path)
{
    DEBUG ("TEST: Get %s = private\n", path);
    return strdup ("private");
}

void
test_fp_get (void)
{
    char *value = NULL;
    test_fastpath->do_get = _test_do_get;
    CU_ASSERT (_fastpath_get (test_fastpath, TEST_PATH"/entity/zones/private/name", &value));
    CU_ASSERT (value && strcmp (value, "private") == 0);
    free (value);
    test_check_integrity ();
}

int
_test_do_set (const char *path, const char *value)
{
    DEBUG ("TEST: Set %s = %s\n", path, value);
    return 0;
}

void
test_fp_set (void)
{
    bool rc = false;
    test_fastpath->do_set = _test_do_set;
    CU_ASSERT (_fastpath_set (test_fastpath, TEST_PATH"/entity/zones/private/name", NULL, &rc));
    CU_ASSERT (rc == true);
    test_check_integrity ();
}

void
test_fp_perf_get ()
{
    char *paths[TEST_NUM_ITERATIONS];
    char *value = NULL;
    uint64_t start;
    int i;

    test_fastpath->do_get = _test_do_get;
    for (i = 0; i < TEST_NUM_ITERATIONS; i++)
         CU_ASSERT (asprintf(&paths[i], TEST_PATH"/zones/%d/state", i) > 0);
    start = get_time_us ();
    for (i = 0; i < TEST_NUM_ITERATIONS; i++)
    {
        if (!_fastpath_get (test_fastpath, paths[i], &value) || !value)
            goto exit;
        free ((void *) value);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_NUM_ITERATIONS);
exit:
    for (i = 0; i < TEST_NUM_ITERATIONS; i++)
        free (paths[i]);
    test_check_integrity ();
}

void
test_fp_perf_set ()
{
    char *paths[TEST_NUM_ITERATIONS];
    uint64_t start;
    int i;
    bool res;

    test_fastpath->do_set = _test_do_set;
    for (i = 0; i < TEST_NUM_ITERATIONS; i++)
        CU_ASSERT (asprintf(&paths[i], TEST_PATH"/zones/%d/state", i) > 0);
    start = get_time_us ();
    for (i = 0; i < TEST_NUM_ITERATIONS; i++)
    {
        if (!_fastpath_set (test_fastpath, paths[i], NULL, &res) || !res)
            goto exit;
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_NUM_ITERATIONS);
exit:
    for (i = 0; i < TEST_NUM_ITERATIONS; i++)
        free (paths[i]);
    test_check_integrity ();
}

void
test_fp_shutdown (void)
{
    /* Shutdown the alternative fastpath */
    _fastpath_shutdown (test_fastpath, true);
    test_fastpath = NULL;
}

CU_TestInfo tests_fastpath[] = {
    { "fp init", test_fp_init },
    { "fp integrity", test_check_integrity },
    { "fp do_get null", test_fp_do_get_null },
    { "fp do_set null", test_fp_do_set_null },
    { "fp get client timeout", test_fp_get_client_timeout },
    { "fp set client timeout", test_fp_set_client_timeout },
    { "fp get", test_fp_get },
    { "fp set", test_fp_set },
    { "fp get perf", test_fp_perf_get },
    { "fp set perf", test_fp_perf_set },
    { "fp get client disappear unlocked", test_fp_get_client_disappear_unlocked },
    { "fp get client disappear locked", test_fp_get_client_disappear_locked },
    { "shutdown", test_fp_shutdown },
    CU_TEST_INFO_NULL,
};
#endif

fastpath_t *fastpath = NULL;

void
fastpath_init (void)
{
    if (fastpath)
        return;
    fastpath = _fastpath_init (APTERYX_FASTPATH_KEY);
}

void
fastpath_shutdown (bool force)
{
    fastpath_t *fp = fastpath;
    fastpath = NULL;
    _fastpath_shutdown (fp, force);
}

void
fastpath_start (int (*set)(const char *path, const char *value),
        char* (*get)(const char *path))
{
    _fastpath_start (fastpath, set, get);
    return;
}

void
fastpath_stop (void)
{
    _fastpath_stop (fastpath);
}

bool
fastpath_get (const char *path, char **value)
{
    return _fastpath_get (fastpath, path, value);
}

bool
fastpath_set (const char *path, const char *value, bool *rc)
{
    return _fastpath_set (fastpath, path, value, rc);
}

#endif /* USE_SHM_FASTPATH */
