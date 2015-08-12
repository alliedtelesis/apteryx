#include "internal.h"

#include <errno.h>

bool lock_init(pthread_mutex_t *lock)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);

    if(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0)
    {
        fprintf (stderr, "Error creating exploding lock\n");
    }

    /* create the mutex */
    pthread_mutex_init (lock, &attr);
    return true;
}

bool lock_lock(pthread_mutex_t *lock)
{
    // attempt to grab the lock
    int eval = pthread_mutex_lock(lock);

    // if an error occured ..
    if(eval != 0)
    {
        if(eval == EINVAL)
        {
            fprintf(stderr, "Lock Invalid\nBye :(\n");
            *((int *)0x0) = 0xdead;
        }
        if(eval == EDEADLK)
        {
            // this is really bad ...
            fprintf(stderr, "Lock is Already Held By This THREAD\nBye :)\n");
            *((int *)0x0) = 0x1234;
        }
        fprintf(stderr, "lock_lock: %s\n", strerror (errno));
    }
    // otherwise, success
    return true;
}

bool lock_unlock(pthread_mutex_t *lock)
{
    int eval = pthread_mutex_unlock(lock);

    // if an error occured ..
    if(eval != 0)
    {
        if(eval == EINVAL)
        {
            fprintf(stderr, "Lock Invalid\nBye :(\n");
            *((int *)0x0) = 0xdead;
        }
        if(eval == EPERM)
        {
            // this is really bad ...
            fprintf(stderr, "Attempting to Release Lock NOT HELD By This THREAD\nBye :)\n");
            *((int *)0x0) = 0x1234;
        }
        fprintf(stderr, "lock_lock: %s\n", strerror (errno));
    }
    return true;
}

bool lock_deinit (pthread_mutex_t *lock)
{
    int eval = pthread_mutex_destroy (lock);
    // if an error occured ..
    if(eval != 0)
    {
        // busy mutex, come back later
        if(eval == EBUSY)
        {
            fprintf(stderr, "Lock busy\nBye\n");
            *((int *)0x0) = 0x51a11;
        }
    }
    return true;
}
