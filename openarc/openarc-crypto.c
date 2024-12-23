/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include "build-config.h"

/* system includes */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/* openssl includes */
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

/* openarc includes */
#include "openarc-crypto.h"
#include "openarc.h"

/* globals */
static bool             crypto_init_done = false;
static pthread_mutex_t  id_lock;
static pthread_key_t    id_key;
static unsigned int     nmutexes = 0;
static unsigned long    threadid = 0L;
static pthread_mutex_t *mutexes = NULL;

/*
**  ARCF_CRYPTO_LOCK_CALLBACK -- locking callback for libcrypto
**
**  Parameters:
**  	mode -- lock mode (request from libcrypto)
**  	idx -- lock index for this request
**  	file -- file making the request
**  	line -- line making the request
**
**  Return value:
**  	None.
*/

static void
arcf_crypto_lock_callback(int                      mode,
                          int                      idx,
                          /* UNUSED */ const char *file,
                          /* UNUSED */ int         line)
{
    int status;

    if ((mode & CRYPTO_LOCK) != 0)
    {
        status = pthread_mutex_lock(&mutexes[idx]);
    }
    else
    {
        status = pthread_mutex_unlock(&mutexes[idx]);
    }

    assert(status == 0);
}

/*
**  ARCF_CRYPTO_GET_ID -- generate/retrieve thread ID
**
**  Parameters:
**
**  Return value:
**
*/

static unsigned long
arcf_crypto_get_id(void)
{
    unsigned long *id;

    id = pthread_getspecific(id_key);
    if (id == NULL)
    {
        id = ARC_MALLOC(sizeof *id);
        assert(pthread_mutex_lock(&id_lock) == 0);
        threadid++;
        *id = threadid;
        assert(pthread_mutex_unlock(&id_lock) == 0);
        assert(pthread_setspecific(id_key, id) == 0);
    }

    return *id;
}

/*
**  ARCF_CRYPTO_FREE_ID -- destroy thread ID
**
**  Parameters:
**  	ptr -- pointer to be destroyed
**
**  Return value:
**  	None.
*/

static void
arcf_crypto_free_id(void *ptr)
{
    /*
    **  Trick arcf_crypto_get_id(); the thread-specific pointer has
    **  already been cleared at this point, but arcf_crypto_get_id()
    **  may be called by ERR_remove_state() which will then allocate a
    **  new thread pointer if the thread-specific pointer is NULL.  This
    **  means a memory leak of thread IDs and, on Solaris, an infinite loop
    **  because the destructor (indirectly) re-sets the thread-specific
    **  pointer to something not NULL.  See pthread_key_create(3).
    */

    if (ptr != NULL)
    {
        assert(pthread_setspecific(id_key, ptr) == 0);

        ERR_remove_state(0);

        ARC_FREE(ptr);

        /* now we can actually clear it for real */
        assert(pthread_setspecific(id_key, NULL) == 0);
    }
}

/*
**  ARCF_CRYPTO_DYN_CREATE -- dynamically create a mutex
**
**  Parameters:
**  	file -- file making the request
**  	line -- line making the request
**
**  Return value:
**  	Pointer to the new mutex.
*/

static struct CRYPTO_dynlock_value *
arcf_crypto_dyn_create(/* UNUSED */ const char *file,
                       /* UNUSED */ int         line)
{
    int err;
    pthread_mutex_t *new;

    new = ARC_MALLOC(sizeof(pthread_mutex_t));
    if (new == NULL)
    {
        return NULL;
    }

    err = pthread_mutex_init(new, NULL);
    if (err != 0)
    {
        ARC_FREE(new);
        return NULL;
    }

    return (void *) new;
}

/*
**  ARCF_CRYPTO_DYN_DESTROY -- destroy a dynamic mutex
**
**  Parameters:
**  	mutex -- pointer to the mutex to destroy
**  	file -- file making the request
**  	line -- line making the request
**
**  Return value:
**  	None.
*/

static void
arcf_crypto_dyn_destroy(struct CRYPTO_dynlock_value *lock,
                        /* UNUSED */ const char     *file,
                        /* UNUSED */ int             line)
{
    assert(lock != NULL);

    pthread_mutex_destroy((pthread_mutex_t *) lock);

    ARC_FREE(lock);
}

/*
**  ARCF_CRYPTO_DYN_LOCK -- lock/unlock a dynamic mutex
**
**  Parameters:
**  	mode -- lock mode (request from libcrypto)
**  	mutex -- pointer to the mutex to lock/unlock
**  	file -- file making the request
**  	line -- line making the request
**
**  Return value:
**  	None.
*/

static void
arcf_crypto_dyn_lock(int                          mode,
                     struct CRYPTO_dynlock_value *lock,
                     /* UNUSED */ const char     *file,
                     /* UNUSED */ int             line)
{
    int status;

    assert(lock != NULL);

    if ((mode & CRYPTO_LOCK) != 0)
    {
        status = pthread_mutex_lock((pthread_mutex_t *) lock);
    }
    else
    {
        status = pthread_mutex_unlock((pthread_mutex_t *) lock);
    }

    assert(status == 0);
}

/*
**  ARCF_CRYPTO_INIT -- set up openssl dependencies
**
**  Parameters:
**  	None.
**
**  Return value:
**  	0 -- success
**  	!0 -- an error code (a la errno)
*/

int
arcf_crypto_init(void)
{
    int c;
    int n;
    int status;

    n = CRYPTO_num_locks();
    mutexes = ARC_CALLOC(n, sizeof(pthread_mutex_t));
    if (mutexes == NULL)
    {
        return errno;
    }

    for (c = 0; c < n; c++)
    {
        status = pthread_mutex_init(&mutexes[c], NULL);
        if (status != 0)
        {
            return status;
        }
    }

    status = pthread_mutex_init(&id_lock, NULL);
    if (status != 0)
    {
        return status;
    }

    nmutexes = n;

    status = pthread_key_create(&id_key, &arcf_crypto_free_id);
    if (status != 0)
    {
        return status;
    }

    SSL_load_error_strings();
    SSL_library_init();
    ERR_load_crypto_strings();

    CRYPTO_set_id_callback(&arcf_crypto_get_id);
    CRYPTO_set_locking_callback(&arcf_crypto_lock_callback);
    CRYPTO_set_dynlock_create_callback(&arcf_crypto_dyn_create);
    CRYPTO_set_dynlock_lock_callback(&arcf_crypto_dyn_lock);
    CRYPTO_set_dynlock_destroy_callback(&arcf_crypto_dyn_destroy);

    crypto_init_done = true;

    return 0;
}

/*
**  ARCF_CRYPTO_FREE -- tear down openssl dependencies
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
arcf_crypto_free(void)
{
    if (crypto_init_done)
    {
        CRYPTO_cleanup_all_ex_data();
        CONF_modules_free();
        EVP_cleanup();
        ERR_free_strings();
        ERR_remove_state(0);

        if (nmutexes > 0)
        {
            unsigned int c;

            for (c = 0; c < nmutexes; c++)
            {
                pthread_mutex_destroy(&mutexes[c]);
            }

            ARC_FREE(mutexes);
            mutexes = NULL;
            nmutexes = 0;
        }

        crypto_init_done = false;
    }
}

#endif /* OpenSSL < 1.1.0 */
