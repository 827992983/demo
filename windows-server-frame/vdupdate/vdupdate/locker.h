#ifndef __LOCKER_H__
#define __LOCKER_H__

#ifdef WIN32
#include <windows.h>
#define LOCK_INIT(x) CreateMutex(NULL, FALSE, x)
#define LOCK(x) WaitForSingleObject(x, INFINITE)
#define UNLOCK(x) ReleaseMutex(x)
#define LOCK_DESTROY(x) CloseHandle(x)
#else
#include <pthread.h>
#define LOCK_INIT(x)    pthread_mutex_init (x, 0)
#define LOCK(x)         pthread_mutex_lock (x)
#define TRY_LOCK(x)     pthread_mutex_trylock (x)
#define UNLOCK(x)       pthread_mutex_unlock (x)
#define LOCK_DESTROY(x) pthread_mutex_destroy (x)
#endif

#endif
