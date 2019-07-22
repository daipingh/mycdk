
#ifndef MCL_DEFS_H_
#define MCL_DEFS_H_

#include <assert.h>
#include <stdlib.h>


/* ASSERT() is for debug checks, CHECK() for run-time sanity checks.
 * DEBUG_CHECKS is for expensive debug checks that we only want to
 * enable in debug builds but still want type-checked by the compiler
 * in release builds.
 */
#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)    do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS  (0)
#else
# define ASSERT(exp)   assert(exp)
# define CHECK(exp)    assert(exp)
# define DEBUG_CHECKS  (1)
#endif

#define UNREACHABLE() CHECK(!"Unreachable code reached.")
#define UNREACHABLE_ASSERT() ASSERT(!"Unreachable code reached.")


#define MCL_HANDLE_CLOSING          0x00000100
#define MCL_HANDLE_CLOSED           0x00000200
#define MCL_HANDLE_ACTIVE           0x00000400
#define MCL_HANDLE_ENDGAME_QUEUED   0x00001000


#define MCL_STREAM_WRITING          0x01000000
#define MCL_STREAM_WRITEABLE        0x02000000

#define MCL_WORKER_WAITING          0x01000000
#define MCL_WORKER_THREAD_REF       0x01000000
#define MCL_WORKER_THREAD_UNREF     0x02000000

#endif
