
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


 /* Macros for character classes; depends on strict-mode  */
#define CR                  '\r'
#define LF                  '\n'
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_NUM(c)           ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_NUM(c))
#define IS_HEX(c)           (IS_NUM(c) || (LOWER(c) >= 'a' && LOWER(c) <= 'f'))
#define IS_MARK(c)          ((c) == '-' || (c) == '_' || (c) == '.' || \
  (c) == '!' || (c) == '~' || (c) == '*' || (c) == '\'' || (c) == '(' || \
  (c) == ')')
#define IS_USERINFO_CHAR(c) (IS_ALPHANUM(c) || IS_MARK(c) || (c) == '%' || \
  (c) == ';' || (c) == ':' || (c) == '&' || (c) == '=' || (c) == '+' || \
  (c) == '$' || (c) == ',')


#define IS_BASE64(c)        (IS_ALPHANUM(c) || (c) == '-' || (c) == '_' || (c) == '.' || (c) == '+'  || (c) == '/' || (c) == '=' || (c) == '*')
#define HEX2DEC(c)          (IS_NUM(c) ? ((c) - '0') : (LOWER(c) - 'a' + 10))
#define DEC2HEX(d)          (IS_NUM((d) + '0') ? ((d) + '0') : ((d) + 'A' - 10))



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
