
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



void *mcl__memlist_get(void **memlist, size_t size);
void mcl__memlist_release(void **memlist, void *mem);


#endif
