
#ifndef MCL_LANG_H_
#define MCL_LANG_H_

#include "lang/config.h"
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

/* macro expand. */
#define MCL_FIELD_MERGE(a, b) a##b
#define MCL_MACRO_EXPAND(...) __VA_ARGS__
#define MCL_MACRO_HELPER(__fn, ...) MCL_MACRO_EXPAND(__fn(__VA_ARGS__))


/* helper to get the number of the args. */
#define PP_NARG(...) PP__NARG_HELPER(PP__ARG_N, 0, __VA_ARGS__, PP__RSEQ_N)

#define PP__NARG_HELPER(__fn, ...) MCL_MACRO_EXPAND(__fn(__VA_ARGS__))

#define PP__ARG_N(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9,  \
				_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,    \
				_20,_21,_22,_23,_24,_25,_26,_27,_28,_29,    \
				_30,_31,_32,_33,_34,_35,_36,_37,_38,_39,    \
				_40,_41,_42,_43,_44,_45,_46,_47,_48,_49,    \
				_50,_51,_52,_53,_54,_55,_56,_57,_58,_59,    \
				_60,_61,_62,_63,_64, _N, ...) _N

#define PP__RSEQ_N	64, 63, 62, 61, 60, 59, 58, 57, 56, 55, \
					54, 53, 52, 51, 50, 49, 48, 47, 46, 45, \
					44, 43, 42, 41, 40, 39, 38, 37, 36, 35, \
					34, 33, 32, 31, 30, 29, 28, 27, 26, 25, \
					24, 23, 22, 21, 20, 19, 18, 17, 16, 15, \
					14, 13, 12, 11, 10, 9,  8,  7,  6,  5,  \
					4,  3,  2,  1,  0


/* max/min implemented by macros. */
#define MCL_MAX(...) MCL_MACRO_EXPAND(MCL__MAX_HELPER(MCL_FIELD_MERGE, MCL_MAX_IMPL, PP_NARG(__VA_ARGS__))(__VA_ARGS__))
#define MCL_MIN(...) MCL_MACRO_EXPAND(MCL__MIN_HELPER(MCL_FIELD_MERGE, MCL_MIN_IMPL, PP_NARG(__VA_ARGS__))(__VA_ARGS__))

#define MCL_MAX_IMPL0(_0)
#define MCL_MAX_IMPL1(_1)             (_1)
#define MCL_MAX_IMPL2(_1, _2)         ((_1) > (_2) ? (_1) : (_2))
#define MCL_MAX_IMPL3(_1, _2, _3)     MCL_MAX_IMPL2(MCL_MAX_IMPL2((_1), (_2)), (_3))
#define MCL_MAX_IMPL4(_1, _2, _3, _4) MCL_MAX_IMPL2(MCL_MAX_IMPL2((_1), (_2)), MCL_MAX_IMPL2((_3), (_4)))
#define MCL_MIN_IMPL0(_0)
#define MCL_MIN_IMPL1(_1)             (_1)
#define MCL_MIN_IMPL2(_1, _2)         ((_1) > (_2) ? (_2) : (_1))
#define MCL_MIN_IMPL3(_1, _2, _3)     MCL_MIN_IMPL2(MCL_MIN_IMPL2((_1), (_2)), (_3))
#define MCL_MIN_IMPL4(_1, _2, _3, _4) MCL_MIN_IMPL2(MCL_MIN_IMPL2((_1), (_2)), MCL_MIN_IMPL2((_3), (_4)))

#define MCL__MAX_HELPER(__fn, ...) MCL_MACRO_EXPAND(__fn(__VA_ARGS__))
#define MCL__MIN_HELPER(__fn, ...) MCL_MACRO_EXPAND(__fn(__VA_ARGS__))


/* ARRAY_SIZE. */
#ifndef ARRAY_SIZE
#ifdef __cplusplus
template<class T, int N> static inline int MCL__ARRAY_SIZE(T(&)[N]) { return N; }
#define ARRAY_SIZE MCL__ARRAY_SIZE
#else
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#endif


/* container_of. */
#ifndef container_of
#define container_of(ptr, type, field)                                        \
	((type *) ((char *) (ptr) - offsetof(type, field)))
#endif


/* STATIC_ASSERT. */
#ifndef STATIC_ASSERT
#define STATIC_ASSERT(expr)                                                   \
	void mcl__static_assert(int static_assert_failed[1 - 2 * !(expr)])
#endif


/* ssize_t. */
#if defined(_WIN32)
#if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
typedef intptr_t ssize_t;
# define _SSIZE_T_
# define _SSIZE_T_DEFINED
#endif
#endif


/* memzero. */
#ifndef memzero
#define memzero(_ptr, _len)                                                   \
	do { size_t i, len = (_len); char *ptr = (char *)(_ptr); for (i = 0; i < len; ++i) ptr[i] = 0; } while (0)
#endif



#ifdef __cplusplus
#include <utility>
#include <string.h>

MCL_BEGIN_NAMESPACE(mcl)

/** inheritance_cast. */
template<class ConcClass, class AbstClass>
static inline void inheritance_cast(ConcClass *&cp, AbstClass *ap) {
	AbstClass *tmp = reinterpret_cast<ConcClass *>(sizeof(ConcClass));
	cp = reinterpret_cast<ConcClass *>(
		reinterpret_cast<char *>(ap)
		- reinterpret_cast<char *>(tmp)
		+ reinterpret_cast<char *>(reinterpret_cast<ConcClass *>(sizeof(ConcClass))));
}

/** inheritance_cast. */
template<class ConcClass, class AbstClass>
static inline ConcClass *inheritance_cast(AbstClass *ap) {
	AbstClass *tmp = reinterpret_cast<ConcClass *>(sizeof(ConcClass));
	return reinterpret_cast<ConcClass *>(
		reinterpret_cast<char *>(ap)
		- reinterpret_cast<char *>(tmp)
		+ reinterpret_cast<char *>(reinterpret_cast<ConcClass *>(sizeof(ConcClass))));
}

/** null. */
class null_t {
public:
	template<class _Tp> inline operator _Tp *() const { return 0; }
	template<class _Cl, class _Tp> inline operator _Tp _Cl::*() const { return 0; }
private:
	void operator &() const;
};
static class null_t null;

MCL_END_NAMESPACE
#endif // __cplusplus
#endif // !MCL_LANG_H_
