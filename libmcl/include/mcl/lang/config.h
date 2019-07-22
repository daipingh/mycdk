
#ifndef MCL_LANG_CONFIG_H_
#define MCL_LANG_CONFIG_H_

/** compiler features. */
#if defined(_MSC_VER)
#  define MCL_NOINLINE_DOTDOTDOT
#  define MCL_NOINLINE __declspec(noinline)
#  define MCL_EXPORTS __declspec(dllexport)
#  define MCL_IMPORTS __declspec(dllimport)
#elif defined(__GNUC__)
#  define MCL_NOINLINE_DOTDOTDOT
#  define MCL_NOINLINE __attribute__((noinline))
#  define MCL_EXPORTS __attribute__((visibility("default")))
#  define MCL_IMPORTS __attribute__((visibility("default")))
#elif defined(__MINGW32__)
#  define MCL_NOINLINE_DOTDOTDOT
#  define MCL_NOINLINE __attribute__((noinline))
#  define MCL_EXPORTS __declspec(dllexport)
#  define MCL_IMPORTS __attribute__((visibility("default")))
#else
#  define MCL_NOINLINE_DOTDOTDOT ...
#  define MCL_NOINLINE
#  define MCL_EXPORTS
#  define MCL_IMPORTS
#endif

/** extern c. */
#ifdef __cplusplus
#  define MCL_EXTERN_C       extern "C"
#  define MCL_BEGIN_EXTERN_C extern "C" {
#  define MCL_END_EXTERN_C   }
#else
#  define MCL_EXTERN_C
#  define MCL_BEGIN_EXTERN_C
#  define MCL_END_EXTERN_C
#endif

/** api declare. */
#if defined(mcl_EXPORTS)
#  define MCL_APIDECL MCL_EXPORTS
#elif defined(mcl_IMPORTS)
#  define MCL_APIDECL MCL_IMPORTS
#else
#  define MCL_APIDECL
#endif

#ifdef __cplusplus
#  if __cplusplus >= 201100L || _MSC_VER >= 1800
#    define MCL_CXX11_RREF
#    define MCL_CXX11_VART
#  endif
#endif

#if defined(__STDC__)/** stdc. */
#  if defined(__STDC__VERSION__) && __STDC_VERSION__ >= 199901L/** C99. */
#    define MCL_STDC99_CSL
#    define __STDC99__ 199901L
#  elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199409L/** C89-fixed. */
#  else/** C89. */
#  endif
#elif defined(_MSC_VER)/** msvc. */
#  if _MSC_VER >= 1800
#    define MCL_STDC99_CSL
#  elif _MSC_VER >= 1300
#    define MCL_STDC99_CSL
#  else
#  endif
#    define MCL_MSVC_INL __inline
#endif

#if defined(__cplusplus)
#  define MCL_INLINE inline
#elif defined(__STDC99__)
#  define MCL_INLINE inline
#elif defined(_MSC_VER)
#  define MCL_INLINE __inline
#elif defined(__GNUC__)
#  define MCL_INLINE inline
#else
#  define MCL_INLINE
#endif
#define MCL_INLDECL static MCL_INLINE
#define MCL_APIDECL_INL MCL_APIDECL MCL_INLINE

/** register for constructor and destructor. */
#if defined(_MSC_VER)
#  if defined(__cplusplus)
#    define MCL_CTOR_SEGNAME ".CRT$XCU"
#  else
#    define MCL_CTOR_SEGNAME ".CRT$XIU"
#  endif
#  pragma section(MCL_CTOR_SEGNAME, read)
#  define MCL_CONSTRUCTOR_REGISTER(_token)                                                        \
	MCL_INLDECL void __mcl_ctor_##_token();                                                       \
	MCL_INLDECL int __cdecl __mcl_ctor_##_token##_vsfun() { __mcl_ctor_##_token(); return 0; }    \
	__declspec(allocate(MCL_CTOR_SEGNAME))                                                        \
		int(__cdecl *__mcl_ctor_##_token##_vsvar)() = __mcl_ctor_##_token##_vsfun;                \
	MCL_INLDECL void __mcl_ctor_##_token()
#  define MCL_DESTRUCTOR_REGISTER(_token)                                                         \
	MCL_INLDECL void __mcl_dtor_##_token(void);                                                   \
	MCL_INLDECL int __cdecl __mcl_dtor_##_token##_vsfun() { return atexit(__mcl_dtor_##_token); } \
	__declspec(allocate(MCL_CTOR_SEGNAME))                                                        \
		int(__cdecl *__mcl_dtor_##_token##_vsvar)() = __mcl_dtor_##_token##_vsfun;                \
	MCL_INLDECL void __mcl_dtor_##_token(void)
#else
#  define MCL_CONSTRUCTOR_REGISTER(_token)                                                        \
	__attribute((constructor)) MCL_INLDECL void __mcl_ctor_##_token()
#  define MCL_DESTRUCTOR_REGISTER(_token)                                                         \
	__attribute((destructor)) MCL_INLDECL void __mcl_dtor_##_token()
#  define MCL_DESTRUCTOR_REGISTER2(_token)                                                        \
	MCL_INLDECL void __mcl_dtor_##_token();                                                       \
	__attribute((constructor)) MCL_INLDECL                                                        \
		void __mcl_dtor_##_token##_helper() { atexit(__mcl_dtor_##_token); }                      \
	MCL_INLDECL void __mcl_dtor_##_token()
#endif


/** compiler options. */
#if defined(_WIN32) && !defined(_WIN32_WINNT)
#  define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif


/** namespaces. */
#ifdef __cplusplus
#  define MCL_BEGIN_NAMESPACE(...)  namespace __VA_ARGS__ {
#  define MCL_END_NAMESPACE         }
#  define USING_NAMESPACE_MCL       using namespace mcl;
#else
#  define MCL_BEGIN_NAMESPACE(...)
#  define MCL_END_NAMESPACE
#  define USING_NAMESPACE_MCL
#endif

#endif // !MCL_LANG_CONFIG_H_
