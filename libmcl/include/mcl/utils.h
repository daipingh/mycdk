
#ifndef MCL_UTILS_H_
#define MCL_UTILS_H_

#include "lang.h"


MCL_BEGIN_EXTERN_C

MCL_APIDECL size_t mcl_strnlen(const char *src, size_t max);
MCL_APIDECL char *mcl_strnlwr(char *dst, const char *src, size_t len);
MCL_APIDECL int mcl_strcasecmp(const char *s1, const char *s2);

MCL_APIDECL const void *mcl_memmem_sunday(const void *src, size_t srclen, const void *dst, size_t dstlen);
MCL_APIDECL const void *mcl_memrmem_sunday(const void *src, size_t srclen, const void *dst, size_t dstlen);

MCL_APIDECL size_t mcl_hex_decode(const char *in, size_t len, unsigned char *out);
MCL_APIDECL size_t mcl_hex_encode(const unsigned char *in, size_t len, char *out);
MCL_APIDECL size_t mcl_base64_decode(const char *in, size_t len, unsigned char *out);
MCL_APIDECL size_t mcl_base64_encode(const unsigned char *in, size_t len, char *out);

MCL_APIDECL size_t mcl_urlencode(const char *in, size_t len, char *out, size_t out_size);
MCL_APIDECL size_t mcl_urldecode(const char *in, size_t len, char *out, size_t out_size);


MCL_END_EXTERN_C
#endif
