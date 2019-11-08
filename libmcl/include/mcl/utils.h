
#ifndef MCL_UTILS_H_
#define MCL_UTILS_H_

#include "lang.h"


MCL_BEGIN_EXTERN_C

typedef struct mcl_fgets_s mcl_fgets_t;
typedef size_t(*mcl_fread_cb)(void *buf, size_t size, size_t count, void *fp);

struct mcl_fgets_s
{
	void *fp;
	mcl_fread_cb fread;

	char *buf;
	size_t buf_size;

	size_t buf_pos;
	size_t buf_len;

	char inline_buf[8];
};

MCL_APIDECL int mcl_sgets_init(mcl_fgets_t *ctx, const char *src, size_t len);
MCL_APIDECL int mcl_fgets_init(mcl_fgets_t *ctx, void *fp, mcl_fread_cb fread);
MCL_APIDECL int mcl_fgets_setbuf(mcl_fgets_t *ctx, char *buf, size_t buf_size);
MCL_APIDECL int mcl_fgets_feof(mcl_fgets_t *ctx);
MCL_APIDECL int mcl_fgets_fgetc(mcl_fgets_t *ctx);
MCL_APIDECL char *mcl_fgets(mcl_fgets_t *ctx, char *buf, size_t buf_size);

MCL_APIDECL int mcl_split_string(char *src, int sep, char **arr, int max);
MCL_APIDECL int mcl_split_string_seps(char *src, const char *seps, char **arr, int max);

MCL_APIDECL size_t mcl_strnlen(const char *src, size_t max);
MCL_APIDECL char *mcl_strnlwr(char *dst, const char *src, size_t len);
MCL_APIDECL int mcl_strcasecmp(const char *s1, const char *s2);

MCL_APIDECL const void *mcl_memmem_sunday(const void *src, size_t srclen, const void *dst, size_t dstlen);
MCL_APIDECL const void *mcl_memrmem_sunday(const void *src, size_t srclen, const void *dst, size_t dstlen);

MCL_APIDECL size_t mcl_hex_decode(const char *in, size_t len, unsigned char *out, size_t out_size);
MCL_APIDECL size_t mcl_hex_encode(const unsigned char *in, size_t len, char *out, size_t out_size);
MCL_APIDECL size_t mcl_base64_decode(const char *in, size_t len, unsigned char *out, size_t out_size);
MCL_APIDECL size_t mcl_base64_encode(const unsigned char *in, size_t len, char *out, size_t out_size);

MCL_APIDECL size_t mcl_urlencode(const char *in, size_t len, char *out, size_t out_size);
MCL_APIDECL size_t mcl_urldecode(const char *in, size_t len, char *out, size_t out_size);


MCL_END_EXTERN_C
#endif
