
#include "utils.h"
#include "defs.h"
#include <memory.h>
#include <string.h>


/******************************** string ********************************/
size_t mcl_strnlen(const char *src, size_t max)
{
	const char *end = memchr(src, 0, max);
	return end ? (size_t)(end - src) : max;
}

char *mcl_strnlwr(char *dst, const char *src, size_t len)
{
	size_t i;

	for (i = 0; i < len && src[i]; ++i) {
		if (src[i] >= 'A' && src[i] <= 'Z')
			dst[i] = src[i] | 0x20;
		else
			dst[i] = src[i];
	}
	if (i < len)
		dst[i] = 0;

	return dst;
}

int mcl_strcasecmp(const char *s1, const char *s2)
{
#if defined(HAVE_STRCASECMP)
	return strcasecmp(s1, s2);
#elif defined(HAVE_STRICMP)
	return stricmp(s1, s2);
#else
	while (*s1 && *s2) {
		if (!(*s1 == *s2 || (IS_ALPHA(*s1) && IS_ALPHA(*s2) && LOWER(*s1) == LOWER(*s2))))
			break;
		++s1, ++s2;
	}
	return *s1 - *s2;
#endif
}


/******************************** fgets ********************************/
static size_t mcl__fgets_eof(void *buf, size_t size, size_t count, void *fp)
{
	return 0;
}
int mcl_sgets_init(mcl_fgets_t *ctx, const char *src, size_t len)
{
	ctx->fp = ctx;
	ctx->fread = mcl__fgets_eof;
	ctx->buf = (char *)src;
	ctx->buf_size = len;
	ctx->buf_len = len;
	ctx->buf_pos = 0;
	return 0;
}
int mcl_fgets_init(mcl_fgets_t *ctx, void *fp, mcl_fread_cb fread)
{
	ctx->fp = fp;
	ctx->fread = fread;
	ctx->buf = 0;
	ctx->buf_size = 0;
	ctx->buf_len = 0;
	ctx->buf_pos = 0;
	return 0;
}
int mcl_fgets_setbuf(mcl_fgets_t *ctx, char *buf, size_t buf_size)
{
	if (ctx->buf != NULL)
		return -1;

	ctx->buf = buf;
	ctx->buf_size = buf_size;

	return 0;
}
int mcl_fgets_feof(mcl_fgets_t *ctx)
{
	if (ctx->buf == NULL) {
		ctx->buf = ctx->inline_buf;
		ctx->buf_size = sizeof(ctx->inline_buf);
	}
	if (ctx->buf_pos == ctx->buf_len) {
		ctx->buf_pos = 0;
		ctx->buf_len = ctx->fread(ctx->buf, 1, ctx->buf_size, ctx->fp);
	}
	return ctx->buf_pos == ctx->buf_len;
}
int mcl_fgets_fgetc(mcl_fgets_t *ctx)
{
	if (mcl_fgets_feof(ctx))
		return -1;
	return ctx->buf[ctx->buf_pos++];
}
char *mcl_fgets(mcl_fgets_t *ctx, char *buf, size_t buf_size)
{
	size_t len;
	int ch, complated = 0;

	if (buf_size < 1)
		return NULL;
	if (mcl_fgets_feof(ctx))
		return NULL;

	len = 0;
	buf_size -= 1;

	while (!complated && len < buf_size) {
		if (mcl_fgets_feof(ctx))
			break;
		ch = mcl_fgets_fgetc(ctx);
		switch (ch) {
		case '\0':
			if (len > 0)
				complated = 1;
			break;
		case '\n':
			complated = 1;
		default:
			buf[len++] = (char)ch;
			break;
		}
	}
	buf[len] = 0;
	return buf;
}


/******************************** split_string ********************************/
int mcl_split_string(char *src, int sep, char **arr, int max)
{
	int n = 0;

	if (max < 1)
		return 0;

	arr[n++] = src;
	while (n < max) {
		src = strchr(src, sep);
		if (src == NULL)
			break;
		*src++ = 0;
		arr[n++] = src;
	}

	return n;
}
int mcl_split_string_seps(char *src, const char *seps, char **arr, int max)
{
	int n = 0;

	if (max < 1)
		return 0;

	arr[n++] = src;
	while (n < max && *src) {

		while (*src) {
			if (strchr(seps, *src)) {
				*src++ = 0;
				arr[n++] = src;
				break;
			}
			src += 1;
		}
	}

	return n;
}


/******************************** memmem ********************************/
const void *mcl_memmem_sunday(const void *src, size_t srclen, const void *dst, size_t dstlen)
{
	size_t table[256];
	size_t i;
	const uint8_t *pos;
	const uint8_t *end;
	const uint8_t *dstptr = (const uint8_t *)dst;
	assert(src && dst);

	if (dstlen > srclen) return 0;
	if (dstlen == 0) return src;
	if (dstlen == 1) return memchr(src, *(const uint8_t *)dst, srclen);

	// prepare.
	for (i = 0; i < 256; ++i)
		table[i] = dstlen + 1;
	for (i = 0; i < dstlen; ++i)
		table[dstptr[i]] = dstlen - i;

	pos = (const uint8_t *)src;
	end = (const uint8_t *)src + srclen - dstlen;

	// search.
	if (dstlen == 2) {
		for (; pos < end; pos += table[pos[dstlen]])
			if ((pos[0] == dstptr[0]) && (pos[1] == dstptr[1]))
				return pos;
		if (pos == end)
			if ((pos[0] == dstptr[0]) && (pos[1] == dstptr[1]))
				return pos;
	}
	else if (dstlen == 3) {
		for (; pos < end; pos += table[pos[dstlen]])
			if (memcmp(pos, dstptr, dstlen) == 0)
				return pos;
		if (pos == end)
			if (memcmp(pos, dstptr, dstlen) == 0)
				return pos;
	}
	else {
		for (; pos < end; pos += table[pos[dstlen]])
			if ((*(const uint32_t *)pos == *(const uint32_t *)dstptr) && (memcmp(pos, dstptr, dstlen) == 0))
				return pos;
		if (pos == end)
			if ((*(const uint32_t *)pos == *(const uint32_t *)dstptr) && (memcmp(pos, dstptr, dstlen) == 0))
				return pos;
	}

	return 0;
}

MCL_INLDECL const void *memrchr(const void *src, int val, size_t len)
{
	const char *end = (const char *)src;
	const char *pos = end + len;
	while (--pos >= end)
		if (*pos == val)
			return pos;
	return 0;
}

const void *mcl_memrmem_sunday(const void *src, size_t srclen, const void *dst, size_t dstlen)
{
	size_t table[256];
	size_t i;
	const uint8_t *pos;
	const uint8_t *end;
	const uint8_t *dstptr = (const uint8_t *)dst;
	assert(src && dst);

	if (dstlen > srclen) return 0;
	if (dstlen == 0) return (const uint8_t *)src + srclen;
	if (dstlen == 1) return memrchr(src, *(const uint8_t *)dst, srclen);

	// prepare.
	for (i = 0; i < 256; ++i)
		table[i] = dstlen;
	for (i = dstlen - 1; i > 0; --i)
		table[dstptr[i]] = i;

	pos = (const uint8_t *)src + srclen - dstlen;
	end = (const uint8_t *)src;

	// search.
	if (dstlen == 2) {
		for (; pos >= end; pos -= table[*pos])
			if (pos[0] == dstptr[0] && pos[1] == dstptr[1])
				return pos;
	}
	else if (dstlen == 3) {
		for (; pos >= end; pos -= table[*pos])
			if (memcmp(dstptr, pos, dstlen) == 0)
				return pos;
	}
	else {
		for (; pos >= end; pos -= table[*pos])
			if ((*(const uint32_t *)pos == *(const uint32_t *)dstptr) && memcmp(dstptr, pos, dstlen) == 0)
				return pos;
	}

	return 0;
}


/******************************** HEX±àÂë ********************************/
size_t mcl_hex_decode(const char *in, size_t len, unsigned char *out, size_t out_size)
{
	char ch;
	unsigned char bch;
	size_t i;
	size_t out_len = 0;

	for (i = 0; i < len && out_len < out_size; ++i) {
		if (in[i] == ' ' || in[i] == '\t' || in[i] == '\n' || in[i] == '\r')
			continue;

		ch = in[i];
		if (IS_NUM(ch))
			bch = (ch - '0') << 4;
		else if (IS_HEX(ch))
			bch = (LOWER(ch) - 'a' + 10) << 4;
		else
			break;

		ch = in[i + 1];
		if (IS_NUM(ch))
			bch |= ch - '0';
		else if (IS_HEX(ch))
			bch |= LOWER(ch) - 'a' + 10;
		else {
			out[out_len++] = bch;
			break;
		}

		i += 1;
		out[out_len++] = bch;
	}

	return out_len;
}
size_t mcl_hex_encode(const unsigned char *in, size_t len, char *out, size_t out_size)
{
	static const char hex_table[] = "0123456789abcdef";
	size_t i;
	size_t out_len = 0;

	if (out_size == 0)
		return 0;

	for (i = 0; i < len && out_len + 2 < out_size; ++i) {
		out[out_len++] = hex_table[in[i] >> 4];
		out[out_len++] = hex_table[in[i] & 0x0F];
	}

	out[out_len] = '\0';
	return out_len;
}


/******************************** BASE64±àÂë ********************************/
static const char BASE64TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/===";
static const int BASE64TABLE_DECODE[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,/* [\t\n\r] */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,/* [ ] */
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };

size_t mcl_base64_decode(const char *in, size_t len, unsigned char *out, size_t out_size)
{
	int k, v;
	unsigned int x;
	size_t i;
	size_t out_len = 0;

	k = 0;
	x = 0;
	for (i = 0; i < len; ++i) {
		v = BASE64TABLE_DECODE[(unsigned char)in[i]];
		if (v < 0) {
			if (v == -2)
				continue;
			break;
		}
		x = (x << 6) | (unsigned int)v;
		if (++k == 4) {
			if (out_len + 3 > out_size)
				break;
			out[out_len++] = (x >> 16) & 0xFF;
			out[out_len++] = (x >> 8) & 0xFF;
			out[out_len++] = x & 0xFF;
			k = 0;
			x = 0;
		}
	}

	if (out_size - out_len > 0) {
		if (k == 4) {
			if (out_size - out_len == 1)
				out[out_len++] = (x >> 16) & 0xFF;
			else if (out_size - out_len == 2) {
				out[out_len++] = (x >> 16) & 0xFF;
				out[out_len++] = (x >> 8) & 0xFF;
			}
			else {
				out[out_len++] = (x >> 16) & 0xFF;
				out[out_len++] = (x >> 8) & 0xFF;
				out[out_len++] = x & 0xFF;
			}
		}
		else if (k == 3) {
			if (out_size - out_len == 1)
				out[out_len++] = (x >> 10) & 0xFF;
			else {
				out[out_len++] = (x >> 10) & 0xFF;
				out[out_len++] = (x >> 2) & 0xFF;
			}
		}
		else if (k == 2) {
			*out++ = (x >> 4) & 0xFF;
		}
	}

	return out_len;
}
size_t mcl_base64_encode(const unsigned char *in, size_t len, char *out, size_t out_size)
{
	size_t i, n;
	size_t out_len = 0;

	if (out_size == 0)
		return 0;

	n = len / 3;
	for (i = 0; i < n && out_len + 4 < out_size; ++i, in += 3) {
		out[out_len++] = BASE64TABLE[((in[0] & 0xFC) >> 2)];
		out[out_len++] = BASE64TABLE[((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4)];
		out[out_len++] = BASE64TABLE[((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6)];
		out[out_len++] = BASE64TABLE[((in[2] & 0x3F) >> 0)];
	}
	if (out_len + 4 < out_size) {
		n = len % 3;
		if (n == 2) {
			out[out_len++] = BASE64TABLE[((in[0] & 0xFC) >> 2)];
			out[out_len++] = BASE64TABLE[((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4)];
			out[out_len++] = BASE64TABLE[((in[1] & 0x0F) << 2)];
			out[out_len++] = BASE64TABLE[64];
		}
		else if (n == 1) {
			out[out_len++] = BASE64TABLE[((in[0] & 0xFC) >> 2)];
			out[out_len++] = BASE64TABLE[((in[0] & 0x03) << 4)];
			out[out_len++] = BASE64TABLE[64];
			out[out_len++] = BASE64TABLE[64];
		}
	}

	out[out_len] = '\0';
	return out_len;
}


/******************************** URL±àÂë ********************************/
size_t mcl_urlencode(const char *in, size_t len, char *out, size_t out_size)
{
	size_t i;
	size_t out_len = 0;

	if (out_size == 0)
		return 0;

	for (i = 0; i < len && out_len + 1 < out_size; ++i) {
		if (in[i] == '\0')
			break;

		if (IS_ALPHANUM(in[i]) || IS_MARK(in[i]))
			out[out_len++] = in[i];
		else {
			if (out_len + 3 >= out_size)
				break;

			out[out_len++] = '%';
			out[out_len++] = DEC2HEX(in[i] >> 4);
			out[out_len++] = DEC2HEX(in[i] & 0x0F);
		}
	}

	out[out_len] = '\0';
	return out_len;
}
size_t mcl_urldecode(const char *in, size_t len, char *out, size_t out_size)
{
	size_t i;
	size_t out_len = 0;
	int value;

	if (out_size == 0)
		return 0;

	for (i = 0; i < len && out_len + 1 < out_size; ++i) {
		if (in[i] == '\0')
			break;

		if (in[i] != '%')
			out[out_len++] = in[i];
		else if (IS_HEX(in[i + 1]) && IS_HEX(in[i + 2])) {
			out[out_len++] = (HEX2DEC(in[i + 1]) << 4) | HEX2DEC(in[i + 2]);
			i += 2;
		}
		else if ((in[i + 1] == 'u' || in[i + 1] == 'U') &&
			IS_HEX(in[i + 2]) && IS_HEX(in[i + 3]) && IS_HEX(in[i + 4]) && IS_HEX(in[i + 5])) {
			value = (HEX2DEC(in[i + 2]) << 12) | (HEX2DEC(in[i + 3]) << 8) | (HEX2DEC(in[i + 4]) << 4) | HEX2DEC(in[i + 5]);
			if (value < 128) {
				out[out_len++] = value & 0x7F;
			}
			else if (value < 0x800) {
				if (out_len + 2 >= out_size)
					break;

				out[out_len++] = (0x6 << 5) | ((value >> 6) & 0x1f);
				out[out_len++] = (1 << 7) | (value & 0x3f);
			}
			else {
				if (out_len + 3 >= out_size)
					break;

				out[out_len++] = (0xE << 4) | ((value >> 12) & 0xf);
				out[out_len++] = (1 << 7) | ((value >> 6) & 0x3f);
				out[out_len++] = (1 << 7) | ((value) & 0x3f);
			}
			i += 5;
		}
	}

	out[out_len] = '\0';
	return out_len;
}
