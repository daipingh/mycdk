
#include "utils.h"
#include "defs.h"
#include <memory.h>
#include <string.h>


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
size_t mcl_hex_decode(const char *in, size_t len, unsigned char *out)
{
	char ch;
	unsigned char bch;
	size_t n = 0;

	while (len > 0) {
		ch = in[0];
		if (IS_NUM(ch))
			bch = (ch - '0') << 4;
		else if (IS_HEX(ch))
			bch = (LOWER(ch) - 'a' + 10) << 4;
		else
			break;

		ch = in[1];
		if (IS_NUM(ch))
			bch |= ch - '0';
		else if (IS_HEX(ch))
			bch |= LOWER(ch) - 'a' + 10;
		else {
			out[n++] = bch;
			break;
		}

		out[n++] = bch;
		in += 2;
		len -= 2;
	}

	return n;
}
size_t mcl_hex_encode(const unsigned char *in, size_t len, char *out)
{
	static const char hex_table[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; ++i) {
		out[0] = hex_table[(in[i] & 0xF0) >> 4];
		out[1] = hex_table[(in[i] & 0x0F)];
		out += 2;
	}
	*out = '\0';
	return len * 2;
}


/******************************** BASE64±àÂë ********************************/
static const char BASE64TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/===";
static const char BASE64TABLE_DECODE[256] = {
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

size_t mcl_base64_decode(const char *in, size_t len, unsigned char *out)
{
	int k, v;
	unsigned int x;
	const unsigned char *in2 = (const unsigned char *)in;
	const unsigned char *end = (const unsigned char *)in + len;
	unsigned char *o = out;

	k = 0;
	x = 0;
	for (; in2 < end; ++in2) {
		v = BASE64TABLE_DECODE[*in2];
		if (v < 0) {
			if (v == -2)
				continue;
			break;
		}
		x = (x << 6) | (unsigned int)v;
		if (++k == 4) {
			*out++ = (x >> 16) & 0xFF;
			*out++ = (x >> 8) & 0xFF;
			*out++ = x & 0xFF;
			k = 0;
			x = 0;
		}
	}
	if (k == 3) {
		*out++ = (x >> 10) & 0xFF;
		*out++ = (x >> 2) & 0xFF;
	}
	else if (k == 2) {
		*out++ = (x >> 4) & 0xFF;
	}

	return out - o;
}
size_t mcl_base64_encode(const unsigned char *in, size_t len, char *out)
{
	size_t count;

	for (count = len / 3; count > 0; --count, out += 4, in += 3) {
		out[0] = BASE64TABLE[((in[0] & 0xFC) >> 2)];
		out[1] = BASE64TABLE[((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4)];
		out[2] = BASE64TABLE[((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6)];
		out[3] = BASE64TABLE[((in[2] & 0x3F) >> 0)];
	}
	switch (len % 3) {
	case 2:
		out[0] = BASE64TABLE[((in[0] & 0xFC) >> 2)];
		out[1] = BASE64TABLE[((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4)];
		out[2] = BASE64TABLE[((in[1] & 0x0F) << 2)];
		out[3] = BASE64TABLE[64];
		out[4] = '\0';
		break;
	case 1:
		out[0] = BASE64TABLE[((in[0] & 0xFC) >> 2)];
		out[1] = BASE64TABLE[((in[0] & 0x03) << 4)];
		out[2] = BASE64TABLE[64];
		out[3] = BASE64TABLE[64];
		out[4] = '\0';
		break;
	default:
		out[0] = '\0';
		break;
	}
	return (len + 2) / 3 * 4;
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
