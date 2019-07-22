
#include "utils.h"
#include <memory.h>
#include <string.h>


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
