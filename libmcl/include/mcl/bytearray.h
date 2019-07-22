
#ifndef MCL_BYTEARRAY_H_
#define MCL_BYTEARRAY_H_

#include "lang.h"
#include "utils.h"
#include <memory.h>		// memcpy
#include <malloc.h>		// malloc
#include <string.h>		// strlen


typedef struct mcl_bytearray_s mcl_bytearray_t;

struct mcl_bytearray_s {
	uint8_t *head; /*!< 数据指针 */
	size_t cap;    /*!< 数组容量 */
	size_t len;    /*!< 数据长度 */
	size_t pos;    /*!< 当前位置 */
	size_t selpos; /*!< 选中长度 */
	size_t selcnt; /*!< 选中长度 */
};

#define MCL_BYTEARRAY_INITIALIZER(_h, _c, _l) { (_h), (_c), (_l), 0, 0, 0 }


MCL_INLDECL void mcl_bytearray_init(mcl_bytearray_t *_this, void *head, size_t cap, size_t len)
{
	_this->head = (uint8_t *)head;
	_this->cap = cap;
	_this->len = len;
	_this->pos = 0;
	_this->selcnt = 0;
	_this->selpos = 0;
}

MCL_INLDECL void mcl_bytearray_del(mcl_bytearray_t *_this)
{
	free(_this);
}

MCL_INLDECL mcl_bytearray_t *mcl_bytearray_new(size_t cap)
{
	mcl_bytearray_t *_this = (mcl_bytearray_t *)malloc(sizeof(mcl_bytearray_t) + cap);
	if (_this != NULL)
		mcl_bytearray_init(_this, (uint8_t *)&_this[1], cap, 0);
	return _this;
}

MCL_INLDECL size_t mcl_bytearray_copy(const mcl_bytearray_t *_this, uint8_t *dest, size_t maxlen)
{
	if (_this->pos >= _this->len)
		return 0;
	if (maxlen > _this->len - _this->pos)
		maxlen = _this->len - _this->pos;
	memcpy(dest, _this->head + _this->pos, maxlen);
	return maxlen;
}

MCL_INLDECL size_t mcl_bytearray_read(mcl_bytearray_t *_this, uint8_t *dest, size_t maxlen)
{
	if (_this->pos >= _this->len)
		return 0;
	if (maxlen > _this->len - _this->pos)
		maxlen = _this->len - _this->pos;
	memcpy(dest, _this->head + _this->pos, maxlen);
	_this->pos += maxlen;
	return maxlen;
}

MCL_INLDECL size_t mcl_bytearray_append(mcl_bytearray_t *_this, const void *src, size_t srclen)
{
	if (srclen > _this->cap - _this->len)
		return 0;
	memcpy(_this->head + _this->len, src, srclen);
	_this->len += srclen;
	return srclen;
}
MCL_INLDECL size_t mcl_bytearray_strapp(mcl_bytearray_t *_this, const void *src, size_t srclen)
{
	if (srclen >= _this->cap - _this->len)
		return 0;
	memcpy(_this->head + _this->len, src, srclen);
	_this->len += srclen;
	_this->head[_this->len] = 0;
	return srclen;
}
MCL_INLDECL size_t mcl_bytearray_strcat(mcl_bytearray_t *_this, const void *src)
{
	return mcl_bytearray_strapp(_this, src, strlen((const char *)src));
}
MCL_INLDECL size_t mcl_bytearray_strncat(mcl_bytearray_t *_this, const void *src, size_t maxlen)
{
	return mcl_bytearray_strapp(_this, src, mcl_strnlen((const char *)src, maxlen));
}

#define mcl_bytearray_printf(_this, fmt, ...) \
	mcl_bytearray_printf_helper(_this, snprintf((char *)(_this)->head + (_this)->len, (_this)->cap - (_this)->len, fmt, ##__VA_ARGS__))

#define mcl_bytearray_vprintf(_this, fmt, arglist) \
	mcl_bytearray_printf_helper(_this, vsnprintf((char *)(_this)->head + (_this)->len, (_this)->cap - (_this)->len, fmt, arglist))

#define mcl_bytearray_wprintf(_this, fmt, ...) \
	mcl_bytearray_printf_helper(_this, swprintf((char *)(_this)->head + (_this)->len, (_this)->cap - (_this)->len, fmt, ##__VA_ARGS__))

#define mcl_bytearray_vwprintf(_this, fmt, arglist) \
	mcl_bytearray_printf_helper(_this, vsnprintf((char *)(_this)->head + (_this)->len, (_this)->cap - (_this)->len, fmt, arglist))

MCL_INLDECL int mcl_bytearray_printf_helper(mcl_bytearray_t *_this, int p_ret)
{
	if (p_ret > 0 && (size_t)p_ret < _this->cap - _this->len)
		_this->len += p_ret;
	else {
		if (_this->cap > _this->len)
			_this->head[_this->len] = 0;
		p_ret = 0;
	}
	return p_ret;
}

MCL_INLDECL int mcl_bytearray_replace(mcl_bytearray_t *_this, const void *src, size_t srclen)
{
	size_t selend;
	if (_this->selpos > _this->cap)
		return 0;

	selend = _this->selpos + _this->selcnt;
	if (selend > _this->len) {
		if (_this->selpos + srclen > _this->cap)
			return 0;
		_this->len = _this->selpos + srclen;
	}
	else {
		if (_this->len - _this->selcnt + srclen > _this->cap)
			return 0;
		if (_this->selcnt != srclen && _this->len > selend)
			memmove(_this->head + _this->selpos + srclen, _this->head + selend, _this->len - selend);
		_this->len = _this->len - _this->selcnt + srclen;
	}
	memcpy(_this->head + _this->selpos, src, srclen);
	_this->selpos += srclen;
	_this->selcnt = 0;

	return 1;
}

MCL_INLDECL int mcl_bytearray_find(mcl_bytearray_t *_this, const void *dst, size_t dstlen)
{
	const void *result = NULL;
	if (_this->pos + dstlen <= _this->len)
		result = mcl_memmem_sunday(_this->head + _this->pos, _this->len - _this->pos, dst, dstlen);
	if (result == NULL) {
		_this->selcnt = 0;
		_this->selpos = (size_t)-1;
		return 0;
	}
	else {
		_this->selcnt = dstlen;
		_this->selpos = (const uint8_t *)result - (const uint8_t *)_this->head;
		return 1;
	}
}


#ifdef __cplusplus
#include "utils.h"
#ifdef MCL_STDC99_CSL
#include <wchar.h>
#endif

MCL_BEGIN_NAMESPACE(mcl)

class BasicByteArray
{
protected:
	void cap(int c) { c_imp.cap = c; }
	void len(int l) { c_imp.len = l; }
	void pos(int p) { c_imp.pos = p; }
	void sel(int s) { c_imp.sel = s; }
	void head(uint8_t *h) { c_imp.head = h; }

	void swap_space(BasicByteArray &right) {
		std::swap(c_imp.cap, right.c_imp.cap);
		std::swap(c_imp.head, right.c_imp.head);
	}
public:
	virtual ~BasicByteArray() {}
	BasicByteArray(uint8_t *head, int cap, int len) {
		mcl_bytearray_init(&c_imp, head, cap, len);
	}
	uint8_t *head() { return c_imp.head; }
	uint8_t *tail() { return &c_imp.head[c_imp.len]; }
	const uint8_t *head() const { return c_imp.head; }
	const uint8_t *tail() const { return &c_imp.head[c_imp.len]; }

	int len() const { return c_imp.len; }
	int cap() const { return c_imp.cap; }
	int rlen() const { return c_imp.len - c_imp.pos; }
	int rcap() const { return c_imp.cap - c_imp.len; }

	int pos() const { return c_imp.pos; }
	int sel() const { return c_imp.sel; }
	int selc() const { return mcl_bytearray_selc(&c_imp); }

	int skip(int len) { return c_imp.pos += len; }
	int seek(int pos) { return mcl_bytearray_seek(&c_imp, pos); }

	int find(const void *dst, int len) { return mcl_bytearray_find(&c_imp, dst, len); }
	int read(uint8_t *dst, int max) { return mcl_bytearray_read(&c_imp, (uint8_t *)dst, max); }
	int copy(uint8_t *dst, int max) const { return mcl_bytearray_copy(&c_imp, (uint8_t *)dst, max); }
	int append(const mcl_bytearray_t &obj) { return append(obj.head, obj.len); }
	int append(const mcl_bytearray_t *obj) { return append(obj->head, obj->len); }
	int append(const void *src, int len) {
		return reserve(this->len() + len) ? mcl_bytearray_append(&c_imp, src, len) : 0;
	}
	int strend() { return append("", 1); }
	int strcat(const char *src) { return strapp(src); }
	int strapp(const char *src) { return strapp(src, (int)::strlen(src)); }
	int strncat(const char *src, int maxlen) { return strapp(src, mcl_strnlen(src, maxlen)); }
	int strapp(const void *src, int len) {
		return reserve(this->len() + len + 1) ? mcl_bytearray_strapp(&c_imp, src, len) : 0;
	}
	int replace(const void *src, int len) {
		return reserve(this->len() - selc() + len) ? mcl_bytearray_replace(&c_imp, src, len) : 0;
	}

	virtual bool reserve(int len) { return len <= c_imp.cap; }

	void swap(BasicByteArray &right) { std::swap(c_imp, right.c_imp); }
	BasicByteArray &clear() { len(0); sel(0); pos(0); return *this; }

	const BasicByteArray sub() const {
		return BasicByteArray((uint8_t *)head() + pos(), selc(), selc());
	}
	const BasicByteArray sub(int pos) const {
		int sublen = len() - pos;
		return BasicByteArray((uint8_t *)head() + pos, sublen, sublen);
	}
	const BasicByteArray sub(int pos, int len) const {
		int sublen = MCL_MIN(this->len() - pos, len);
		return BasicByteArray((uint8_t *)head() + pos, sublen, sublen);
	}

#ifdef MCL_CXX11_VART
		template<class... _Tp> int printf(const char *fmt, _Tp... args) {
			int retval;
			do {
				retval = mcl_bytearray_printf(&c_imp, fmt, args...);
			} while (!retval && reserve(cap() + (cap() + 1) / 2));
			return retval;
		}
#	ifdef MCL_STDC99_CSL
		template<class... _Tp> int printf(const wchar_t *fmt, _Tp... args) {
			int retval;
			do {
				retval = mcl_bytearray_wprintf(&c_imp, fmt, args...);
			} while (!retval && reserve(cap() + (cap() + 1) / 2));
			return retval;
		}
#	endif
#else
	int printf(const char *fmt, ...) {
		int retval;
		va_list ap;
		do {
			va_start(ap, fmt);
			retval = mcl_bytearray_vprintf(&c_imp, fmt, ap);
			va_end(ap);
		} while (!retval && reserve(cap() + (cap() + 1) / 2));
		return retval;
	}
#	ifdef MCL_STDC99_CSL
	int printf(const wchar_t *fmt, ...) {
		int retval;
		va_list ap;
		do {
			va_start(ap, fmt);
			retval = mcl_bytearray_vwprintf(&c_imp, fmt, ap);
			va_end(ap);
		} while (!retval && reserve(cap() + (cap() + 1) / 2));
		return retval;
	}
#	endif
#endif

	operator mcl_bytearray_t *() { return &c_imp; }
	operator const mcl_bytearray_t *() const { return &c_imp; }

	BasicByteArray &operator=(const BasicByteArray &obj) {
		clear().append(obj); return *this;
	}
	BasicByteArray &operator=(const mcl_bytearray_t &obj) {
		clear().append(obj); return *this;
	}
	BasicByteArray &operator=(const null_t &val) {
		clear(); return *this;
	}

private:
	mcl_bytearray_t c_imp;
};

class ByteArray : public BasicByteArray
{
	typedef BasicByteArray _Super;
public:
	virtual ~ByteArray() {
		if (head()) delete[] head();
	}
#ifdef MCL_CXX11_RREF
	ByteArray(ByteArray &&obj) : _Super(obj.head(), obj.cap(), obj.len()) { obj.head(0); }
#endif
	explicit ByteArray(int cap = 1024)
		: _Super(new uint8_t[cap], cap, 0) { }
	ByteArray(const uint8_t *bytes, int len)
		: _Super(new uint8_t[len], len, 0) { append(bytes, len); }
	ByteArray(const mcl_bytearray_t &obj)
		: _Super(new uint8_t[obj.len], obj.len, 0) { append(obj); }
	ByteArray(const BasicByteArray &obj)
		: _Super(new uint8_t[obj.len()], obj.len(), 0) { append(obj); }
	ByteArray(const ByteArray &obj)
		: _Super(new uint8_t[obj.len()], obj.len(), 0) { append(obj); }

	virtual bool reserve(int _cap) {
		if (_cap > cap()) {
			ByteArray newTmp(_cap);
			newTmp.append(head(), len());
			swap_space(newTmp);
		}
		return true;
	}

	ByteArray &operator=(const mcl_bytearray_t &obj) {
		clear().append(obj); return *this;
	}
	ByteArray &operator=(const BasicByteArray &obj) {
		clear().append(obj); return *this;
	}
	ByteArray &operator=(const ByteArray &obj) {
		clear().append(obj); return *this;
	}
	ByteArray &operator=(const null_t &val) {
		len(0); sel(0); pos(0); return *this;
	}
#ifdef MCL_CXX11_RREF
	ByteArray &operator=(ByteArray &&obj) {
		obj.pos(0);
		obj.pos(0);
		swap(obj);
		return *this;
	}
#endif
};


#ifdef MCL_CXX11_RREF
//ByteArray operator+(ByteArray &&l, const BasicByteArray &r) { l.append(r); return l; }
#endif
ByteArray operator+(const BasicByteArray &r, const BasicByteArray &l)
{
	ByteArray t(l.len() + r.len());
	t.append(l); t.append(r);
	return t;
}


MCL_END_NAMESPACE
#endif // __cplusplus
#endif
