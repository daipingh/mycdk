
#ifndef MCL_STREAM_H_
#define MCL_STREAM_H_

#include "lang.h"
#include <uv.h>


MCL_BEGIN_EXTERN_C

#define MCL_STREAM_WRITE_T_SIZE                   256

typedef struct mcl_stream_s mcl_stream_t;
typedef struct mcl_stream_vtbl_s mcl_stream_vtbl_t;
typedef struct mcl_stream_write_s mcl_stream_write_t;

typedef void(*mcl_stream_close_cb)(mcl_stream_t *handle);
typedef void(*mcl_stream_alloc_cb)(mcl_stream_t *handle, size_t suggested_size, uv_buf_t *buf);
typedef void(*mcl_stream_read_cb)(mcl_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
typedef void(*mcl_stream_write_cb)(mcl_stream_write_t *req, int status);

typedef void(*mcl_stream_close_fn)(mcl_stream_t *handle, mcl_stream_close_cb close_cb);
typedef int(*mcl_stream_read_start_fn)(mcl_stream_t *handle, mcl_stream_alloc_cb alloc_cb, mcl_stream_read_cb read_cb);
typedef int(*mcl_stream_read_stop_fn)(mcl_stream_t *handle);
typedef int(*mcl_stream_write_fn)(mcl_stream_t *handle, mcl_stream_write_t *req, const uv_buf_t *bufs, unsigned int nbufs, mcl_stream_write_cb write_cb);


struct mcl_stream_vtbl_s
{
	mcl_stream_close_fn close;
	mcl_stream_write_fn write;
	mcl_stream_read_start_fn read_start;
	mcl_stream_read_stop_fn read_stop;
};

struct mcl_stream_s
{
	const mcl_stream_vtbl_t *vtbl;
	void *data;
	void *extension_data;
};

typedef struct {
	mcl_stream_t *handle;
	mcl_stream_write_cb write_cb;
	void *data;
} mcl__stream_write_t;

struct mcl_stream_write_s
{
	mcl_stream_t *handle;
	mcl_stream_write_cb write_cb;
	void *data;
	union {
		char extension_data[MCL_STREAM_WRITE_T_SIZE - sizeof(mcl__stream_write_t)];
	};
};

static __inline void mcl_stream_close(mcl_stream_t *handle, mcl_stream_close_cb close_cb)
{
	handle->vtbl->close(handle, close_cb);
}
static __inline int mcl_stream_read_start(mcl_stream_t *handle, mcl_stream_alloc_cb alloc_cb, mcl_stream_read_cb read_cb)
{
	return handle->vtbl->read_start(handle, alloc_cb, read_cb);
}
static __inline int mcl_stream_read_stop(mcl_stream_t *handle)
{
	return handle->vtbl->read_stop(handle);
}
static __inline int mcl_stream_write(mcl_stream_t *handle, mcl_stream_write_t *req, const uv_buf_t *bufs, unsigned int nbufs, mcl_stream_write_cb write_cb)
{
	return handle->vtbl->write(handle, req, bufs, nbufs, write_cb);
}


typedef struct {
	mcl_stream_t *handle;
	mcl_stream_write_cb write_cb;
	void *data;
	union {
		uv_write_t uvwrite;
		char extension_data[MCL_STREAM_WRITE_T_SIZE - sizeof(mcl__stream_write_t)];
	};
} mcl_stream_uvwrite_t;
STATIC_ASSERT(sizeof(mcl_stream_uvwrite_t) == MCL_STREAM_WRITE_T_SIZE);


MCL_END_EXTERN_C
#endif
