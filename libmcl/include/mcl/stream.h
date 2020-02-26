
#ifndef MCL_STREAM_H_
#define MCL_STREAM_H_

#include "lang.h"
#include <uv.h>


MCL_BEGIN_EXTERN_C


typedef struct mcl_stream_s mcl_stream_t;

typedef void(*mcl_stream_close_cb)(mcl_stream_t *strm);
typedef void(*mcl_stream_alloc_cb)(mcl_stream_t *strm, size_t suggested_size, uv_buf_t *buf);
typedef void(*mcl_stream_read_cb)(mcl_stream_t *strm, ssize_t nread, const uv_buf_t *buf);
typedef void(*mcl_stream_write_cb)(void *arg, int status);

typedef void(*mcl_stream_close_fn)(mcl_stream_t *strm, mcl_stream_close_cb close_cb);
typedef int(*mcl_stream_read_start_fn)(mcl_stream_t *strm, mcl_stream_alloc_cb alloc_cb, mcl_stream_read_cb read_cb);
typedef int(*mcl_stream_read_stop_fn)(mcl_stream_t *strm);
typedef int(*mcl_stream_write_fn)(mcl_stream_t *strm, const uv_buf_t *bufs, unsigned int nbufs, void *arg, mcl_stream_write_cb write_cb);
typedef int(*mcl_stream_crack_fn)(mcl_stream_t *strm);
typedef int(*mcl_stream_get_prop_fn)(mcl_stream_t *strm, int name, void *val, int *len);
typedef int(*mcl_stream_set_prop_fn)(mcl_stream_t *strm, int name, const void *val, int len);


struct mcl_stream_s
{
	struct {
		mcl_stream_close_fn close;
		mcl_stream_read_start_fn read_start;
		mcl_stream_read_stop_fn read_stop;
		mcl_stream_write_fn write;
		mcl_stream_crack_fn crack;
		mcl_stream_get_prop_fn get_prop;
		mcl_stream_set_prop_fn set_prop;
	} vtbl;
	void *data;
};

enum MCL_STREAM_PROP
{
	MCL_STREAM_PROP_TIMEOUT,
	MCL_STREAM_PROP_TCPNODELAY,
	MCL_STREAM_PROP_PEERNAME,
	MCL_STREAM_PROP_SOCKNAME,
	MCL_STREAM_PROP_QUEUEWORK,
	MCL_STREAM_PROP_MAX
};

#define mcl_stream_close(strm, close_cb) \
	(strm)->vtbl.close((strm), (close_cb))

#define mcl_stream_read_start(strm, alloc_cb, read_cb) \
	((strm)->vtbl.read_start ? (strm)->vtbl.read_start((strm), (alloc_cb), (read_cb)) : -1)

#define mcl_stream_read_stop(strm) \
	((strm)->vtbl.read_stop ? (strm)->vtbl.read_stop((strm)) : -1)

#define mcl_stream_write(strm, bufs, nbufs, arg, write_cb) \
	((strm)->vtbl.write ? (strm)->vtbl.write((strm), (bufs), (nbufs), (arg), (write_cb)) : -1)

#define mcl_stream_crack(strm) \
	((strm)->vtbl.crack ? (strm)->vtbl.crack((strm)) : -1)

#define mcl_stream_get_prop(strm, name, val, len) \
	((strm)->vtbl.get_prop ? (strm)->vtbl.get_prop((strm), (name), (val), (len)) : -1)

#define mcl_stream_set_prop(strm, name, val, len) \
	((strm)->vtbl.set_prop ? (strm)->vtbl.set_prop((strm), (name), (val), (len)) : -1)


MCL_APIDECL mcl_stream_t *mcl_uvstream_wrap(uv_loop_t *loop, uv_stream_t *client, int *result);
MCL_APIDECL mcl_stream_t *mcl_uvstream_accept(uv_loop_t *loop, uv_stream_t *server, int *result, uv_stream_t **client);
MCL_APIDECL mcl_stream_t *mcl_sslstream_wrap(uv_loop_t *loop, mcl_stream_t *stream, int is_server, void *ssl_ctx, int *result, void **ssl);


MCL_END_EXTERN_C
#endif
