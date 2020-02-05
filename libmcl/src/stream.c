
#include "queue.h"
#include "mcl/stream.h"
#include <memory.h>


/* ASSERT() is for debug checks, CHECK() for run-time sanity checks.
 * DEBUG_CHECKS is for expensive debug checks that we only want to
 * enable in debug builds but still want type-checked by the compiler
 * in release builds.
 */
#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)    do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS  (0)
#else
# define ASSERT(exp)   assert(exp)
# define CHECK(exp)    assert(exp)
# define DEBUG_CHECKS  (1)
#endif

#define UNREACHABLE() CHECK(!"Unreachable code reached.")
#define UNREACHABLE_ASSERT() ASSERT(!"Unreachable code reached.")



struct mcl__memlist
{
	struct mcl__memlist *n;
};

static __inline void *mcl__memlist_get(void **memlist, size_t size)
{
	void *mem;
	struct mcl__memlist **_memlist = (struct mcl__memlist **)memlist;

	if (!_memlist || !*_memlist)
		mem = malloc(size);
	else {
		mem = *_memlist;
		*_memlist = (*_memlist)->n;
	}

	return mem;
}
static __inline void mcl__memlist_release(void **memlist, void *mem)
{
	struct mcl__memlist *_mem = (struct mcl__memlist *)mem;
	struct mcl__memlist **_memlist = (struct mcl__memlist **)memlist;

	if (!_memlist)
		free(mem);
	else {
		_mem->n = *_memlist;
		*_memlist = _mem;
	}
}


/****************************************************************/

typedef struct mcl_uvstream_s mcl_uvstream_t;
typedef struct mcl_uvstream_write_s mcl_uvstream_write_t;

struct mcl_uvstream_write_s
{
	mcl_uvstream_t *handle;
	mcl_stream_write_cb write_cb;
	void *arg;
	uv_write_t uvwrite;
};

struct mcl_uvstream_s
{
	mcl_stream_t stream_base;
	mcl_stream_close_cb close_cb;
	mcl_stream_read_cb read_cb;
	mcl_stream_alloc_cb alloc_cb;

	int reading;
	int cracked;
	int closing;
	unsigned int ref_count;
	uint64_t timeout;

	void *uvwritebufs;
	mcl_uvstream_write_t uvwritebufs2[4];

	uv_timer_t timer;
	uv_stream_t *uvstream;

	union {
		uv_stream_t stream;
		uv_tcp_t tcp;
		uv_pipe_t pipe;
	} client;
};


/****************************************************************/

static int mcl_uvstream_crack(mcl_stream_t *stream);


static void mcl_uvstream__ref(mcl_uvstream_t *handle)
{
	handle->ref_count += 1;
}
static void mcl_uvstream__unref(mcl_uvstream_t *handle)
{
	handle->ref_count -= 1;
	if (handle->ref_count == 0) {
		mcl_uvstream_write_t *req;
		CHECK(handle->closing);

		while (handle->uvwritebufs) {
			req = (mcl_uvstream_write_t *)mcl__memlist_get(&handle->uvwritebufs, sizeof(mcl_uvstream_write_t));
			if (!(req >= handle->uvwritebufs2 && req < handle->uvwritebufs2 + ARRAY_SIZE(handle->uvwritebufs2)))
				mcl__memlist_release(NULL, req);
		}
		if (handle->close_cb != NULL)
			handle->close_cb(&handle->stream_base);
		free(handle);
	}
}

static void mcl_uvstream__on_alloc(uv_handle_t *uvstream, size_t suggested_size, uv_buf_t *buf)
{
	mcl_uvstream_t *handle = (mcl_uvstream_t *)uvstream->data;
	if (handle->reading)
		handle->alloc_cb(&handle->stream_base, suggested_size, buf);
	else {
		buf->base = NULL;
		buf->len = 0;
		handle->cracked = 1;
	}
}
static void mcl_uvstream__on_read(uv_stream_t *uvstream, ssize_t nread, const uv_buf_t *buf)
{
	mcl_uvstream_t *handle = (mcl_uvstream_t *)uvstream->data;

	if (handle->reading) {
		if (nread > 0 && handle->timeout)
			uv_timer_again(&handle->timer);
		if (nread < 0) {
			handle->reading = 0;
			uv_timer_stop(&handle->timer);
		}
		handle->read_cb(&handle->stream_base, nread, buf);
	}
}
static void mcl_uvstream__on_write(uv_write_t *uvwrite, int status)
{
	mcl_uvstream_write_t *req = container_of(uvwrite, mcl_uvstream_write_t, uvwrite);
	mcl_uvstream_t *handle = req->handle;
	if (req->write_cb != NULL)
		req->write_cb(req->arg, status);
	mcl__memlist_release(&handle->uvwritebufs, req);
	mcl_uvstream__unref(handle);
}
static void mcl_uvstream__on_timeout(uv_timer_t *timer)
{
	uv_timer_stop(timer);
	mcl_uvstream_crack(&container_of(timer, mcl_uvstream_t, timer)->stream_base);
}

static void mcl_uvstream__on_timer_close(uv_handle_t *handle)
{
	mcl_uvstream__unref(container_of(handle, mcl_uvstream_t, timer));
}
static void mcl_uvstream__on_stream_close(uv_handle_t *handle)
{
	mcl_uvstream__unref(container_of(handle, mcl_uvstream_t, client.stream));
}

static void mcl_uvstream_close(mcl_stream_t *strm, mcl_stream_close_cb close_cb)
{
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);
	ASSERT(!handle->closing);

	handle->close_cb = close_cb;
	handle->closing = 1;

	if (handle->reading) {
		handle->reading = 0;
		uv_read_stop(handle->uvstream);
	}
	if (handle->uvstream == &handle->client.stream)
		uv_close((uv_handle_t *)handle->uvstream, mcl_uvstream__on_stream_close);

	uv_close((uv_handle_t *)&handle->timer, mcl_uvstream__on_timer_close);
}
static int mcl_uvstream_read_start(mcl_stream_t *strm, mcl_stream_alloc_cb alloc_cb, mcl_stream_read_cb read_cb)
{
	int err;
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);

	if (handle->cracked)
		return UV_EPIPE;
	if (handle->closing)
		return UV_EINVAL;

	err = uv_read_start(handle->uvstream, mcl_uvstream__on_alloc, mcl_uvstream__on_read);
	if (err == 0) {
		handle->uvstream->data = handle;
		handle->alloc_cb = alloc_cb;
		handle->read_cb = read_cb;
		handle->reading = 1;
		if (handle->timeout)
			uv_timer_start(&handle->timer, mcl_uvstream__on_timeout, handle->timeout, handle->timeout);
	}
	return err;
}
static int mcl_uvstream_read_stop(mcl_stream_t *strm)
{
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);

	if (handle->reading) {
		handle->reading = 0;
		uv_read_stop(handle->uvstream);
		uv_timer_stop(&handle->timer);
	}

	return 0;
}
static int mcl_uvstream_write(mcl_stream_t *strm, void *arg, const uv_buf_t *bufs, unsigned int nbufs, mcl_stream_write_cb write_cb)
{
	int err;
	mcl_uvstream_write_t *req;
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);

	req = (mcl_uvstream_write_t *)mcl__memlist_get(&handle->uvwritebufs, sizeof(mcl_uvstream_write_t));
	if (req == NULL)
		return UV_ENOMEM;

	req->handle = handle;
	req->write_cb = write_cb;
	req->arg = arg;
	err = uv_write(&req->uvwrite, handle->uvstream, bufs, nbufs, mcl_uvstream__on_write);
	if (err < 0) {
		mcl__memlist_release(&handle->uvwritebufs, req);
		return err;
	}

	mcl_uvstream__ref(handle);
	return 0;
}
static int mcl_uvstream_crack(mcl_stream_t *strm)
{
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);

	if (handle->cracked)
		return 0;

	if (handle->reading) {
		mcl_uvstream_read_stop(&handle->stream_base);
		handle->read_cb(&handle->stream_base, UV_EPIPE, NULL);
	}

	handle->cracked = 1;
	return 0;
}

static void get_prop__uint64(void *out, int *out_size, uint64_t val)
{
	if (out && out_size && *out_size > 0) {
		switch (*out_size)
		{
		case 1:
			*((uint8_t *)out) = (uint8_t)val;
			*out_size = 1;
			break;
		case 2:
		case 3:
			*((uint16_t *)out) = (uint16_t)val;
			*out_size = 2;
			break;
		case 4:
		case 5:
		case 6:
		case 7:
			*((uint32_t *)out) = (uint32_t)val;
			*out_size = 4;
			break;
		default:
			*((uint64_t *)out) = (uint64_t)val;
			*out_size = 8;
			break;
		}
	}
}
static void get_prop__int64(void *out, int *out_size, int64_t val)
{
	if (out && out_size && *out_size > 0) {
		switch (*out_size)
		{
		case 1:
			*((int8_t *)out) = (int8_t)val;
			*out_size = 1;
			break;
		case 2:
		case 3:
			*((int16_t *)out) = (int16_t)val;
			*out_size = 2;
			break;
		case 4:
		case 5:
		case 6:
		case 7:
			*((int32_t *)out) = (int32_t)val;
			*out_size = 4;
			break;
		default:
			*((int64_t *)out) = (int64_t)val;
			*out_size = 8;
			break;
		}
	}
}
static void set_prop__uint64(const void *in, int in_size, uint64_t *val)
{
	if (in && in_size > 0) {
		switch (in_size)
		{
		case 1:
			*val = *((const uint8_t *)in);
			break;
		case 2:
		case 3:
			*val = *((const uint16_t *)in);
			break;
		case 4:
		case 5:
		case 6:
		case 7:
			*val = *((const uint32_t *)in);
			break;
		default:
			*val = *((const uint64_t *)in);
			break;
		}
	}
}
static void set_prop__int64(const void *in, int in_size, int64_t *val)
{
	if (in && in_size > 0) {
		switch (in_size)
		{
		case 1:
			*val = *((const int8_t *)in);
			break;
		case 2:
		case 3:
			*val = *((const int16_t *)in);
			break;
		case 4:
		case 5:
		case 6:
		case 7:
			*val = *((const int32_t *)in);
			break;
		default:
			*val = *((const int64_t *)in);
			break;
		}
	}
}

static int mcl_uvstream_get_prop(mcl_stream_t *strm, int name, void *val, int *len)
{
	int tmplen;
	int intval;
	size_t sizeval;
	uv_os_fd_t fd;
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);

	switch (name)
	{
	case MCL_STREAM_PROP_TIMEOUT:
		get_prop__uint64(val, len, handle->timeout);
		return (int)handle->timeout;

	case MCL_STREAM_PROP_TCPNODELAY:
		if (handle->uvstream->type == UV_TCP) {
			intval = uv_fileno((uv_handle_t *)handle->uvstream, &fd);
			if (intval < 0)
				return intval;
			tmplen = sizeof(intval);
			intval = 0;
			if (getsockopt((uv_os_sock_t)fd, IPPROTO_TCP, TCP_NODELAY, (char *)&intval, &tmplen))
				return uv_translate_sys_error(errno);
			get_prop__int64(val, len, intval);
			return !!intval;
		}
		break;

	case MCL_STREAM_PROP_PEERNAME:
	case MCL_STREAM_PROP_SOCKNAME:
		if (handle->uvstream->type == UV_TCP) {
			if (name == MCL_STREAM_PROP_PEERNAME)
				intval = uv_tcp_getpeername((uv_tcp_t *)handle->uvstream, (struct sockaddr *)val, len);
			else
				intval = uv_tcp_getsockname((uv_tcp_t *)handle->uvstream, (struct sockaddr *)val, len);
			if (intval < 0)
				return intval;
			return 0;
		}
		else if (handle->uvstream->type == UV_NAMED_PIPE) {
			if (len == NULL) {
				if (name == MCL_STREAM_PROP_PEERNAME)
					intval = uv_pipe_getpeername((uv_pipe_t *)handle->uvstream, (char *)val, NULL);
				else
					intval = uv_pipe_getsockname((uv_pipe_t *)handle->uvstream, (char *)val, NULL);
				if (intval < 0)
					return intval;
			}
			else {
				sizeval = (size_t)*len;
				if (name == MCL_STREAM_PROP_PEERNAME)
					intval = uv_pipe_getpeername((uv_pipe_t *)handle->uvstream, (char *)val, &sizeval);
				else
					intval = uv_pipe_getsockname((uv_pipe_t *)handle->uvstream, (char *)val, &sizeval);
				if (intval < 0)
					return intval;
				*len = (int)sizeval;
			}
			return 0;
		}
		break;
	}
	return UV_EINVAL;
}
static int mcl_uvstream_set_prop(mcl_stream_t *strm, int name, const void *val, int len)
{
	int intval;
	int64_t i64val;
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);
	
	switch (name)
	{
	case MCL_STREAM_PROP_TIMEOUT:
		set_prop__uint64(val, len, &handle->timeout);
		if (handle->reading) {
			uv_timer_stop(&handle->timer);
			if (handle->timeout)
				uv_timer_start(&handle->timer, mcl_uvstream__on_timeout, handle->timeout, handle->timeout);
		}
		return (int)handle->timeout;

	case MCL_STREAM_PROP_TCPNODELAY:
		if (handle->uvstream->type == UV_TCP) {
			i64val = 1;
			set_prop__int64(val, len, &i64val);
			intval = uv_tcp_nodelay((uv_tcp_t *)handle->uvstream, !!i64val);
			if (intval < 0)
				return intval;
			return !!i64val;
		}
		break;
	}
	return UV_EINVAL;
}

mcl_stream_t *mcl_uvstream_wrap(uv_loop_t *loop, uv_stream_t *client, int *result)
{
	int i;
	mcl_uvstream_t *handle;

	handle = (mcl_uvstream_t *)malloc(sizeof(mcl_uvstream_t));
	if (handle == NULL) {
		if (result != NULL)
			*result = UV_ENOMEM;
		return NULL;
	}

	handle->stream_base.vtbl.close = mcl_uvstream_close;
	handle->stream_base.vtbl.write = mcl_uvstream_write;
	handle->stream_base.vtbl.read_start = mcl_uvstream_read_start;
	handle->stream_base.vtbl.read_stop = mcl_uvstream_read_stop;
	handle->stream_base.vtbl.crack = mcl_uvstream_crack;
	handle->stream_base.vtbl.get_prop = mcl_uvstream_get_prop;
	handle->stream_base.vtbl.set_prop = mcl_uvstream_set_prop;
	handle->stream_base.data = NULL;

	handle->close_cb = NULL;
	handle->read_cb = NULL;
	handle->alloc_cb = NULL;

	handle->reading = 0;
	handle->cracked = 0;
	handle->closing = 0;
	handle->timeout = 0;
	handle->ref_count = 1;

	handle->uvwritebufs = NULL;
	for (i = 0; i < ARRAY_SIZE(handle->uvwritebufs2); ++i)
		mcl__memlist_release(&handle->uvwritebufs, &handle->uvwritebufs2[i]);

	ASSERT(uv_timer_init(loop, &handle->timer));
	handle->uvstream = client;

	if (result != NULL)
		*result = 0;
	return &handle->stream_base;
}

mcl_stream_t *mcl_uvstream_accept(uv_loop_t *loop, uv_stream_t *server, int *result, uv_stream_t **client)
{
	int i, err;
	mcl_uvstream_t *handle;

	handle = (mcl_uvstream_t *)malloc(sizeof(mcl_uvstream_t));
	if (handle == NULL) {
		if (result != NULL)
			*result = UV_ENOMEM;
		return NULL;
	}

	handle->stream_base.vtbl.close = mcl_uvstream_close;
	handle->stream_base.vtbl.write = mcl_uvstream_write;
	handle->stream_base.vtbl.read_start = mcl_uvstream_read_start;
	handle->stream_base.vtbl.read_stop = mcl_uvstream_read_stop;
	handle->stream_base.vtbl.crack = mcl_uvstream_crack;
	handle->stream_base.vtbl.get_prop = mcl_uvstream_get_prop;
	handle->stream_base.vtbl.set_prop = mcl_uvstream_set_prop;
	handle->stream_base.data = NULL;

	handle->close_cb = NULL;
	handle->read_cb = NULL;
	handle->alloc_cb = NULL;

	handle->reading = 0;
	handle->cracked = 0;
	handle->closing = 0;
	handle->timeout = 0;
	handle->ref_count = 1;

	handle->uvwritebufs = NULL;
	for (i = 0; i < ARRAY_SIZE(handle->uvwritebufs2); ++i)
		mcl__memlist_release(&handle->uvwritebufs, &handle->uvwritebufs2[i]);

	CHECK(0 == uv_timer_init(loop, &handle->timer));
	handle->uvstream = NULL;
	if (server->type == UV_TCP) {
		CHECK(0 == uv_tcp_init(loop, &handle->client.tcp));
		handle->uvstream = &handle->client.stream;
		handle->ref_count += 1;
	}
	else if (server->type == UV_NAMED_PIPE) {
		if (((uv_pipe_t *)server)->ipc == 0) {
			CHECK(0 == uv_pipe_init(loop, &handle->client.pipe, 0));
			handle->uvstream = &handle->client.stream;
			handle->ref_count += 1;
		}
		else {
			if (uv_pipe_pending_count((uv_pipe_t *)server)) {
				if (uv_pipe_pending_type((uv_pipe_t *)server) == UV_TCP) {
					CHECK(0 == uv_tcp_init(loop, &handle->client.tcp));
					handle->uvstream = &handle->client.stream;
					handle->ref_count += 1;
				}
			}
		}
	}
	if (handle->uvstream == NULL)
		err = UV_EINVAL;
	else
		err = uv_accept(server, handle->uvstream);

	if (err < 0) {
		mcl_uvstream_close(&handle->stream_base, NULL);
		if (result != NULL)
			*result = err;
		return NULL;
	}

	if (client != NULL)
		*client = handle->uvstream;

	if (result != NULL)
		*result = 0;
	return &handle->stream_base;
}
