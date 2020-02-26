
#include "stream.h"
#include "defs.h"
#include "queue.h"
#include <memory.h>


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

	void *writereqs;
	mcl_uvstream_write_t writereqs2[4];

	uv_timer_t timer;
	uv_stream_t *uvstream;

	union {
		uv_stream_t stream;
		uv_tcp_t tcp;
		uv_pipe_t pipe;
	} client;
};


static void mcl_uvstream__on_timer_close(uv_handle_t *_handle)
{
	mcl_uvstream_t *handle = container_of(_handle, mcl_uvstream_t, timer);
	handle->ref_count -= 1;
	if (handle->ref_count == 0) {
		if (handle->close_cb != NULL)
			handle->close_cb(&handle->stream_base);
		free(handle);
	}
}
static void mcl_uvstream__on_stream_close(uv_handle_t *_handle)
{
	mcl_uvstream_t *handle = container_of(_handle, mcl_uvstream_t, client.stream);
	handle->ref_count -= 1;
	if (handle->ref_count == 0) {
		if (handle->close_cb != NULL)
			handle->close_cb(&handle->stream_base);
		free(handle);
	}
}

static void mcl_uvstream__ref(mcl_uvstream_t *handle)
{
	handle->ref_count += 1;
}
static void mcl_uvstream__unref(mcl_uvstream_t *handle)
{
	mcl_uvstream_write_t *req;
	handle->ref_count -= 1;

	if (handle->ref_count == 0) {
		CHECK(handle->closing);

		while (handle->writereqs) {
			req = (mcl_uvstream_write_t *)mcl__memlist_get(&handle->writereqs, sizeof(mcl_uvstream_write_t));
			if (!(req >= handle->writereqs2 && req < handle->writereqs2 + ARRAY_SIZE(handle->writereqs2)))
				mcl__memlist_release(NULL, req);
		}

		if (handle->uvstream == &handle->client.stream) {
			handle->ref_count += 1;
			uv_close((uv_handle_t *)handle->uvstream, mcl_uvstream__on_stream_close);
		}

		handle->ref_count += 1;
		uv_close((uv_handle_t *)&handle->timer, mcl_uvstream__on_timer_close);
	}
}

static void mcl_uvstream__on_alloc(uv_handle_t *uvstream, size_t suggested_size, uv_buf_t *buf)
{
	mcl_uvstream_t *handle = (mcl_uvstream_t *)uvstream->data;
	ASSERT(handle->reading);
	handle->alloc_cb(&handle->stream_base, suggested_size, buf);
}
static void mcl_uvstream__on_read(uv_stream_t *uvstream, ssize_t nread, const uv_buf_t *buf)
{
	mcl_uvstream_t *handle = (mcl_uvstream_t *)uvstream->data;
	ASSERT(handle->reading);
	if (nread > 0 && handle->timeout)
		uv_timer_again(&handle->timer);
	if (nread < 0) {
		handle->reading = 0;
		uv_timer_stop(&handle->timer);
	}
	handle->read_cb(&handle->stream_base, nread, buf);
}
static void mcl_uvstream__on_write(uv_write_t *uvwrite, int status)
{
	mcl_uvstream_write_t *req = container_of(uvwrite, mcl_uvstream_write_t, uvwrite);
	mcl_uvstream_t *handle = req->handle;
	if (req->write_cb != NULL)
		req->write_cb(req->arg, status);
	mcl__memlist_release(&handle->writereqs, req);
	mcl_uvstream__unref(handle);
}
static void mcl_uvstream__on_timeout(uv_timer_t *timer)
{
	mcl_uvstream_t *handle = container_of(timer, mcl_uvstream_t, timer);
	uv_timer_stop(timer);
	if (handle->reading) {
		handle->reading = 0;
		uv_read_stop(handle->uvstream);
		handle->read_cb(&handle->stream_base, UV_EPIPE, NULL);
	}
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

	mcl_uvstream__unref(handle);
}
static int mcl_uvstream_read_start(mcl_stream_t *strm, mcl_stream_alloc_cb alloc_cb, mcl_stream_read_cb read_cb)
{
	int err;
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);

	if (handle->closing)
		return UV_EINVAL;
	if (handle->cracked)
		return UV_EPIPE;

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
static int mcl_uvstream_write(mcl_stream_t *strm, const uv_buf_t *bufs, unsigned int nbufs, void *arg, mcl_stream_write_cb write_cb)
{
	int err;
	mcl_uvstream_write_t *req;
	mcl_uvstream_t *handle = container_of(strm, mcl_uvstream_t, stream_base);

	req = (mcl_uvstream_write_t *)mcl__memlist_get(&handle->writereqs, sizeof(mcl_uvstream_write_t));
	if (req == NULL)
		return UV_ENOMEM;

	req->handle = handle;
	req->write_cb = write_cb;
	req->arg = arg;
	err = uv_write(&req->uvwrite, handle->uvstream, bufs, nbufs, mcl_uvstream__on_write);
	if (err < 0) {
		mcl__memlist_release(&handle->writereqs, req);
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
	handle->cracked = 1;

	if (handle->reading) {
		uv_timer_stop(&handle->timer);
		uv_timer_start(&handle->timer, mcl_uvstream__on_timeout, 0, 0);
	}
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
		if (handle->reading && !handle->cracked) {
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

	handle->writereqs = NULL;
	for (i = 0; i < ARRAY_SIZE(handle->writereqs2); ++i)
		mcl__memlist_release(&handle->writereqs, &handle->writereqs2[i]);

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

	handle->writereqs = NULL;
	for (i = 0; i < ARRAY_SIZE(handle->writereqs2); ++i)
		mcl__memlist_release(&handle->writereqs, &handle->writereqs2[i]);

	CHECK(0 == uv_timer_init(loop, &handle->timer));
	handle->uvstream = NULL;
	if (server->type == UV_TCP) {
		CHECK(0 == uv_tcp_init(loop, &handle->client.tcp));
		handle->uvstream = &handle->client.stream;
	}
	else if (server->type == UV_NAMED_PIPE) {
		if (((uv_pipe_t *)server)->ipc == 0) {
			CHECK(0 == uv_pipe_init(loop, &handle->client.pipe, 0));
			handle->uvstream = &handle->client.stream;
		}
		else {
			if (uv_pipe_pending_count((uv_pipe_t *)server)) {
				if (uv_pipe_pending_type((uv_pipe_t *)server) == UV_TCP) {
					CHECK(0 == uv_tcp_init(loop, &handle->client.tcp));
					handle->uvstream = &handle->client.stream;
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



/****************************************************************/

#include <openssl/ssl.h>

typedef struct mcl_sslstream_s mcl_sslstream_t;
typedef struct mcl_sslstream_buf_s mcl_sslstream_buf_t;
typedef struct mcl_sslstream_req_s mcl_sslstream_req_t;
typedef struct mcl_sslstream_on_read_s mcl_sslstream_on_read_t;
typedef struct mcl_sslstream_write_s mcl_sslstream_write_t;
typedef struct mcl_sslstream_close_s mcl_sslstream_close_t;

enum
{
	mcl_sslstream_req_on_read,
	mcl_sslstream_req_write,
	mcl_sslstream_req_close,
};

struct mcl_sslstream_buf_s
{
	QUEUE queue;
	unsigned int size;
	unsigned int len;
};
struct mcl_sslstream_req_s
{
	QUEUE queue;
	int   type;
};
struct mcl_sslstream_on_read_s
{
	QUEUE queue;
	int   type;

	int result;
	int nread;
	int offset;
	QUEUE bufs;
	int inited;
	int shutdown;
	mcl_sslstream_write_t *writereq;
};
struct mcl_sslstream_write_s
{
	QUEUE queue;
	int   type;

	int result;
	mcl_sslstream_t *handle;
	mcl_stream_write_cb write_cb;
	void *arg;
	uv_buf_t static_bufs[4];
	uv_buf_t *bufs;
	unsigned int nbufs;
	unsigned int nbiobufs;
};
struct mcl_sslstream_close_s
{
	QUEUE queue;
	int   type;

	int result;
	mcl_sslstream_write_t *writereq;
};

struct mcl_sslstream_s
{
	mcl_stream_t stream_base;
	mcl_stream_close_cb close_cb;
	mcl_stream_read_cb read_cb;
	mcl_stream_alloc_cb alloc_cb;

	int reading;
	int cracked;
	int closing;
	unsigned int ref_count;
	int readerr;
	int writerr;
	int inited;
	int shutdown;
	int w_enable;
	int w_padding;
	int s_reading;
	int s_writing;
	unsigned int buf_size;
	unsigned int buf_size_default;

	int ssl_closing;
	int ssl_closed;

	uv_work_t work;
	mcl_sslstream_close_t closereq;
	void *writereqs;
	mcl_sslstream_write_t writereqs2[8];
	void *readreqs;
	mcl_sslstream_on_read_t readreqs2[4];

	void *read_queue[2];
	void *write_queue[2];
	void *wait_reqs[2];
	void *queue_reqs[2];
	void *padding_reqs[2];

	uv_async_t async;
	uv_idle_t idle;
	mcl_stream_t *uvstream;

	SSL *ssl;
	BIO *read_bio;
	BIO *write_bio;
};

static int mcl_sslstream__s_read_start(mcl_sslstream_t *handle);
static void mcl_sslstream__s_read_stop(mcl_sslstream_t *handle);
static void mcl_sslstream__s_write(mcl_sslstream_t *handle, mcl_sslstream_write_t *req);
static void mcl_sslstream__queue_work(mcl_sslstream_t *handle, mcl_sslstream_req_t *req);

#define mcl_sslstream__set_readerr(handle, err) \
	do { if ((err) < 0 && (handle)->readerr == 0) { mcl_sslstream__s_read_stop((handle)); (handle)->readerr = (err); } } while (0)
#define mcl_sslstream__set_writerr(handle, err) \
	do { if ((err) < 0 && (handle)->writerr == 0) { mcl_sslstream__set_readerr((handle), (err)); (handle)->writerr = (err); } } while (0)


static mcl_sslstream_buf_t *mcl_sslstream_buf_create(size_t size)
{
	mcl_sslstream_buf_t *buf = (mcl_sslstream_buf_t *)malloc(sizeof(mcl_sslstream_buf_t) + size);
	if (buf != NULL) {
		//QUEUE_INIT(&buf->queue);
		buf->size = (unsigned int)size;
		buf->len = 0;
	}
	return buf;
}
static void mcl_sslstream_buf_destroy(mcl_sslstream_buf_t *buf)
{
	free(buf);
}
static void *mcl_sslstream_buf_to_ptr(mcl_sslstream_buf_t *buf)
{
	return buf ? &buf[1] : NULL;
}
static mcl_sslstream_buf_t *mcl_sslstream_buf_from_ptr(void *ptr)
{
	return ptr ? (mcl_sslstream_buf_t *)((char *)ptr - sizeof(mcl_sslstream_buf_t)) : NULL;
}

static mcl_sslstream_write_t *mcl_sslstream_write__new(mcl_sslstream_t *handle)
{
	mcl_sslstream_write_t *req = (mcl_sslstream_write_t *)mcl__memlist_get(&handle->writereqs, sizeof(mcl_sslstream_write_t));
	if (req != NULL) {
		req->type = mcl_sslstream_req_write;
		req->result = 0;
		req->handle = handle;
		req->write_cb = NULL;
		req->arg = NULL;
		req->bufs = req->static_bufs;
		req->nbufs = 0;
		req->nbiobufs = 0;
	}
	return req;
}
static void mcl_sslstream_write__delete(mcl_sslstream_t *handle, mcl_sslstream_write_t *req)
{
	unsigned int i;
	unsigned int all = req->nbufs + req->nbiobufs;
	for (i = req->nbufs; i < all; ++i) {
		if (req->bufs[i].base != NULL)
			free(req->bufs[i].base);
	}
	if (req->bufs != req->static_bufs)
		free(req->bufs);
	mcl__memlist_release(&handle->writereqs, req);
}
static mcl_sslstream_on_read_t *mcl_sslstream_on_read__new(mcl_sslstream_t *handle)
{
	mcl_sslstream_on_read_t *req = (mcl_sslstream_on_read_t *)mcl__memlist_get(&handle->readreqs, sizeof(mcl_sslstream_on_read_t));
	if (req != NULL) {
		req->type = mcl_sslstream_req_on_read;
		req->result = 0;
		req->nread = 0;
		req->offset = 0;
		QUEUE_INIT(&req->bufs);
		req->inited = 0;
		req->shutdown = 0;
		req->writereq = NULL;
	}
	return req;
}
static void mcl_sslstream_on_read__delete(mcl_sslstream_t *handle, mcl_sslstream_on_read_t *req)
{
	QUEUE *ite;
	mcl_sslstream_buf_t *bufinfo;

	if (req->writereq != NULL)
		mcl_sslstream_write__delete(handle, req->writereq);
	while (!QUEUE_EMPTY(&req->bufs)) {
		ite = QUEUE_HEAD(&req->bufs);
		bufinfo = QUEUE_DATA(ite, mcl_sslstream_buf_t, queue);
		QUEUE_REMOVE(ite);
		mcl_sslstream_buf_destroy(bufinfo);
	}
	mcl__memlist_release(&handle->readreqs, req);
}


static void mcl_sslstream__on_idle_close(uv_handle_t *_handle)
{
	mcl_sslstream_t *handle = container_of(_handle, mcl_sslstream_t, idle);
	handle->ref_count -= 1;
	if (handle->ref_count == 0) {
		if (handle->close_cb != NULL)
			handle->close_cb(&handle->stream_base);
		free(handle);
	}
}
static void mcl_sslstream__on_async_close(uv_handle_t *_handle)
{
	mcl_sslstream_t *handle = container_of(_handle, mcl_sslstream_t, async);
	handle->ref_count -= 1;
	if (handle->ref_count == 0) {
		if (handle->close_cb != NULL)
			handle->close_cb(&handle->stream_base);
		free(handle);
	}
}

static void mcl_sslstream__ref(mcl_sslstream_t *handle)
{
	handle->ref_count += 1;
}
static void mcl_sslstream__unref(mcl_sslstream_t *handle)
{
	mcl_sslstream_on_read_t *readreq;
	mcl_sslstream_write_t *writereq;
	handle->ref_count -= 1;

	if (handle->ref_count == 0) {
		CHECK(handle->closing);
		ASSERT(QUEUE_EMPTY(&handle->read_queue));
		ASSERT(QUEUE_EMPTY(&handle->write_queue));
		ASSERT(QUEUE_EMPTY(&handle->wait_reqs));
		ASSERT(QUEUE_EMPTY(&handle->queue_reqs));
		ASSERT(QUEUE_EMPTY(&handle->padding_reqs));

		while (handle->readreqs) {
			readreq = (mcl_sslstream_on_read_t *)mcl__memlist_get(&handle->readreqs, sizeof(mcl_sslstream_on_read_t));
			if (!(readreq >= handle->readreqs2 && readreq < handle->readreqs2 + ARRAY_SIZE(handle->readreqs2)))
				mcl__memlist_release(NULL, readreq);
		}
		while (handle->writereqs) {
			writereq = (mcl_sslstream_write_t *)mcl__memlist_get(&handle->writereqs, sizeof(mcl_sslstream_write_t));
			if (!(writereq >= handle->writereqs2 && writereq < handle->writereqs2 + ARRAY_SIZE(handle->writereqs2)))
				mcl__memlist_release(NULL, writereq);
		}

		SSL_free(handle->ssl); handle->ssl = NULL;
		/*BIO_free(conn->read_bio);  */handle->read_bio = NULL;
		/*BIO_free(conn->write_bio); */handle->write_bio = NULL;

		handle->ref_count = 2;
		uv_close((uv_handle_t *)&handle->idle, mcl_sslstream__on_idle_close);
		uv_close((uv_handle_t *)&handle->async, mcl_sslstream__on_async_close);
	}
}

static int mcl_sslstream__read_bio(mcl_sslstream_t *handle, mcl_sslstream_write_t **pp)
{
	void *new_ptr;
	unsigned int all;
	mcl_sslstream_write_t *req = *pp;
	int r = BIO_get_mem_data(handle->write_bio, NULL);

	if (r < 0)
		return UV_UNKNOWN;

	if (r > 0) {
		if (req == NULL) {
			req = mcl_sslstream_write__new(handle);
			if (req == NULL)
				return UV_ENOMEM;
			*pp = req;
		}
		all = req->nbufs + req->nbiobufs;

		if (req->bufs == req->static_bufs) {
			ASSERT(all <= ARRAY_SIZE(req->static_bufs));
			if (all == ARRAY_SIZE(req->static_bufs)) {
				req->bufs = (uv_buf_t *)malloc(sizeof(uv_buf_t) * (all + 1));
				if (req->bufs == NULL) {
					req->bufs = req->static_bufs;
					return UV_ENOMEM;
				}
				memcpy(req->bufs, req->static_bufs, sizeof(uv_buf_t) * all);
			}
		}
		else {
			new_ptr = realloc(req->bufs, sizeof(uv_buf_t) * (all + 1));
			if (new_ptr == NULL)
				return UV_ENOMEM;

			req->bufs = (uv_buf_t *)new_ptr;
		}

		req->bufs[all].base = (char *)malloc((size_t)r);
		if (req->bufs[all].base == NULL)
			return UV_ENOMEM;

		r = BIO_read(handle->write_bio, req->bufs[all].base, (int)r);
		if (r < 0)
			return UV_UNKNOWN;

		req->bufs[all].len = (unsigned int)r;
		req->nbiobufs += 1;
	}

	return 0;
}

static void mcl_sslstream__on_read__work(mcl_sslstream_t *handle, mcl_sslstream_req_t *_req)
{
	char shutdown_buf[256];
	mcl_sslstream_buf_t *bufinfo;
	int ret, err;
	mcl_sslstream_on_read_t *req = (mcl_sslstream_on_read_t *)_req;

	// 判断ssl是否正常.
	if (handle->ssl_closed) {
		req->result = UV_EPIPE;
		return;
	}

	// 判断数据接收是否正常.
	if (req->nread < 0) {
		BIO_set_mem_eof_return(handle->read_bio, -1);

		if (handle->ssl_closing) {
			SSL_shutdown(handle->ssl);
			mcl_sslstream__read_bio(handle, &req->writereq);
			handle->ssl_closed = 1;
		}
		else {
			if (!SSL_is_init_finished(handle->ssl))
				SSL_do_handshake(handle->ssl);
			else
				SSL_read(handle->ssl, shutdown_buf, sizeof(shutdown_buf));
			handle->ssl_closed = 1;
		}
		return;
	}

	// 将数据写入BIO供ssl读取.
	bufinfo = QUEUE_DATA(QUEUE_HEAD(&req->bufs), mcl_sslstream_buf_t, queue);
	ASSERT(&bufinfo->queue != &req->bufs && QUEUE_NEXT(&bufinfo->queue) == &req->bufs);

	ret = BIO_write(handle->read_bio, mcl_sslstream_buf_to_ptr(bufinfo), (int)bufinfo->len);
	if (ret != (int)bufinfo->len) {
		bufinfo->len = 0;
		req->result = UV_ENOMEM;
		return;
	}
	bufinfo->len = 0;
	req->nread = 0;
	req->offset = 0;

	// 判断是否走ssl断开流程.
	if (handle->ssl_closing) {
		ret = SSL_shutdown(handle->ssl);
		if (ret != 1) {
			if (ret == 0)
				err = SSL_ERROR_WANT_READ;
			else
				err = SSL_get_error(handle->ssl, ret);

			if (err == SSL_ERROR_WANT_READ) {
				err = mcl_sslstream__read_bio(handle, &req->writereq);
				if (err < 0) {
					handle->ssl_closed = 1;
					req->result = err;
				}
			}
			else {
				handle->ssl_closed = 1;
				req->result = UV_EPIPE;
				//printf("SSL_shutdown: SSL_get_error %d\n", err);
			}
		}
		else {
			err = mcl_sslstream__read_bio(handle, &req->writereq);
			if (err < 0) {
				handle->ssl_closed = 1;
				req->result = err;
			}
			else {
				handle->ssl_closed = 1;
				req->shutdown = 2;
			}
		}
		return;
	}

	// 判断是否走ssl初始化流程.
	if (!SSL_is_init_finished(handle->ssl)) {
		ret = SSL_do_handshake(handle->ssl);
		if (ret != 1) {
			err = SSL_get_error(handle->ssl, ret);
			if (err == SSL_ERROR_WANT_READ) {
				err = mcl_sslstream__read_bio(handle, &req->writereq);
				if (err < 0) {
					handle->ssl_closed = 1;
					req->result = err;
				}
			}
			else {
				handle->ssl_closed = 1;
				req->result = UV_EPIPE;
				//printf("SSL_do_handshake: SSL_get_error %d\n", err);
			}
			return;
		}

		req->inited = 1;
	}

	// 调用SSL_read获取解密的数据，放入队列并通过回调传递给应用.
	ret = SSL_read(handle->ssl, (char *)mcl_sslstream_buf_to_ptr(bufinfo) + bufinfo->len, (int)(bufinfo->size - bufinfo->len));
	while (ret > 0) {
		req->nread += ret;
		bufinfo->len += (unsigned int)ret;

		if (bufinfo->len == bufinfo->size) {
			bufinfo = mcl_sslstream_buf_create(bufinfo->size);
			if (bufinfo == NULL) {
				err = mcl_sslstream__read_bio(handle, &req->writereq);
				if (err < 0) {
					handle->ssl_closed = 1;
					req->result = err;
				}
				return;
			}
			QUEUE_INSERT_TAIL(&req->bufs, &bufinfo->queue);
		}
		ret = SSL_read(handle->ssl, (char *)mcl_sslstream_buf_to_ptr(bufinfo) + bufinfo->len, (int)(bufinfo->size - bufinfo->len));
	}

	err = SSL_get_error(handle->ssl, ret);
	if (err == SSL_ERROR_ZERO_RETURN) {
		req->shutdown = 1;
		err = mcl_sslstream__read_bio(handle, &req->writereq);
		if (err < 0) {
			handle->ssl_closed = 1;
			req->result = err;
		}
	}
	else if (err == SSL_ERROR_WANT_READ || bufinfo->len > 0) {
		// 多线程环境下，SSL_get_error取得的错误好像不准确；
		// 这里如果有收到数据，则直接忽略错误.
		err = mcl_sslstream__read_bio(handle, &req->writereq);
		if (err < 0) {
			handle->ssl_closed = 1;
			req->result = err;
		}
	}
	else {
		handle->ssl_closed = 1;
		req->result = UV_EPIPE;
	}
}
static void mcl_sslstream__on_read__done(mcl_sslstream_t *handle, mcl_sslstream_req_t *_req, int status)
{
	QUEUE *ite;
	int err;
	mcl_sslstream_on_read_t *req = (mcl_sslstream_on_read_t *)_req;

	// 待写数据.
	if (req->writereq != NULL) {
		mcl_sslstream__s_write(handle, req->writereq);
		req->writereq = NULL;
	}

	// 错误处理.
	if (status < 0 || req->result < 0 || req->nread < 0) {
		if (status < 0)
			err = status;
		else if (req->result < 0)
			err = req->result;
		else if (req->nread < 0)
			err = req->nread;
		else
			err = UV_UNKNOWN;

		mcl_sslstream__set_readerr(handle, err);
		mcl_sslstream_on_read__delete(handle, req);
		return;
	}

	// 连接初始化标识.
	if (req->inited) {
		mcl_sslstream_req_t *writereq;
		handle->inited = 1;
		while (!QUEUE_EMPTY(&handle->wait_reqs)) {
			ite = QUEUE_HEAD(&handle->wait_reqs);
			writereq = QUEUE_DATA(ite, mcl_sslstream_req_t, queue);
			QUEUE_REMOVE(ite);
			mcl_sslstream__queue_work(handle, writereq);
		}
	}
	// 连接断开标识.
	if (req->shutdown == 1)
		handle->shutdown = 1;
	else if (req->shutdown == 2) {
		ASSERT(handle->closing);
		mcl_sslstream__set_readerr(handle, UV_EOF);
	}

	// 如果有数据，则放到队列.
	if (req->nread > 0)
		QUEUE_INSERT_TAIL(&handle->read_queue, &req->queue);
	else
		mcl_sslstream_on_read__delete(handle, req);
}
static void mcl_sslstream_write__work(mcl_sslstream_t *handle, mcl_sslstream_req_t *_req)
{
	unsigned int i;
	int ret, err;
	uv_buf_t buf;
	mcl_sslstream_write_t *req = (mcl_sslstream_write_t *)_req;

	// 判断ssl是否正常.
	if (handle->ssl_closed) {
		req->result = UV_EPIPE;
		return;
	}

	for (i = 0; i < req->nbufs; ++i) {
		if (req->bufs[i].len == 0)
			continue;
		buf = req->bufs[i];

	write_again:
		ret = SSL_write(handle->ssl, buf.base, (int)buf.len);
		if (ret > 0) {
			CHECK(ret == (int)buf.len);
			continue;
		}

		err = SSL_get_error(handle->ssl, ret);
		if (err == SSL_ERROR_WANT_WRITE) {
			err = mcl_sslstream__read_bio(handle, &req);
			if (err < 0) {
				handle->ssl_closed = 1;
				req->result = err;
				return;
			}
			goto write_again;
		}
		else {
			handle->ssl_closed = 1;
			req->result = UV_UNKNOWN;
			//printf("SSL_write: SSL_get_error %d\n", err);
			return;
		}
	}

	err = mcl_sslstream__read_bio(handle, &req);
	if (err < 0) {
		handle->ssl_closed = 1;
		req->result = err;
		return;
	}
}
static void mcl_sslstream_write__done(mcl_sslstream_t *handle, mcl_sslstream_req_t *_req, int status)
{
	mcl_sslstream_write_t *req = (mcl_sslstream_write_t *)_req;

	if (status < 0) {
		mcl_sslstream__set_writerr(handle, status);
		req->result = status;
	}

	mcl_sslstream__s_write(handle, req);
}
static void mcl_sslstream_close__work(mcl_sslstream_t *handle, mcl_sslstream_req_t *_req)
{
	int ret, err;
	mcl_sslstream_close_t *req = (mcl_sslstream_close_t *)_req;

	// 判断ssl是否正常.
	if (handle->ssl_closed) {
		req->result = UV_EPIPE;
		return;
	}

	ASSERT(!handle->ssl_closing);
	handle->ssl_closing = 1;
	ret = SSL_shutdown(handle->ssl);
	if (ret != 1) {
		if (ret == 0)
			err = SSL_ERROR_WANT_READ;
		else
			err = SSL_get_error(handle->ssl, ret);

		if (err == SSL_ERROR_WANT_READ) {
			err = mcl_sslstream__read_bio(handle, &req->writereq);
			if (err < 0) {
				handle->ssl_closed = 1;
				req->result = err;
			}
		}
		else {
			handle->ssl_closed = 1;
			req->result = UV_EPIPE;
			//printf("SSL_shutdown: SSL_get_error %d\n", err);
		}
	}
	else {
		err = mcl_sslstream__read_bio(handle, &req->writereq);
		if (err < 0) {
			handle->ssl_closed = 1;
			req->result = err;
		}
		else {
			handle->ssl_closed = 1;
			req->result = UV_EOF;
		}
	}
}
static void mcl_sslstream_close__done(mcl_sslstream_t *handle, mcl_sslstream_req_t *_req, int status)
{
	QUEUE *ite;
	mcl_sslstream_on_read_t *readreq;
	int err;
	mcl_sslstream_close_t *req = (mcl_sslstream_close_t *)_req;

	// 待写数据.
	if (req->writereq != NULL) {
		mcl_sslstream__s_write(handle, req->writereq);
		req->writereq = NULL;
	}

	while (!QUEUE_EMPTY(&handle->read_queue)) {
		ite = QUEUE_HEAD(&handle->read_queue);
		readreq = QUEUE_DATA(ite, mcl_sslstream_on_read_t, queue);

		QUEUE_REMOVE(&readreq->queue);
		mcl_sslstream_on_read__delete(handle, readreq);
	}

	if (status < 0 || req->result < 0) {
		if (status < 0)
			err = status;
		else if (req->result < 0)
			err = req->result;
		else
			err = UV_UNKNOWN;

		mcl_sslstream__set_readerr(handle, err);
	}
}

static void mcl_sslstream__check(mcl_sslstream_t *handle)
{
	QUEUE *ite;
	mcl_sslstream_on_read_t *readreq;
	mcl_sslstream_buf_t *bufinfo;
	uv_buf_t buf;
	int err;
	unsigned int ncopy, nread;

	// 处理已读数据.
	while (handle->reading) {
		if (handle->cracked) {
			handle->reading = 0;
			handle->read_cb(&handle->stream_base, UV_EPIPE, NULL);
		}
		else if (!QUEUE_EMPTY(&handle->read_queue)) {
			ite = QUEUE_HEAD(&handle->read_queue);
			readreq = QUEUE_DATA(ite, mcl_sslstream_on_read_t, queue);
			ASSERT(readreq->type == mcl_sslstream_req_on_read);
			ASSERT(readreq->nread > readreq->offset);

			buf = uv_buf_init(NULL, 0);
			handle->alloc_cb(&handle->stream_base, readreq->nread - readreq->offset, &buf);
			if (buf.base == NULL || buf.len == 0) {
				handle->reading = 0;
				handle->read_cb(&handle->stream_base, UV_ENOBUFS, &buf);
			}
			else {
				nread = 0;

				while (readreq->nread > readreq->offset) {
					ASSERT(!QUEUE_EMPTY(&readreq->bufs));
					ite = QUEUE_HEAD(&readreq->bufs);
					bufinfo = QUEUE_DATA(ite, mcl_sslstream_buf_t, queue);

					ASSERT(bufinfo->len >= (unsigned int)readreq->offset);
					if (bufinfo->len - (unsigned int)readreq->offset > buf.len - nread) {
						// 缓冲区还有剩余数据.
						ncopy = buf.len - nread;
						memcpy(buf.base + nread, (char *)mcl_sslstream_buf_to_ptr(bufinfo) + readreq->offset, ncopy);
						nread += ncopy;
						readreq->offset += ncopy;
						break;
					}
					else {
						// 缓冲区数据已全部处理.
						ncopy = bufinfo->len - (unsigned int)readreq->offset;
						if (ncopy > 0) {
							memcpy(buf.base + nread, (char *)mcl_sslstream_buf_to_ptr(bufinfo) + readreq->offset, ncopy);
							nread += ncopy;
						}
						readreq->offset = 0;
						readreq->nread -= bufinfo->len;
						QUEUE_REMOVE(ite);
						mcl_sslstream_buf_destroy(bufinfo);

						if (nread == buf.len)
							break;
					}
				}

				if (readreq->nread == readreq->offset) {
					QUEUE_REMOVE(&readreq->queue);
					mcl_sslstream_on_read__delete(handle, readreq);
				}
				handle->read_cb(&handle->stream_base, (ssize_t)nread, &buf);
			}
		}
		else {
			if (handle->readerr < 0) {
				handle->reading = 0;
				handle->read_cb(&handle->stream_base, handle->readerr, NULL);
			}
			else if (handle->shutdown) {
				handle->reading = 0;
				handle->read_cb(&handle->stream_base, UV_EOF, NULL);
			}
			break;
		}
	}

	// 没有错误则继续接收数据.
	if (handle->readerr < 0) {
		if (!handle->inited) {
			mcl_sslstream_write_t *writereq;
			while (!QUEUE_EMPTY(&handle->wait_reqs)) {
				ite = QUEUE_HEAD(&handle->wait_reqs);
				writereq = QUEUE_DATA(ite, mcl_sslstream_write_t, queue);
				QUEUE_REMOVE(ite);
				if (writereq->write_cb)
					writereq->write_cb(writereq->arg, UV_EPIPE);
				mcl_sslstream_write__delete(handle, writereq);
			}
		}
	}
	else {
		if (handle->readreqs != NULL) {
			err = mcl_sslstream__s_read_start(handle);
			if (err < 0) {
				handle->readerr = err;
				if (handle->reading) {
					handle->reading = 0;
					handle->read_cb(&handle->stream_base, handle->readerr, NULL);
				}
			}
		}
	}
}
static void mcl_sslstream__on_work(uv_work_t *work)
{
	mcl_sslstream_t *handle = container_of(work, mcl_sslstream_t, work);
	QUEUE n, *ite;
	mcl_sslstream_req_t *req;

	// 处理队列任务.
	QUEUE_MOVE(&handle->padding_reqs, &n);

	while (!QUEUE_EMPTY(&n)) {
		ite = QUEUE_HEAD(&n);
		req = QUEUE_DATA(ite, mcl_sslstream_req_t, queue);
		QUEUE_REMOVE(ite);

		switch (req->type)
		{
		case mcl_sslstream_req_on_read:
			mcl_sslstream__on_read__work(handle, req);
			break;
		case mcl_sslstream_req_write:
			mcl_sslstream_write__work(handle, req);
			break;
		case mcl_sslstream_req_close:
			mcl_sslstream_close__work(handle, req);
			break;
		default:
			UNREACHABLE();
			break;
		}

		QUEUE_INSERT_TAIL(&handle->padding_reqs, ite);
	}
}
static void mcl_sslstream__on_done(uv_work_t *work, int status)
{
	mcl_sslstream_t *handle = container_of(work, mcl_sslstream_t, work);
	QUEUE n, *ite;
	mcl_sslstream_req_t *req;

	// 处理队列任务.
	QUEUE_MOVE(&handle->padding_reqs, &n);

	while (!QUEUE_EMPTY(&n)) {
		ite = QUEUE_HEAD(&n);
		req = QUEUE_DATA(ite, mcl_sslstream_req_t, queue);
		QUEUE_REMOVE(ite);

		switch (req->type)
		{
		case mcl_sslstream_req_on_read:
			mcl_sslstream__on_read__done(handle, req, status);
			break;
		case mcl_sslstream_req_write:
			mcl_sslstream_write__done(handle, req, status);
			break;
		case mcl_sslstream_req_close:
			mcl_sslstream_close__done(handle, req, status);
			break;
		default:
			UNREACHABLE();
			break;
		}

		mcl_sslstream__unref(handle);
	}

	mcl_sslstream__check(handle);

	if (!QUEUE_EMPTY(&handle->queue_reqs)) {
		QUEUE_MOVE(&handle->queue_reqs, &handle->padding_reqs);
		uv_queue_work(handle->async.loop, &handle->work, mcl_sslstream__on_work, mcl_sslstream__on_done);
	}
	else {
		handle->w_padding = 0;
		mcl_sslstream__unref(handle);
	}
}
static void mcl_sslstream__on_idle(uv_idle_t *idle)
{
	mcl_sslstream_t *handle = container_of(idle, mcl_sslstream_t, idle);
	QUEUE n, *ite;
	mcl_sslstream_req_t *req;

	// 处理队列任务.
	QUEUE_MOVE(&handle->padding_reqs, &n);

	while (!QUEUE_EMPTY(&n)) {
		ite = QUEUE_HEAD(&n);
		req = QUEUE_DATA(ite, mcl_sslstream_req_t, queue);
		QUEUE_REMOVE(ite);

		switch (req->type)
		{
		case mcl_sslstream_req_on_read:
			mcl_sslstream__on_read__work(handle, req);
			mcl_sslstream__on_read__done(handle, req, 0);
			break;
		case mcl_sslstream_req_write:
			mcl_sslstream_write__work(handle, req);
			mcl_sslstream_write__done(handle, req, 0);
			break;
		case mcl_sslstream_req_close:
			mcl_sslstream_close__work(handle, req);
			mcl_sslstream_close__done(handle, req, 0);
			break;
		default:
			UNREACHABLE();
			break;
		}

		mcl_sslstream__unref(handle);
	}

	mcl_sslstream__check(handle);

	if (!QUEUE_EMPTY(&handle->queue_reqs)) {
		QUEUE_MOVE(&handle->queue_reqs, &handle->padding_reqs);
		uv_idle_start(&handle->idle, mcl_sslstream__on_idle);
	}
	else {
		uv_idle_stop(&handle->idle);
		handle->w_padding = 0;
		mcl_sslstream__unref(handle);
	}
}
static void mcl_sslstream__on_async(uv_async_t *async)
{
	mcl_sslstream_t *handle = container_of(async, mcl_sslstream_t, async);
	mcl_sslstream__ref(handle);
	mcl_sslstream__check(handle);
	mcl_sslstream__unref(handle);
}

static void mcl_sslstream__on_alloc(mcl_stream_t *uvstream, size_t suggested_size, uv_buf_t *buf)
{
	mcl_sslstream_buf_t *bufinfo;
	mcl_sslstream_t *handle = (mcl_sslstream_t *)uvstream->data;
	bufinfo = mcl_sslstream_buf_create(handle->buf_size);
	buf->len = (unsigned int)handle->buf_size;
	buf->base = mcl_sslstream_buf_to_ptr(bufinfo);
}
static void mcl_sslstream__on_read(mcl_stream_t *uvstream, ssize_t nread, const uv_buf_t *buf)
{
	mcl_sslstream_buf_t *bufinfo;
	mcl_sslstream_on_read_t *req;
	mcl_sslstream_t *handle = (mcl_sslstream_t *)uvstream->data;

	req = mcl_sslstream_on_read__new(handle);
	ASSERT(req != NULL);

	if (nread < 0) {
		req->nread = (int)nread;
		if (buf && buf->base) {
			bufinfo = mcl_sslstream_buf_from_ptr(buf->base);
			mcl_sslstream_buf_destroy(bufinfo);
		}
		mcl_sslstream__queue_work(handle, (mcl_sslstream_req_t *)req);
	}
	else {
		if ((unsigned int)nread == handle->buf_size)
			handle->buf_size += handle->buf_size_default;
		else if ((unsigned int)nread < handle->buf_size / 2) {
			if (handle->buf_size >= handle->buf_size_default * 2)
				handle->buf_size -= handle->buf_size_default;
			else
				handle->buf_size = handle->buf_size_default;
		}
		bufinfo = mcl_sslstream_buf_from_ptr(buf->base);
		bufinfo->len = (unsigned int)nread;
		QUEUE_INSERT_TAIL(&req->bufs, &bufinfo->queue);
		mcl_sslstream__queue_work(handle, (mcl_sslstream_req_t *)req);

		if (handle->readreqs == NULL) {
			// 接收缓存已用完，暂停接收.
			mcl_sslstream__s_read_stop(handle);
		}
	}

}
static void mcl_sslstream__on_write(void *arg, int status)
{
	QUEUE *ite;
	int err;
	mcl_sslstream_write_t *req = (mcl_sslstream_write_t *)arg;
	mcl_sslstream_t *handle = req->handle;

	mcl_sslstream__set_writerr(handle, status);
	if (req->write_cb != NULL)
		req->write_cb(req->arg, status);
	mcl_sslstream_write__delete(handle, req);

	while (!QUEUE_EMPTY(&handle->write_queue)) {
		ite = QUEUE_HEAD(&handle->write_queue);
		req = QUEUE_DATA(ite, mcl_sslstream_write_t, queue);
		QUEUE_REMOVE(ite);

		if (handle->writerr < 0) {
			if (req->write_cb)
				req->write_cb(req->arg, handle->writerr);
			mcl_sslstream_write__delete(handle, req);
		}
		else if (req->result < 0) {
			mcl_sslstream__set_writerr(handle, req->result);
			if (req->write_cb)
				req->write_cb(req->arg, req->result);
			mcl_sslstream_write__delete(handle, req);
		}
		else if (req->nbiobufs == 0) {
			if (req->write_cb)
				req->write_cb(req->arg, 0);
			mcl_sslstream_write__delete(handle, req);
		}
		else {
			err = mcl_stream_write(handle->uvstream, req->bufs + req->nbufs, req->nbiobufs, req, mcl_sslstream__on_write);
			if (err < 0) {
				mcl_sslstream__set_writerr(handle, err);
				if (req->write_cb)
					req->write_cb(req->arg, err);
				mcl_sslstream_write__delete(handle, req);
			}
			else {
				//handle->s_writing = 1;
				//mcl_sslstream__ref(handle);
				return;
			}
		}
	}

	handle->s_writing = 0;
	mcl_sslstream__unref(handle);
}

static int mcl_sslstream__s_read_start(mcl_sslstream_t *handle) {
	int err;
	if (handle->s_reading)
		err = 0;
	else {
		err = mcl_stream_read_start(handle->uvstream, mcl_sslstream__on_alloc, mcl_sslstream__on_read);
		if (err == 0) {
			handle->uvstream->data = handle;
			handle->s_reading = 1;
			mcl_sslstream__ref(handle);
		}
	}
	return err;
}
static void mcl_sslstream__s_read_stop(mcl_sslstream_t *handle)
{
	if (handle->s_reading) {
		mcl_stream_read_stop(handle->uvstream);
		handle->s_reading = 0;
		mcl_sslstream__unref(handle);
	}
}
static void mcl_sslstream__s_write(mcl_sslstream_t *handle, mcl_sslstream_write_t *req)
{
	int err;

	if (handle->s_writing)
		QUEUE_INSERT_TAIL(&handle->write_queue, &req->queue);
	else {
		if (handle->writerr < 0) {
			if (req->write_cb)
				req->write_cb(req->arg, handle->writerr);
			mcl_sslstream_write__delete(handle, req);
		}
		else if (req->result < 0) {
			mcl_sslstream__set_writerr(handle, req->result);
			if (req->write_cb)
				req->write_cb(req->arg, req->result);
			mcl_sslstream_write__delete(handle, req);
		}
		else if (req->nbiobufs == 0) {
			if (req->write_cb)
				req->write_cb(req->arg, 0);
			mcl_sslstream_write__delete(handle, req);
		}
		else {
			req->handle = handle;
			err = mcl_stream_write(handle->uvstream, req->bufs + req->nbufs, req->nbiobufs, req, mcl_sslstream__on_write);
			if (err < 0) {
				mcl_sslstream__set_writerr(handle, err);
				if (req->write_cb)
					req->write_cb(req->arg, err);
				mcl_sslstream_write__delete(handle, req);
			}
			else {
				handle->s_writing = 1;
				mcl_sslstream__ref(handle);
			}
		}
	}
}
static void mcl_sslstream__queue_work(mcl_sslstream_t *handle, mcl_sslstream_req_t *req)
{
	QUEUE_INSERT_TAIL(&handle->queue_reqs, &req->queue);
	mcl_sslstream__ref(handle);

	if (!handle->w_padding) {
		handle->w_padding = 1;
		mcl_sslstream__ref(handle);

		if (!handle->w_enable) {
			QUEUE_MOVE(&handle->queue_reqs, &handle->padding_reqs);
			uv_idle_start(&handle->idle, mcl_sslstream__on_idle);
		}
		else {
			QUEUE_MOVE(&handle->queue_reqs, &handle->padding_reqs);
			uv_queue_work(handle->async.loop, &handle->work, mcl_sslstream__on_work, mcl_sslstream__on_done);
		}
	}
}

static void mcl_sslstream_close(mcl_stream_t *strm, mcl_stream_close_cb close_cb)
{
	mcl_sslstream_t *handle = container_of(strm, mcl_sslstream_t, stream_base);
	ASSERT(!handle->closing);

	handle->close_cb = close_cb;
	handle->closing = 1;
	handle->reading = 0;

	handle->closereq.type = mcl_sslstream_req_close;
	handle->closereq.result = 0;
	handle->closereq.writereq = NULL;
	mcl_sslstream__queue_work(handle, (mcl_sslstream_req_t *)&handle->closereq);

	mcl_sslstream__unref(handle);
}
static int mcl_sslstream_read_start(mcl_stream_t *strm, mcl_stream_alloc_cb alloc_cb, mcl_stream_read_cb read_cb)
{
	mcl_sslstream_t *handle = container_of(strm, mcl_sslstream_t, stream_base);

	if (handle->reading)
		return UV_EALREADY;
	if (handle->closing)
		return UV_EINVAL;
	if (handle->cracked)
		return UV_EPIPE;

	if (QUEUE_EMPTY(&handle->read_queue)) {
		if (handle->shutdown)
			return UV_EPIPE;
		if (handle->readerr)
			return handle->readerr;
	}

	handle->alloc_cb = alloc_cb;
	handle->read_cb = read_cb;
	handle->reading = 1;
	uv_async_send(&handle->async);
	return 0;
}
static int mcl_sslstream_read_stop(mcl_stream_t *strm)
{
	mcl_sslstream_t *handle = container_of(strm, mcl_sslstream_t, stream_base);

	if (handle->reading) {
		handle->reading = 0;
		// TODO: 在alloc_cb活动时禁止暂停.
	}

	return 0;
}
static int mcl_sslstream_write(mcl_stream_t *strm, const uv_buf_t *bufs, unsigned int nbufs, void *arg, mcl_stream_write_cb write_cb)
{
	void *new_ptr;
	mcl_sslstream_write_t *req;
	mcl_sslstream_t *handle = container_of(strm, mcl_sslstream_t, stream_base);

	if (handle->closing)
		return UV_EINVAL;
	if (handle->writerr)
		return UV_EPIPE;
	if (handle->readerr && !handle->inited)
		return UV_EPIPE;

	req = mcl_sslstream_write__new(handle);
	if (req == NULL)
		return UV_ENOMEM;

	req->write_cb = write_cb;
	req->arg = arg;
	if (nbufs > ARRAY_SIZE(req->static_bufs)) {
		new_ptr = (uv_buf_t *)malloc(sizeof(uv_buf_t) * nbufs);
		if (new_ptr == NULL) {
			mcl_sslstream_write__delete(handle, req);
			return UV_ENOMEM;
		}
		req->bufs = new_ptr;
	}
	memcpy(req->bufs, bufs, sizeof(uv_buf_t) * nbufs);
	req->nbufs = nbufs;

	if (!handle->inited)
		QUEUE_INSERT_TAIL(&handle->wait_reqs, &req->queue);
	else
		mcl_sslstream__queue_work(handle, (mcl_sslstream_req_t *)req);

	return 0;
}
static int mcl_sslstream_crack(mcl_stream_t *strm)
{
	mcl_sslstream_t *handle = container_of(strm, mcl_sslstream_t, stream_base);

	if (handle->cracked)
		return 0;
	handle->cracked = 1;

	if (handle->reading) {
		uv_async_send(&handle->async);
	}
	return 0;
}

static int mcl_sslstream_get_prop(mcl_stream_t *strm, int name, void *val, int *len)
{
	mcl_sslstream_t *handle = container_of(strm, mcl_sslstream_t, stream_base);

	switch (name)
	{
	case MCL_STREAM_PROP_QUEUEWORK:
		get_prop__int64(val, len, handle->w_enable);
		return handle->w_enable;
	default:
		return mcl_stream_get_prop(handle->uvstream, name, val, len);
	}
	//return UV_EINVAL;
}
static int mcl_sslstream_set_prop(mcl_stream_t *strm, int name, const void *val, int len)
{
	int64_t i64val;
	mcl_sslstream_t *handle = container_of(strm, mcl_sslstream_t, stream_base);

	switch (name)
	{
	case MCL_STREAM_PROP_QUEUEWORK:
		i64val = 0;
		set_prop__int64(val, len, &i64val);
		if (i64val == 0)
			return handle->w_enable ? UV_EINVAL : 0;
		else {
			handle->w_enable = 1;
			return 0;
		}
	default:
		return mcl_stream_set_prop(handle->uvstream, name, val, len);
	}
	//return UV_EINVAL;
}

mcl_stream_t *mcl_sslstream_wrap(uv_loop_t *loop, mcl_stream_t *stream, int is_server, void *ssl_ctx, int *result, void **ssl)
{
	int i, ret, err;
	mcl_sslstream_t *handle;

	// 创建并初始化对象.
	handle = (mcl_sslstream_t *)malloc(sizeof(mcl_sslstream_t));
	if (handle == NULL) {
		if (result != NULL)
			*result = UV_ENOMEM;
		return NULL;
	}

	handle->stream_base.vtbl.close = mcl_sslstream_close;
	handle->stream_base.vtbl.write = mcl_sslstream_write;
	handle->stream_base.vtbl.read_start = mcl_sslstream_read_start;
	handle->stream_base.vtbl.read_stop = mcl_sslstream_read_stop;
	handle->stream_base.vtbl.crack = mcl_sslstream_crack;
	handle->stream_base.vtbl.get_prop = mcl_sslstream_get_prop;
	handle->stream_base.vtbl.set_prop = mcl_sslstream_set_prop;
	handle->stream_base.data = NULL;

	handle->close_cb = NULL;
	handle->read_cb = NULL;
	handle->alloc_cb = NULL;

	handle->reading = 0;
	handle->cracked = 0;
	handle->closing = 0;
	handle->ref_count = 1;
	handle->readerr = 0;
	handle->writerr = 0;
	handle->inited = 0;
	handle->shutdown = 0;
	handle->w_enable = 0;
	handle->w_padding = 0;
	handle->s_reading = 0;
	handle->s_writing = 0;
	handle->buf_size = 4096;
	handle->buf_size_default = 4096;
	handle->ssl_closing = 0;
	handle->ssl_closed = 0;

	handle->writereqs = NULL;
	for (i = 0; i < ARRAY_SIZE(handle->writereqs2); ++i)
		mcl__memlist_release(&handle->writereqs, &handle->writereqs2[i]);
	handle->readreqs = NULL;
	for (i = 0; i < ARRAY_SIZE(handle->readreqs2); ++i)
		mcl__memlist_release(&handle->readreqs, &handle->readreqs2[i]);

	QUEUE_INIT(&handle->read_queue);
	QUEUE_INIT(&handle->write_queue);
	QUEUE_INIT(&handle->wait_reqs);
	QUEUE_INIT(&handle->queue_reqs);
	QUEUE_INIT(&handle->padding_reqs);

	handle->ssl = SSL_new(ssl_ctx);
	handle->read_bio = BIO_new(BIO_s_mem());
	handle->write_bio = BIO_new(BIO_s_mem());
	if (handle->ssl == NULL || handle->read_bio == NULL || handle->write_bio == NULL) {
		if (handle->ssl)
			SSL_free(handle->ssl);
		if (handle->read_bio)
			BIO_free(handle->read_bio);
		if (handle->write_bio)
			BIO_free(handle->write_bio);
		free(handle);
		if (result != NULL)
			*result = UV_ENOMEM;
		return NULL;
	}

	SSL_set_bio(handle->ssl, handle->read_bio, handle->write_bio);
	if (is_server)
		SSL_set_accept_state(handle->ssl);
	else
		SSL_set_connect_state(handle->ssl);

	CHECK(0 == uv_async_init(loop, &handle->async, mcl_sslstream__on_async));
	CHECK(0 == uv_idle_init(loop, &handle->idle));
	handle->uvstream = stream;

	// 开始SSL握手.
	mcl_sslstream_write_t *writereq = NULL;

	ret = SSL_do_handshake(handle->ssl);
	if (ret == 1) {
		if (SSL_is_init_finished(handle->ssl))
			handle->inited = 1;
		err = mcl_sslstream__read_bio(handle, &writereq);
	}
	else {
		err = SSL_get_error(handle->ssl, ret);
		if (err == SSL_ERROR_WANT_READ)
			err = mcl_sslstream__read_bio(handle, &writereq);
		else
			err = UV_UNKNOWN;
	}

	if (writereq != NULL)
		mcl_sslstream__s_write(handle, writereq);
	if (err == 0)
		err = mcl_sslstream__s_read_start(handle);

	if (err < 0) {
		mcl_sslstream_close(&handle->stream_base, NULL);
		if (result != NULL)
			*result = err;
		return NULL;
	}

	if (ssl != NULL)
		*ssl = handle->ssl;

	if (result != NULL)
		*result = 0;
	return &handle->stream_base;
}
