
#include "fstail.h"
#include "defs.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>


#define FSTAIL_MAX 128

#ifndef O_BINARY
#define O_BINARY 0
#endif

typedef struct {
	uv_work_t wreq;
	mcl_fstail_t *parent_handle;
	int work_padding;
	unsigned int interval;
	uint64_t last_size;
	uint64_t curr_size;
	ssize_t buf_len;
	char buf[FSTAIL_MAX];
	size_t tail_len;
	char tail_buf[2048];
	char path[4];
} fstail_ctx_t;


static void mcl_fstail__read_work(uv_work_t *wreq)
{
	int err;
	uv_fs_t fsreq;
	uv_file fd = -1;
	uv_buf_t buf;
	uint64_t size, offset;
	fstail_ctx_t *ctx = container_of(wreq, fstail_ctx_t, wreq);
	char read_buf[sizeof(ctx->tail_buf) * 2];
	char *s;

	err = uv_fs_open(NULL, &fsreq, ctx->path, O_BINARY | O_RDONLY, 0644, NULL);
	if (err < 0)
		goto out;
	fd = (uv_file)fsreq.result;

	size = ctx->curr_size;
	if (ctx->last_size == 0) {
		offset = 0;
		goto found;
	}
	if (ctx->tail_len == 0) {
		offset = ctx->last_size;
		goto found;
	}

	buf = uv_buf_init(read_buf, sizeof(read_buf));
	if (size >= ctx->last_size) {
		// 向后搜索.
		offset = ctx->last_size - ctx->tail_len;

		while (1) {
			uv_fs_req_cleanup(&fsreq);
			err = uv_fs_read(NULL, &fsreq, fd, &buf, 1, offset, NULL);
			if (err < 0)
				goto out;

			s = (char *)(void *)mcl_memmem_sunday(read_buf, (size_t)fsreq.result, ctx->tail_buf, ctx->tail_len);
			if (s != NULL) {
				if (size < offset + (size_t)fsreq.result)
					size = offset + (size_t)fsreq.result;
				offset += (s - read_buf) + ctx->tail_len;
				goto found;
			}
			if ((unsigned int)fsreq.result < buf.len) {
				offset = ctx->last_size - ctx->tail_len;
				goto search_left;
			}

			offset += fsreq.result - ctx->tail_len;
		}
	}
	else {
		// 向前搜索.
		offset = size >= sizeof(read_buf) ? size - sizeof(read_buf) : 0;

		while (1) {
			uv_fs_req_cleanup(&fsreq);
			err = uv_fs_read(NULL, &fsreq, fd, &buf, 1, offset, NULL);
			if (err < 0)
				goto out;

			s = (char *)(void *)mcl_memrmem_sunday(read_buf, (size_t)fsreq.result, ctx->tail_buf, ctx->tail_len);
			if (s != NULL) {
				offset += (s - read_buf) + ctx->tail_len;
				goto found;
			}

		search_left:
			if (offset == 0 && fsreq.result > 0) {
				if (ctx->tail_len - offset > (unsigned int)fsreq.result)
					offset = ctx->tail_len - (unsigned int)fsreq.result;
				while (offset < ctx->tail_len) {
					s = memchr(ctx->tail_buf + offset, read_buf[0], ctx->tail_len - offset);
					if (s == NULL)
						break;
					offset = s - ctx->tail_buf;
					if (memcmp(s, read_buf, ctx->tail_len - offset) == 0) {
						offset = ctx->tail_len - offset;
						goto found;
					}
					offset += 1;
				}
				offset = 0;
				goto found;
			}
			else if (offset >= sizeof(read_buf) - ctx->tail_len)
				offset -= sizeof(read_buf) - ctx->tail_len;
			else
				offset = 0;
		}
	}

found:
	if (size > offset) {
		unsigned long this_len;
		if (size - offset > sizeof(ctx->buf))
			this_len = sizeof(ctx->buf);
		else
			this_len = (unsigned long)(size - offset);

		uv_fs_req_cleanup(&fsreq);
		buf = uv_buf_init(ctx->buf, this_len);
		err = uv_fs_read(NULL, &fsreq, fd, &buf, 1, offset, NULL);
		if (err < 0) {
			size = offset;
			goto reinit;
		}
		ctx->buf_len = fsreq.result;
		size = offset + ctx->buf_len;
	}

reinit:
	uv_fs_req_cleanup(&fsreq);
	offset = size >= sizeof(ctx->tail_buf) ? size - sizeof(ctx->tail_buf) : 0;
	buf = uv_buf_init(ctx->tail_buf, (unsigned int)(size - offset));
	err = uv_fs_read(NULL, &fsreq, fd, &buf, 1, offset, NULL);
	if (err < 0) {
		ctx->tail_len = 0;
		ctx->last_size = 0;
	}
	else {
		if ((unsigned int)fsreq.result < buf.len)
			ctx->curr_size = offset + fsreq.result;

		ctx->tail_len = fsreq.result;
		ctx->last_size = offset + ctx->tail_len;
	}

out:
	uv_fs_req_cleanup(&fsreq);
	if (fd != -1) {
		uv_fs_close(NULL, &fsreq, fd, NULL);
		uv_fs_req_cleanup(&fsreq);
	}
}
static void mcl_fstail__read_done(uv_work_t *wreq, int status)
{
	int err;
	fstail_ctx_t *ctx = container_of(wreq, fstail_ctx_t, wreq);
	mcl_fstail_t *handle = ctx->parent_handle;

	if (handle->ctx != ctx) {
		free(ctx);
		goto out;
	}

	if (ctx->buf_len < 0) {
		if (handle->cb)
			handle->cb(handle, NULL, ctx->buf_len);
	}
	else if (ctx->buf_len > 0) {
		if (handle->cb)
			handle->cb(handle, ctx->buf, ctx->buf_len);
	}

	if (handle->ctx == ctx && ctx->last_size < ctx->curr_size) {
		err = uv_queue_work(handle->poll.loop, &ctx->wreq, mcl_fstail__read_work, mcl_fstail__read_done);
		if (err == 0)
			return;

		if (handle->cb)
			handle->cb(handle, NULL, status);
	}

	if (handle->ctx != ctx) {
		free(ctx);
		goto out;
	}
	ctx->work_padding = 0;

out:
	--handle->nrefs;
	if (handle->nrefs == 0) {
		if (handle->close_cb)
			handle->close_cb(handle);
	}
}

static void mcl_fstail__on_poll(uv_fs_poll_t *_handle, int status, const uv_stat_t *prev, const uv_stat_t *curr)
{
	int err;
	mcl_fstail_t *handle = container_of(_handle, mcl_fstail_t, poll);
	fstail_ctx_t *ctx = (fstail_ctx_t *)handle->ctx;
	ASSERT(ctx != NULL);

	// busying.
	if (ctx->work_padding)
		return;

	if (status < 0) {
		if (handle->cb)
			handle->cb(handle, NULL, status);
	}
	else {
		ASSERT(curr != NULL);
		ctx->curr_size = curr->st_size;
		ctx->buf_len = 0;
		err = uv_queue_work(handle->poll.loop, &ctx->wreq, mcl_fstail__read_work, mcl_fstail__read_done);
		if (err < 0) {
			if (handle->cb)
				handle->cb(handle, NULL, status);
		}
		else {
			ctx->work_padding = 1;
			++handle->nrefs;
		}
	}
}
static void mcl_fstail__on_poll_close(uv_handle_t *_handle)
{
	mcl_fstail_t *handle = container_of(_handle, mcl_fstail_t, poll);
	--handle->nrefs;
	if (handle->nrefs == 0) {
		if (handle->close_cb)
			handle->close_cb(handle);
	}
}

static void mcl_fstail__init_work(uv_work_t *wreq)
{
	int err;
	uv_fs_t fsreq;
	uv_file fd = -1;
	uv_buf_t buf;
	uint64_t fsize, offset;
	fstail_ctx_t *ctx = container_of(wreq, fstail_ctx_t, wreq);

	err = uv_fs_stat(NULL, &fsreq, ctx->path, NULL);
	if (err < 0 || fsreq.statbuf.st_size == 0)
		goto out;
	fsize = fsreq.statbuf.st_size;

	uv_fs_req_cleanup(&fsreq);
	err = uv_fs_open(NULL, &fsreq, ctx->path, O_BINARY | O_RDONLY, 0644, NULL);
	if (err < 0)
		goto out;
	fd = (uv_file)fsreq.result;

	uv_fs_req_cleanup(&fsreq);
	buf = uv_buf_init(ctx->tail_buf, sizeof(ctx->tail_buf));
	offset = fsize >= sizeof(ctx->tail_buf) ? fsize - sizeof(ctx->tail_buf) : 0;
	err = uv_fs_read(NULL, &fsreq, fd, &buf, 1, offset, NULL);
	if (err <= 0)
		goto out;
	ctx->tail_len = fsreq.result;
	ctx->last_size = offset + ctx->tail_len;

out:
	uv_fs_req_cleanup(&fsreq);
	if (fd != -1) {
		uv_fs_close(NULL, &fsreq, fd, NULL);
		uv_fs_req_cleanup(&fsreq);
	}
}
static void mcl_fstail__init_done(uv_work_t *wreq, int status)
{
	int err;
	fstail_ctx_t *ctx = container_of(wreq, fstail_ctx_t, wreq);
	mcl_fstail_t *handle = ctx->parent_handle;

	if (handle->ctx != ctx) {
		free(ctx);
		goto out;
	}

	err = uv_fs_poll_start(&handle->poll, mcl_fstail__on_poll, ctx->path, ctx->interval);
	if (err < 0) {
		handle->ctx = NULL;
		free(ctx);
		if (handle->cb)
			handle->cb(handle, NULL, err);
		goto out;
	}
	ctx->work_padding = 0;

out:
	--handle->nrefs;
	if (handle->nrefs == 0) {
		if (handle->close_cb)
			handle->close_cb(handle);
	}
}

int mcl_fstail_init(mcl_fstail_t *handle, uv_loop_t *loop)
{
	int err;
	handle->nrefs = 0;
	handle->cb = NULL;
	handle->close_cb = NULL;
	handle->ctx = NULL;
	err = uv_fs_poll_init(loop, &handle->poll);
	if (err < 0)
		return err;

	++handle->nrefs;
	return 0;
}

int mcl_fstail_start(mcl_fstail_t *handle, mcl_fstail_cb cb, const char *path, unsigned int interval)
{
	int err;
	fstail_ctx_t *ctx = (fstail_ctx_t *)handle->ctx;

	if (ctx && interval == ctx->interval && strcmp(path, ctx->path) == 0) {
		handle->cb = cb;
		return 0;
	}

	ctx = (fstail_ctx_t *)malloc(sizeof(fstail_ctx_t) + strlen(path));
	if (ctx == NULL)
		return UV_ENOMEM;

	memset(ctx, 0, sizeof(fstail_ctx_t));
	strcpy(ctx->path, path);
	ctx->work_padding = 1;
	ctx->interval = interval;
	ctx->parent_handle = handle;
	err = uv_queue_work(handle->poll.loop, &ctx->wreq, mcl_fstail__init_work, mcl_fstail__init_done);
	if (err < 0) {
		free(ctx);
		return err;
	}

	mcl_fstail_stop(handle);
	handle->cb = cb;
	handle->ctx = ctx;
	++handle->nrefs;
	return 0;
}

int mcl_fstail_stop(mcl_fstail_t *handle)
{
	fstail_ctx_t *ctx = (fstail_ctx_t *)handle->ctx;
	uv_fs_poll_stop(&handle->poll);
	if (ctx && !ctx->work_padding)
		free(ctx);
	handle->ctx = NULL;
	return 0;
}

void mcl_fstail_close(mcl_fstail_t *handle, mcl_fstail_close_cb close_cb)
{
	handle->close_cb = close_cb;
	mcl_fstail_stop(handle);
	uv_close((uv_handle_t *)&handle->poll, mcl_fstail__on_poll_close);
}
