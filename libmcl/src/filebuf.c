
#include "filebuf.h"
#include <uv.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#ifdef _WIN64
#pragma warning(disable: 4018)
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define zone_union_is_sequent(s1, n1, s2, n2) ((s1) <= (s2) + (n2) && (s1) + (n1) >= (s2))
#define zone_union_a(s1, n1, s2, n2) MCL_MIN((s1), (s2))
#define zone_union_b(s1, n1, s2, n2) MCL_MAX((s1) + (n1), (s2) + (n2))

#define zone_intersection_not_empty(s1, n1, s2, n2) ((n1) && (n2) && (s1) < (s2) + (n2) && (s1) + (n1) > (s2))
#define zone_intersection_a(s1, n1, s2, n2) MCL_MAX((s1), (s2))
#define zone_intersection_b(s1, n1, s2, n2) MCL_MIN((s1) + (n1), (s2) + (n2))

#define filebuf__cache_copy(s1, n1, b1, s2, n2, b2)                    \
do {                                                                   \
	if (zone_intersection_not_empty((s1), (n1), (s2), (n2))) {         \
		int64_t _a = zone_intersection_a((s1), (n1), (s2), (n2));      \
		int64_t _b = zone_intersection_b((s1), (n1), (s2), (n2));      \
		memcpy(&(b1)[_a - (s1)], &(b2)[_a - (s2)], (size_t)(_b - _a)); \
	}                                                                  \
} while(0)


typedef struct mcl_filebuf_impl_s mcl_filebuf_impl_t;

struct mcl_filebuf_impl_s
{
	int64_t size;
	size_t linked;
	size_t bufsize;
	size_t wrlen;
	size_t rdlen;
	int64_t wrpos;
	int64_t rdpos;
	char *wrbuf;
	char *rdbuf;
	uv_rwlock_t locker;
	int flags;
	char path[4];
};


static void file_close(uv_file *fdp, mcl_filebuf_impl_t *filp)
{
	uv_fs_t fsreq;

	if (*fdp >= 0) {
		uv_fs_close(NULL, &fsreq, *fdp, NULL);
		uv_fs_req_cleanup(&fsreq);
		*fdp = -1;
	}
}

ssize_t mcl_filebuf_impl__read_file(uv_file *fdp, mcl_filebuf_impl_t *filp, char *buf, size_t count, int64_t pos)
{
	size_t nread;
	uv_fs_t fsreq;
	uv_buf_t bufs = uv_buf_init(buf, (unsigned int)count);

	if (*fdp < 0) {
		uv_fs_open(NULL, &fsreq, filp->path, O_RDONLY | O_BINARY, 0644, NULL);
		uv_fs_req_cleanup(&fsreq);
		if (fsreq.result < 0) {
			// 文件打开失败，空数据填充.
			memset(buf, 0, count);
			return fsreq.result;
		}
		*fdp = (uv_file)fsreq.result;
	}

	uv_fs_read(NULL, &fsreq, *fdp, &bufs, 1, pos, NULL);
	uv_fs_req_cleanup(&fsreq);

	nread = fsreq.result > 0 ? fsreq.result : 0;
	if (nread < count)
		memset(buf + nread, 0, count - nread);

	return fsreq.result;
}

ssize_t mcl_filebuf_impl__write_file(uv_file *fdp, mcl_filebuf_impl_t *filp, const uv_buf_t *bufs, unsigned int nbufs, int64_t pos)
{
	uv_fs_t fsreq;

	if (*fdp < 0) {
		uv_fs_open(NULL, &fsreq, filp->path, O_RDWR | O_BINARY | O_CREAT, 0644, NULL);
		uv_fs_req_cleanup(&fsreq);
		if (fsreq.result < 0)
			return fsreq.result;
		*fdp = (uv_file)fsreq.result;
	}

	uv_fs_write(NULL, &fsreq, *fdp, bufs, nbufs, pos, NULL);
	uv_fs_req_cleanup(&fsreq);

	return fsreq.result;
}

static ssize_t mcl_filebuf_impl__read(uv_file *fdp, mcl_filebuf_impl_t *filp, char *buf, size_t count, int64_t pos)
{
	// 命中写缓冲区.
	if (zone_intersection_not_empty(pos, (ssize_t)count, filp->wrpos, (ssize_t)filp->wrlen)) {
		int64_t begin = zone_intersection_a(pos, count, filp->wrpos, filp->wrlen);
		int64_t end = zone_intersection_b(pos, count, filp->wrpos, filp->wrlen);

		if (pos < begin)
			mcl_filebuf_impl__read(fdp, filp, buf, (size_t)(begin - pos), pos);
		if (pos + (ssize_t)count > end)
			mcl_filebuf_impl__read(fdp, filp, &buf[end - pos], (size_t)(pos + count - end), end);

		if (buf != filp->rdbuf)
			memcpy(&buf[begin - pos], &filp->wrbuf[begin - filp->wrpos], (size_t)(end - begin));

		return count;
	}
	// 命中读缓冲区.
	else if (zone_intersection_not_empty(pos, (ssize_t)count, filp->rdpos, (ssize_t)filp->rdlen)) {
		int64_t begin = zone_intersection_a(pos, count, filp->rdpos, filp->rdlen);
		int64_t end = zone_intersection_b(pos, count, filp->rdpos, filp->rdlen);

		if (buf == filp->rdbuf)
			memmove(&buf[begin - pos], &filp->rdbuf[begin - filp->rdpos], (size_t)(end - begin));

		if (pos < begin)
			mcl_filebuf_impl__read_file(fdp, filp, buf, (size_t)(begin - pos), pos);
		if (pos + (ssize_t)count > end)
			mcl_filebuf_impl__read_file(fdp, filp, &buf[end - pos], (size_t)(pos + count - end), end);

		if (buf != filp->rdbuf)
			memcpy(&buf[begin - pos], &filp->rdbuf[begin - filp->rdpos], (size_t)(end - begin));

		return count;
	}

	// 直接从文件读取.
	return mcl_filebuf_impl__read_file(fdp, filp, buf, count, pos);
}

ssize_t mcl_filebuf_impl_read(mcl_filebuf_impl_t *filp, char *buf, size_t count, int64_t *fpos)
{
	ssize_t r;
	uv_file fd = -1;
	int64_t pos = *fpos;

	if (count > UINT_MAX)
		return UV_E2BIG;
	if (pos >= filp->size || count == 0)
		return UV_EOF;

	uv_rwlock_rdlock(&filp->locker);

	if (pos >= filp->size) {
		uv_rwlock_rdunlock(&filp->locker);
		return UV_EOF;
	}
	if (count > (size_t)(filp->size - pos))
		count = (size_t)(filp->size - pos);

	r = mcl_filebuf_impl__read(&fd, filp, buf, count, pos);
	uv_rwlock_rdunlock(&filp->locker);

	// 需要刷新读缓冲区.
	if ((pos + (ssize_t)count < filp->rdpos || pos + count > filp->rdpos + filp->rdlen || filp->rdlen == 0) &&
		(pos + (ssize_t)count < filp->wrpos || pos + count > filp->wrpos + filp->wrlen || filp->wrlen == 0) &&
		(r > 0) && (filp->bufsize > 0)) {

		if (uv_rwlock_trywrlock(&filp->locker) == 0) {
			int64_t rdpos = 0;
			size_t rdlen = (size_t)filp->size;

			if (rdlen > filp->bufsize) {
				rdpos = pos + count;
				rdlen = filp->bufsize;
				if (rdpos > filp->size - (ssize_t)filp->bufsize)
					rdpos = filp->size - (ssize_t)filp->bufsize;
			}
			if ((rdlen != 0) && (filp->rdpos != rdpos || filp->rdlen != rdlen)) {
				if (filp->rdbuf == NULL)
					filp->rdbuf = (char *)malloc(filp->bufsize);
				if (filp->rdbuf != NULL) {
					mcl_filebuf_impl__read(&fd, filp, filp->rdbuf, rdlen, rdpos);
					filp->rdlen = rdlen;
					filp->rdpos = rdpos;
				}
			}

			uv_rwlock_wrunlock(&filp->locker);
		}
	}

	file_close(&fd, filp);
	*fpos += count;

	return count;
}

ssize_t mcl_filebuf_impl_write(mcl_filebuf_impl_t *filp, const char *buf, size_t count, int64_t *fpos)
{
	ssize_t r = 0;
	uv_file fd = -1;
	int64_t pos = *fpos;
	int64_t zone_head;
	int64_t zone_tail;
	uv_buf_t bufs[2];

	if (count == 0)
		return 0;
	if (count > UINT_MAX)
		return UV_E2BIG;

	bufs[0] = uv_buf_init("", 0);
	bufs[1] = uv_buf_init("", 0);

	uv_rwlock_wrlock(&filp->locker);

	if (filp->wrlen == 0)
		filp->wrpos = pos;

	// 与当前的缓存相邻.
	if (zone_union_is_sequent(pos, (ssize_t)count, filp->wrpos, (ssize_t)filp->wrlen)) {
		zone_head = zone_union_a(pos, count, filp->wrpos, filp->wrlen);
		zone_tail = zone_union_b(pos, count, filp->wrpos, filp->wrlen);

		if (filp->wrbuf == NULL && zone_tail - zone_head <= (ssize_t)filp->bufsize)
			filp->wrbuf = (char *)malloc(filp->bufsize);

		// 如果写缓存区充足，则写缓存.
		if (filp->wrbuf != NULL && zone_tail - zone_head <= (ssize_t)filp->bufsize) {
			if (pos <= filp->wrpos) {
				if (pos + count < filp->wrpos + filp->wrlen)
					memmove(&filp->wrbuf[count], &filp->wrbuf[pos + count - filp->wrpos], (size_t)(filp->wrpos + filp->wrlen - (pos + count)));
				filp->wrpos = pos;
			}
			memcpy(&filp->wrbuf[pos - filp->wrpos], buf, count);
			filp->wrlen = (size_t)(zone_tail - zone_head);
		}
		else {
			if (pos <= filp->wrpos) {
				bufs[0] = uv_buf_init((char *)buf, (unsigned int)count);
				if (pos + count < filp->wrpos + filp->wrlen)
					bufs[1] = uv_buf_init(&filp->wrbuf[pos + count - filp->wrpos], (unsigned int)(filp->wrpos + filp->wrlen - (pos + count)));
			}
			else {
				bufs[0] = uv_buf_init(filp->wrbuf, (unsigned int)(pos - filp->wrpos));
				bufs[1] = uv_buf_init((char *)buf, (unsigned int)count);
			}

			r = mcl_filebuf_impl__write_file(&fd, filp, bufs, 2, zone_head);
			if (r < 0)
				goto wr_end;
			filebuf__cache_copy(filp->rdpos, (ssize_t)filp->rdlen, filp->rdbuf, zone_head, (ssize_t)bufs[0].len, bufs[0].base);
			filebuf__cache_copy(filp->rdpos, (ssize_t)filp->rdlen, filp->rdbuf, zone_head + (ssize_t)bufs[0].len, (ssize_t)bufs[1].len, bufs[1].base);
			filp->wrlen = 0;
		}
	}
	// 无法利用写缓存.
	else {
		if (filp->wrlen != 0) {
			bufs[0] = uv_buf_init(filp->wrbuf, (unsigned int)filp->wrlen);
			r = mcl_filebuf_impl__write_file(&fd, filp, bufs, 1, filp->wrpos);
			if (r < 0)
				goto wr_end;
			filebuf__cache_copy(filp->rdpos, (ssize_t)filp->rdlen, filp->rdbuf, filp->wrpos, (ssize_t)bufs[0].len, bufs[0].base);
			filp->wrlen = 0;
		}
		bufs[0] = uv_buf_init((char *)buf, (unsigned int)count);
		r = mcl_filebuf_impl__write_file(&fd, filp, bufs, 1, pos);
		if (r < 0)
			goto wr_end;
		filebuf__cache_copy(filp->rdpos, (ssize_t)filp->rdlen, filp->rdbuf, pos, (ssize_t)bufs[0].len, bufs[0].base);
	}
	if (filp->size < pos + (ssize_t)count)
		filp->size = pos + (ssize_t)count;

wr_end:
	uv_rwlock_wrunlock(&filp->locker);
	file_close(&fd, filp);

	if (r < 0)
		return r;

	*fpos += count;
	return count;
}

int mcl_filebuf_impl_open(mcl_filebuf_impl_t **pp, const char *path, int flags)
{
	int err;
	int o_flags;
	uv_file fd;
	uv_fs_t fsreq;
	uv_stat_t statbuf;
	mcl_filebuf_impl_t *filp;
	size_t pathlen;

	pathlen = strlen(path);
	if (pathlen > 4096)
		return UV_EINVAL;

	flags &= MCL_FILEBUF_CREAT | MCL_FILEBUF_TRUNC | MCL_FILEBUF_EXCL | MCL_FILEBUF_TMPFILE;
	o_flags = O_BINARY;

	if (flags & MCL_FILEBUF_CREAT)
		o_flags |= O_CREAT;
	if (flags & MCL_FILEBUF_TRUNC)
		o_flags |= O_TRUNC;
	if (flags & MCL_FILEBUF_EXCL)
		o_flags |= O_EXCL;

	if (flags & MCL_FILEBUF_RDONLY)
		o_flags |= O_RDONLY;
	else
		o_flags |= O_RDWR;

	fd = uv_fs_open(NULL, &fsreq, path, o_flags, 0644, NULL);
	uv_fs_req_cleanup(&fsreq);
	if (fd < 0)
		return fd;

	err = uv_fs_fstat(NULL, &fsreq, fd, NULL);
	memcpy(&statbuf, &fsreq.statbuf, sizeof(statbuf));
	uv_fs_req_cleanup(&fsreq);
	if (err < 0) {
		uv_fs_close(NULL, &fsreq, fd, NULL);
		return err;
	}
	
	err = uv_fs_close(NULL, &fsreq, fd, NULL);
	uv_fs_req_cleanup(&fsreq);
	if (err < 0)
		return err;

	filp = (mcl_filebuf_impl_t *)malloc(sizeof(mcl_filebuf_impl_t) + pathlen);
	if (filp == NULL)
		return UV_ENOMEM;

	filp->rdlen = 0;
	filp->rdpos = 0;
	filp->rdbuf = NULL;
	filp->wrlen = 0;
	filp->wrpos = 0;
	filp->wrbuf = NULL;
	filp->linked = 1;
	filp->bufsize = 16 * 1024;
	filp->flags = flags;

	filp->size = statbuf.st_size;
	memcpy(filp->path, path, pathlen + 1);
	uv_rwlock_init(&filp->locker);

	*pp = filp;
	return 0;
}

void mcl_filebuf_impl_sync(mcl_filebuf_impl_t *filp)
{
	uv_buf_t wrbuf;
	uv_file fd = -1;

	if (filp->wrlen != 0) {
		uv_rwlock_wrlock(&filp->locker);
		if (filp->wrlen != 0) {
			wrbuf = uv_buf_init(filp->wrbuf, (unsigned int)filp->wrlen);
			mcl_filebuf_impl__write_file(&fd, filp, &wrbuf, 1, filp->wrpos);
			filebuf__cache_copy(filp->rdpos, (ssize_t)filp->rdlen, filp->rdbuf, filp->wrpos, (ssize_t)wrbuf.len, wrbuf.base);
			filp->wrlen = 0;
			free(filp->wrbuf);
			filp->wrbuf = NULL;
		}
		uv_rwlock_wrunlock(&filp->locker);
		file_close(&fd, filp);
	}
}

void mcl_filebuf_impl_set_bufsize(mcl_filebuf_impl_t *filp, size_t bufsize)
{
	if (!(filp->rdbuf || filp->wrbuf || bufsize > 512 * 1024))
		filp->bufsize = bufsize;
}

void mcl_filebuf_impl_link(mcl_filebuf_impl_t *filp)
{
	uv_rwlock_wrlock(&filp->locker);
	filp->linked += 1;
	uv_rwlock_wrunlock(&filp->locker);
}

void mcl_filebuf_impl_close(mcl_filebuf_impl_t *filp)
{
	size_t linked;
	uv_file fd = -1;

	uv_rwlock_wrlock(&filp->locker);
	filp->linked -= 1;
	linked = filp->linked;
	uv_rwlock_wrunlock(&filp->locker);

	if (linked == 0) {
		if (filp->flags & MCL_FILEBUF_TMPFILE) {
			uv_fs_t fsreq;
			uv_fs_unlink(NULL, &fsreq, filp->path, NULL);
			uv_fs_req_cleanup(&fsreq);
		}
		else if (filp->wrlen != 0) {
			uv_buf_t wrbuf = uv_buf_init(filp->wrbuf, (unsigned int)filp->wrlen);
			mcl_filebuf_impl__write_file(&fd, filp, &wrbuf, 1, filp->wrpos);
			file_close(&fd, filp);
		}
		if (filp->rdbuf)
			free(filp->rdbuf);
		if (filp->wrbuf)
			free(filp->wrbuf);
		uv_rwlock_destroy(&filp->locker);
		free(filp);
	}
}


void mcl_filebuf_close(mcl_filebuf_t *fp)
{
	if (!fp->filp) {
		assert(0);
		return;
	}
	mcl_filebuf_impl_close(fp->filp);
	fp->filp = NULL;
}
int mcl_filebuf_open(mcl_filebuf_t *fp, const char *path, int flags)
{
	int err;

	err = mcl_filebuf_impl_open(&fp->filp, path, flags);
	if (err < 0)
		return err;

	fp->fpos = 0;
	return 0;
}
int mcl_filebuf_ref_from(mcl_filebuf_t *fp, const mcl_filebuf_t *from)
{
	fp->fpos = 0;
	fp->filp = from->filp;
	mcl_filebuf_impl_link(from->filp);
	return 0;
}
int mcl_filebuf_move_from(mcl_filebuf_t *fp, mcl_filebuf_t *from)
{
	fp->fpos = 0;
	fp->filp = from->filp;
	from->filp = NULL;
	return 0;
}
size_t mcl_filebuf_get_bufsize(mcl_filebuf_t *fp)
{
	return fp->filp->bufsize;
}
void mcl_filebuf_set_bufsize(mcl_filebuf_t *fp, size_t size)
{
	mcl_filebuf_impl_set_bufsize(fp->filp, size);
}
int mcl_filebuf_get_flags(mcl_filebuf_t *fp, int masks)
{
	return fp->filp->flags & masks;
}
void mcl_filebuf_set_flags(mcl_filebuf_t *fp, int masks, int flags)
{
	// rwlock.
	fp->filp->flags = (fp->filp->flags & ~masks) | (flags & masks);
	// rwunlock.
}

int64_t mcl_filebuf_get_size(const mcl_filebuf_t *fp)
{
	return fp->filp->size;
}
const char *mcl_filebuf_get_path(const mcl_filebuf_t *fp)
{
	return fp->filp->path;
}
ssize_t mcl_filebuf_read(mcl_filebuf_t *fp, void *buf, size_t count)
{
	return mcl_filebuf_impl_read(fp->filp, (char *)buf, count, &fp->fpos);
}
ssize_t mcl_filebuf_write(mcl_filebuf_t *fp, const void *buf, size_t count)
{
	return mcl_filebuf_impl_write(fp->filp, (char *)buf, count, &fp->fpos);
}
void mcl_filebuf_flush(const mcl_filebuf_t *fp)
{
	mcl_filebuf_impl_sync(fp->filp);
}

size_t mcl_filebuf_fread(void *buf, size_t size, size_t count, mcl_filebuf_t *fp)
{
	ssize_t r;
	r = mcl_filebuf_impl_read(fp->filp, (char *)buf, size * count, &fp->fpos);
	return r > 0 ? r / size : 0;
}
size_t mcl_filebuf_fwrite(const void *buf, size_t size, size_t count, mcl_filebuf_t *fp)
{
	ssize_t r;
	r = mcl_filebuf_impl_write(fp->filp, (char *)buf, size * count, &fp->fpos);
	return r > 0 ? r / size : 0;
}


/**************** uv extension. ****************/

//typedef struct { uv_work_t work_req; uv_fs_t *req; const char *path; int mode; uv_fs_cb cb; } uv_fs__req_t;
//static void uv_fs_mkdir_p__on_work(uv_work_t *req)
//{
//	uv_fs__req_t *fs_req;
//	char buf[512];
//	char *path = NULL;
//	int path_len;
//	int i, status;
//
//	fs_req = container_of(req, uv_fs__req_t, work_req);
//
//	status = uv_fs_access(req->loop, fs_req->req, fs_req->path, F_OK, NULL);
//	if (status == 0)
//		fs_req->req->result = UV_EEXIST;
//	else {
//		// copy the path to a new buffer.
//		path = buf;
//		path_len = (int)strlen(fs_req->path);
//		if (path_len >= (int)sizeof(buf)) {
//			path = malloc(path_len + 2);
//			if (path == NULL) {
//				fs_req->req->result = UV_ENOMEM;
//				goto endgame;
//			}
//		}
//
//		// 扫描路径，如果一个目录不存在就开始创建.
//		path[0] = fs_req->path[0];
//		for (i = 1; i < path_len; ++i) {
//
//			if (fs_req->path[i] == '/' || fs_req->path[i] == '\\') {
//				path[i] = '\0';
//				uv_fs_req_cleanup(fs_req->req);
//				status = uv_fs_access(req->loop, fs_req->req, path, F_OK, NULL);
//				if (status != 0) {
//					uv_fs_req_cleanup(fs_req->req);
//					status = uv_fs_mkdir(req->loop, fs_req->req, path, fs_req->mode, NULL);
//					if (status != 0)
//						goto endgame;
//				}
//			}
//			path[i] = fs_req->path[i];
//		}
//		path[i] = '\0';
//		if (path[i - 1] != '/' && path[i - 1] != '\\') {
//			uv_fs_req_cleanup(fs_req->req);
//			uv_fs_mkdir(req->loop, fs_req->req, path, fs_req->mode, NULL);
//		}
//	}
//
//endgame:
//	if (path && path != buf)
//		free(path);
//}
//static void uv_fs__after_work(uv_work_t *req, int status)
//{
//	uv_fs_t *cb_req;
//	uv_fs__req_t *fs_req;
//
//	fs_req = container_of(req, uv_fs__req_t, work_req);
//	cb_req = fs_req->req;
//
//	if (status == UV_ECANCELED) {
//		assert(cb_req->result == 0);
//		cb_req->result = UV_ECANCELED;
//	}
//
//	free(fs_req);
//	fs_req->cb(fs_req->req);
//}
//static int uv_fs_mkdir_p(uv_loop_t* loop, uv_fs_t* req, const char* path, int mode, uv_fs_cb cb)
//{
//	uv_fs__req_t *fs_req;
//	uv_fs__req_t the_fs_req;
//	int err = 0;
//
//	if (cb != NULL) {
//		fs_req = (uv_fs__req_t *)malloc(sizeof(uv_fs__req_t) + strlen(path) + 2);
//		if (fs_req == NULL)
//			return UV_ENOMEM;
//
//		fs_req->req = req;
//		fs_req->path = strcpy((char *)&fs_req[1], path);
//		fs_req->mode = mode;
//		fs_req->cb = cb;
//		fs_req->work_req.data = fs_req;
//		fs_req->work_req.loop = loop;
//
//		err = uv_queue_work(loop, &fs_req->work_req, uv_fs_mkdir_p__on_work, uv_fs__after_work);
//		if (err != 0)
//			free(fs_req);
//
//		return err;
//	}
//	else {
//		fs_req = &the_fs_req;
//
//		fs_req->req = req;
//		fs_req->path = path;
//		fs_req->mode = mode;
//		fs_req->cb = cb;
//		fs_req->work_req.data = fs_req;
//		fs_req->work_req.loop = loop;
//
//		uv_fs_mkdir_p__on_work(&fs_req->work_req);
//		return (int)req->result;
//	}
//}
//static int uv_fs_mkdir2_p(uv_loop_t* loop, uv_fs_t* req, const char* name, int mode, uv_fs_cb cb)
//{
//	int err = 0;
//	char buf[512];
//	char *dn = NULL;
//	const char *p1, *p2;
//
//	err = uv_fs_access(loop, req, name, F_OK, NULL);
//	if (err == 0)
//		return 0;
//
//	p1 = strrchr(name, '/');
//	p2 = strrchr(name, '\\');
//	if (p1 == NULL && p2 == NULL)
//		return 0;
//
//	if (p1 < p2)
//		p1 = p2;
//
//	dn = buf;
//	if (p1 - name >= (ssize_t)sizeof(buf)) {
//		dn = malloc(p1 - name + 2);
//		if (dn == NULL) {
//			req->result = UV_ENOMEM;
//			return UV_ENOMEM;
//		}
//	}
//
//	memcpy(dn, name, p1 - name);
//	dn[p1 - name] = 0;
//
//	uv_fs_req_cleanup(req);
//	err = uv_fs_mkdir_p(loop, req, dn, mode, cb);
//
//	if (dn && dn != buf)
//		free(dn);
//
//	return err;
//}

