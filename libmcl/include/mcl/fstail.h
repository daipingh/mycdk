
#ifndef MCL_FSTAIL_H_
#define MCL_FSTAIL_H_

#include "lang.h"
#include <uv.h>


MCL_BEGIN_EXTERN_C

typedef struct mcl_fstail_s mcl_fstail_t;
typedef void(*mcl_fstail_cb)(mcl_fstail_t *handle, const char *buf, ssize_t len);
typedef void(*mcl_fstail_close_cb)(mcl_fstail_t *handle);

struct mcl_fstail_s
{
	uv_fs_poll_t poll;
	size_t nrefs;
	mcl_fstail_cb cb;
	mcl_fstail_close_cb close_cb;
	void *ctx;
};

MCL_APIDECL int mcl_fstail_init(mcl_fstail_t *handle, uv_loop_t *loop);
MCL_APIDECL void mcl_fstail_close(mcl_fstail_t *handle, mcl_fstail_close_cb close_cb);
MCL_APIDECL int mcl_fstail_stop(mcl_fstail_t *handle);
MCL_APIDECL int mcl_fstail_start(mcl_fstail_t *handle, mcl_fstail_cb cb, const char *path, unsigned int interval);


MCL_END_EXTERN_C
#endif
