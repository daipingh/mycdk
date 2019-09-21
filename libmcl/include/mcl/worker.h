
#ifndef MCL_WORKER_H_
#define MCL_WORKER_H_

#include "lang.h"
#include <uv.h>


MCL_BEGIN_EXTERN_C

typedef struct mcl_work_s mcl_work_t;
typedef void(*mcl_work_cb)(mcl_work_t *work);
typedef struct mcl_worker_s mcl_worker_t;
typedef void(*mcl_worker_cb)(mcl_worker_t *worker);

struct mcl_work_s
{
	void *wq[2];
	mcl_work_cb cb;
	mcl_worker_t *worker;
	void *data;
};

struct mcl_worker_s
{
	unsigned short f_closing;
	unsigned short f_closed;
	unsigned short f_waiting;
	unsigned short f_ref;
	unsigned short f_unref;
	unsigned short f_reserved;

	void *wq[2];
	uv_cond_t wq_cond;
	uv_loop_t wq_loop;
	uv_async_t wq_async;

	mcl_worker_cb close_cb;
	uv_mutex_t mutex;
	uv_async_t async;
	uv_thread_t thread;
};

MCL_APIDECL int mcl_worker_init(mcl_worker_t *worker, uv_loop_t *loop);
MCL_APIDECL int mcl_worker_post(mcl_worker_t *worker, mcl_work_t *work, mcl_work_cb cb);
MCL_APIDECL void mcl_worker_close(mcl_worker_t *worker, mcl_worker_cb cb);
MCL_APIDECL uv_loop_t *mcl_worker_get_loop(mcl_worker_t *worker);

MCL_END_EXTERN_C
#endif
