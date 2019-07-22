
#ifndef MCL_WORKER_H_
#define MCL_WORKER_H_

#include "lang.h"
#include <uv.h>
#include <uv/tree.h>


MCL_BEGIN_EXTERN_C

typedef struct mcl_loopex_s mcl_loopex_t;
typedef struct mcl_loopex_req_s mcl_loopex_req_t;
typedef struct mcl_loopex_key_s mcl_loopex_key_t;
typedef void(*mcl_loopex_req_cb)(mcl_loopex_req_t *req);
typedef void(*mcl_loopex_wait_cb)(mcl_loopex_t *loopex, int status);


struct mcl_loopex_s
{
	struct uv__work work_req;
	unsigned int flags;
	unsigned int pri_flags;
	void *wq[2];
	void *loopex_queue[2];
	mcl_loopex_wait_cb wait_cb;
	uv_cond_t wait_cond;
	void *specific_queue[2];
};

struct mcl_loopex_req_s
{
	void *wq[2];
	mcl_loopex_t *loopex;
	mcl_loopex_req_cb cb;
	void *data;
};

struct mcl_loopex_key_s
{
	void(*destroy_cb)(void *);
};

MCL_APIDECL int mcl_loopex_init(mcl_loopex_t *loopex, uv_loop_t *loop);
MCL_APIDECL int mcl_loopex_post(mcl_loopex_t *loopex, mcl_loopex_req_t *req, mcl_loopex_req_cb cb);
MCL_APIDECL void mcl_loopex_wait(mcl_loopex_t *loopex, mcl_loopex_wait_cb cb);
MCL_APIDECL void mcl_loopex_destroy(mcl_loopex_t *loopex);

MCL_APIDECL void mcl_loopex_key_init(mcl_loopex_key_t *key, void(*destroy_cb)(void *));
MCL_APIDECL int mcl_loopex_setspecific(mcl_loopex_t *loopex, mcl_loopex_key_t *key, void *value);
MCL_APIDECL void *mcl_loopex_getspecific(mcl_loopex_t *loopex, mcl_loopex_key_t *key);

MCL_APIDECL uv_loop_t *mcl_loopex_get_loop(mcl_loopex_t *loopex);
MCL_APIDECL mcl_loopex_t *mcl_loopex_from_loop(uv_loop_t *loop);


typedef struct mcl_worker_s mcl_worker_t;
typedef void(*mcl_worker_cb)(mcl_worker_t *contex);

struct mcl_worker_s
{
	mcl_loopex_t loopex;
	mcl_worker_cb close_cb;
	unsigned int flags;
	uv_loop_t loop;
	uv_async_t async;
	uv_mutex_t mutex;
	uv_thread_t thread;
};

MCL_APIDECL int mcl_worker_init(mcl_worker_t *contex, uv_loop_t *loop);
MCL_APIDECL void mcl_worker_close(mcl_worker_t *contex, mcl_worker_cb cb);
MCL_APIDECL mcl_loopex_t *mcl_worker_get_loopex(mcl_worker_t *contex);


MCL_END_EXTERN_C
#endif
