
#include "worker.h"
#include "defs.h"
#include "queue.h"


static void mcl_worker__on_async_close(uv_handle_t *handle)
{
	mcl_worker_t *worker = container_of(handle, mcl_worker_t, async);
	ASSERT(QUEUE_EMPTY(&worker->wq));

	uv_cond_destroy(&worker->wq_cond);
	uv_close((uv_handle_t *)&worker->wq_async, NULL);
	CHECK(0 == uv_run(&worker->wq_loop, UV_RUN_NOWAIT));
	CHECK(0 == uv_loop_close(&worker->wq_loop));
	CHECK(0 == uv_thread_join(&worker->thread));
	uv_mutex_destroy(&worker->mutex);

	if (worker->close_cb)
		worker->close_cb(worker);
}

static void mcl_worker__on_async(uv_async_t *async)
{
	mcl_worker_t *worker = container_of(async, mcl_worker_t, async);

	uv_mutex_lock(&worker->mutex);
	if (worker->f_closed) {
		uv_close((uv_handle_t *)async, mcl_worker__on_async_close);
	}
	else if (worker->f_ref) {
		worker->f_ref = 0;
		uv_ref((uv_handle_t *)async);
		uv_async_send(&worker->async);
	}
	else if (worker->f_waiting) {
		if (worker->f_unref) {
			uv_unref((uv_handle_t *)async);
		}
		else {
			worker->f_unref = 1;
			uv_async_send(&worker->async);
		}
	}
	uv_mutex_unlock(&worker->mutex);
}

static void mcl_worker__on_thread(void *arg)
{
	mcl_worker_t *worker = (mcl_worker_t *)arg;

	uv_mutex_lock(&worker->mutex);
	while (1) {
		if (QUEUE_EMPTY(&worker->wq)) {
			if (worker->f_closing) {
				worker->f_closed = 1;
				uv_async_send(&worker->async);
				break;
			}
			else {
				worker->f_waiting = 1;
				uv_async_send(&worker->async);
				uv_cond_wait(&worker->wq_cond, &worker->mutex);
			}
		}
		if (!QUEUE_EMPTY(&worker->wq))
			uv_ref((uv_handle_t *)&worker->wq_async);
		uv_mutex_unlock(&worker->mutex);

		while (uv_run(&worker->wq_loop, UV_RUN_DEFAULT))
			fprintf(stderr, "The event loop was accidentally interrupted, the pointer of loop is %p.\n", &worker->wq_loop);

		uv_mutex_lock(&worker->mutex);
	}
	uv_mutex_unlock(&worker->mutex);
}


static void mcl_worker__on_wq_async(uv_async_t *async)
{
	mcl_work_t *work;
	mcl_worker_t *worker = container_of(async, mcl_worker_t, wq_async);
	QUEUE n;

	uv_mutex_lock(&worker->mutex);
	QUEUE_MOVE(&worker->wq, &n);
	uv_mutex_unlock(&worker->mutex);

	while (!QUEUE_EMPTY(&n)) {
		work = QUEUE_DATA(QUEUE_HEAD(&n), mcl_work_t, wq);
		QUEUE_REMOVE(&work->wq);
		if (work->cb)
			work->cb(work);
	}
	uv_unref((uv_handle_t *)&worker->wq_async);
}


int mcl_worker_init(mcl_worker_t *worker, uv_loop_t *loop)
{
	worker->f_closing = 0;
	worker->f_closed = 0;
	worker->f_waiting = 0;
	worker->f_ref = 0;
	worker->f_unref = 0;

	QUEUE_INIT(&worker->wq);
	CHECK(0 == uv_cond_init(&worker->wq_cond));
	CHECK(0 == uv_loop_init(&worker->wq_loop));
	CHECK(0 == uv_async_init(&worker->wq_loop, &worker->wq_async, mcl_worker__on_wq_async));
	uv_unref((uv_handle_t *)&worker->wq_async);

	worker->close_cb = NULL;
	CHECK(0 == uv_mutex_init(&worker->mutex));
	CHECK(0 == uv_async_init(loop, &worker->async, mcl_worker__on_async));
	CHECK(0 == uv_thread_create(&worker->thread, mcl_worker__on_thread, worker));

	return 0;
}

int mcl_worker_post(mcl_worker_t *worker, mcl_work_t *work, mcl_work_cb cb)
{
	ASSERT(!worker->f_closing);
	uv_mutex_lock(&worker->mutex);

	work->cb = cb;
	work->worker = worker;
	QUEUE_INSERT_TAIL(&worker->wq, &work->wq);
	uv_async_send(&worker->wq_async);

	if (worker->f_waiting) {
		worker->f_waiting = 0;
		worker->f_unref = 0;
		worker->f_ref = 1;
		uv_async_send(&worker->async);
		uv_cond_broadcast(&worker->wq_cond);
	}

	uv_mutex_unlock(&worker->mutex);
	return 0;
}

void mcl_worker_close(mcl_worker_t *worker, mcl_worker_cb cb)
{
	ASSERT(!worker->f_closing);
	uv_mutex_lock(&worker->mutex);

	worker->close_cb = cb;
	worker->f_closing = 1;

	if (worker->f_waiting) {
		worker->f_waiting = 0;
		worker->f_unref = 0;
		worker->f_ref = 1;
		uv_ref((uv_handle_t *)&worker->async);
		uv_cond_broadcast(&worker->wq_cond);
	}
	uv_mutex_unlock(&worker->mutex);
}

uv_loop_t *mcl_worker_get_loop(mcl_worker_t *worker)
{
	return &worker->wq_loop;
}
