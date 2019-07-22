
#include "loopex.h"
#include "defs.h"
#include "queue.h"


struct mcl_loopex__specific_s
{
	void *specific_queue[2];
	mcl_loopex_key_t *key;
	void *value;
};

static void *mcl__loopexs[2];
static uv_mutex_t mcl__loopexs_mutex;
static uv_once_t mcl_loopex__once_guard = UV_ONCE_INIT;

static void mcl_loopex__once_init(void)
{
	uv_loop_t loop;
	CHECK(0 == uv_loop_init(&loop));
	CHECK(0 == uv_loop_close(&loop));
	QUEUE_INIT(&mcl__loopexs);
	uv_mutex_init(&mcl__loopexs_mutex);
}

static void mcl_loopex__ref(mcl_loopex_t *r)
{
	if (!(r->pri_flags & MCL_HANDLE_ACTIVE)) {
		r->pri_flags |= MCL_HANDLE_ACTIVE;
		r->work_req.loop->active_reqs.count += 1;
	}
}
static void mcl_loopex__unref(mcl_loopex_t *r)
{
	if (r->pri_flags & MCL_HANDLE_ACTIVE) {
		r->pri_flags &= ~MCL_HANDLE_ACTIVE;
		r->work_req.loop->active_reqs.count -= 1;
	}
}

static void mcl_loopex__on_work(struct uv__work *w, int err)
{
	QUEUE n, *q;
	mcl_loopex_req_t *req;
	uv_loop_t *loop = w->loop;
	mcl_loopex_t *loopex = NULL;

	loopex = container_of(w, mcl_loopex_t, work_req);

	uv_mutex_lock(&loop->wq_mutex);
	QUEUE_MOVE(&loopex->wq, &n);
	QUEUE_INSERT_HEAD(&loop->wq, &loopex->work_req.wq);
	uv_mutex_unlock(&loop->wq_mutex);

	if (QUEUE_EMPTY(&n))
		mcl_loopex__unref(loopex);
	else {
		while (!QUEUE_EMPTY(&n)) {
			q = QUEUE_HEAD(&n);
			QUEUE_REMOVE(q);

			req = QUEUE_DATA(q, mcl_loopex_req_t, wq);
			if (req->cb)
				req->cb(req);
		}
		mcl_loopex__ref(loopex);
		uv_async_send(&loop->wq_async);
	}
}

static mcl_loopex_t *mcl_loopex_from_loop__find_wq(uv_loop_t *loop)
{
	QUEUE *q;
	struct uv__work *w;

	QUEUE_FOREACH(q, &loop->wq) {
		w = QUEUE_DATA(q, struct uv__work, wq);
		if (w->done == mcl_loopex__on_work)
			return container_of(w, mcl_loopex_t, work_req);
	}
	return NULL;
}
static mcl_loopex_t *mcl_loopex_from_loop__find_list(uv_loop_t *loop)
{
	QUEUE *q;
	mcl_loopex_t *loopex;

	QUEUE_FOREACH(q, &mcl__loopexs) {
		loopex = QUEUE_DATA(q, mcl_loopex_t, loopex_queue);
		if (loopex->work_req.loop == loop)
			return loopex;
	}
	return NULL;
}

mcl_loopex_t *mcl_loopex_from_loop(uv_loop_t *loop)
{
	mcl_loopex_t *loopex;
	uv_once(&mcl_loopex__once_guard, mcl_loopex__once_init);

	uv_mutex_lock(&loop->wq_mutex);
	loopex = mcl_loopex_from_loop__find_wq(loop);
	if (loopex == NULL) {
		uv_mutex_lock(&mcl__loopexs_mutex);
		loopex = mcl_loopex_from_loop__find_list(loop);
		uv_mutex_unlock(&mcl__loopexs_mutex);
	}
	uv_mutex_unlock(&loop->wq_mutex);

	return loopex;
}


int mcl_loopex_init(mcl_loopex_t *loopex, uv_loop_t *loop)
{
	uv_once(&mcl_loopex__once_guard, mcl_loopex__once_init);

	loopex->flags = 0;
	loopex->pri_flags = 0;
	loopex->wait_cb = NULL;
	QUEUE_INIT(&loopex->wq);
	QUEUE_INIT(&loopex->specific_queue);
	CHECK(0 == uv_cond_init(&loopex->wait_cond));

	loopex->work_req.loop = loop;
	loopex->work_req.work = NULL;
	loopex->work_req.done = mcl_loopex__on_work;

	uv_mutex_lock(&mcl__loopexs_mutex);
	QUEUE_INSERT_TAIL(&mcl__loopexs, &loopex->loopex_queue);
	uv_mutex_unlock(&mcl__loopexs_mutex);

	uv_mutex_lock(&loop->wq_mutex);
	QUEUE_INSERT_HEAD(&loop->wq, &loopex->work_req.wq);
	uv_mutex_unlock(&loop->wq_mutex);

	mcl_loopex__ref(loopex);
	uv_async_send(&loop->wq_async);

	return 0;
}

void mcl_loopex_destroy(mcl_loopex_t *loopex)
{
	QUEUE *q;
	struct mcl_loopex__specific_s *specific;;
	uv_loop_t *loop = loopex->work_req.loop;
	ASSERT(loopex->work_req.done == mcl_loopex__on_work);
	ASSERT(QUEUE_EMPTY(&loopex->wq));

	uv_mutex_lock(&loop->wq_mutex);
	QUEUE_REMOVE(&loopex->work_req.wq);
	uv_mutex_unlock(&loop->wq_mutex);

	uv_mutex_lock(&mcl__loopexs_mutex);
	QUEUE_REMOVE(&loopex->loopex_queue);
	uv_mutex_unlock(&mcl__loopexs_mutex);

	while (!QUEUE_EMPTY(&loopex->specific_queue)) {
		q = QUEUE_HEAD(&loopex->specific_queue);
		QUEUE_REMOVE(q);

		specific = QUEUE_DATA(q, struct mcl_loopex__specific_s, specific_queue);
		if (specific->key->destroy_cb && specific->value)
			specific->key->destroy_cb(specific->value);
		free(specific);
	}

	mcl_loopex__unref(loopex);
	uv_cond_destroy(&loopex->wait_cond);
	loopex->work_req.done = NULL;
}


int mcl_loopex_post(mcl_loopex_t *loopex, mcl_loopex_req_t *req, mcl_loopex_req_cb cb)
{
	uv_loop_t *loop = loopex->work_req.loop;
	ASSERT(loopex->work_req.done == mcl_loopex__on_work);

	uv_mutex_lock(&loop->wq_mutex);
	if (req != NULL) {
		req->loopex = loopex;
		req->cb = cb;
		QUEUE_INSERT_TAIL(&loopex->wq, &req->wq);
		uv_async_send(&loop->wq_async);
	}
	if (loopex->flags & MCL_WORKER_WAITING) {
		loopex->flags &= ~MCL_WORKER_WAITING;
		if (loopex->wait_cb)
			loopex->wait_cb(loopex, 1);
		uv_cond_broadcast(&loopex->wait_cond);
	}
	uv_mutex_unlock(&loop->wq_mutex);

	return 0;
}

void mcl_loopex_wait(mcl_loopex_t *loopex, mcl_loopex_wait_cb cb)
{
	uv_loop_t *loop = loopex->work_req.loop;
	ASSERT(loopex->work_req.done == mcl_loopex__on_work);

	uv_mutex_lock(&loop->wq_mutex);
	if (QUEUE_EMPTY(&loopex->wq)) {
		loopex->flags |= MCL_WORKER_WAITING;
		loopex->wait_cb = cb;
		if (loopex->wait_cb)
			loopex->wait_cb(loopex, 0);
		uv_cond_wait(&loopex->wait_cond, &loop->wq_mutex);
	}
	if (!QUEUE_EMPTY(&loopex->wq))
		mcl_loopex__ref(loopex);
	uv_mutex_unlock(&loop->wq_mutex);
}

uv_loop_t *mcl_loopex_get_loop(mcl_loopex_t *loopex)
{
	return loopex->work_req.loop;
}

static struct mcl_loopex__specific_s *mcl_loopex__getspecific(mcl_loopex_t *loopex, mcl_loopex_key_t *key)
{
	QUEUE *q;
	struct mcl_loopex__specific_s *specific;
	QUEUE_FOREACH(q, &loopex->specific_queue) {
		specific = QUEUE_DATA(q, struct mcl_loopex__specific_s, specific_queue);
		if (specific->key == key)
			return specific;
	}
	return NULL;
}
void *mcl_loopex_getspecific(mcl_loopex_t *loopex, mcl_loopex_key_t *key)
{
	struct mcl_loopex__specific_s *specific;
	specific = mcl_loopex__getspecific(loopex, key);
	return specific ? specific->value : NULL;
}
int mcl_loopex_setspecific(mcl_loopex_t *loopex, mcl_loopex_key_t *key, void *value)
{
	struct mcl_loopex__specific_s *specific;
	specific = mcl_loopex__getspecific(loopex, key);
	if (specific == NULL) {
		specific = malloc(sizeof(struct mcl_loopex__specific_s));
		if (specific == NULL)
			return UV_ENOMEM;
		specific->key = key;
		QUEUE_INSERT_HEAD(&loopex->specific_queue, &specific->specific_queue);
	}
	specific->value = value;
	return 0;
}
void mcl_loopex_key_init(mcl_loopex_key_t *key, void(*destroy_cb)(void *))
{
	key->destroy_cb = destroy_cb;
}



static void mcl_worker__on_async_close(uv_handle_t *handle)
{
	mcl_worker_t *contex;
	contex = container_of(handle, mcl_worker_t, async);

	mcl_loopex_destroy(&contex->loopex);
	CHECK(0 == uv_thread_join(&contex->thread));
	CHECK(0 == uv_run(&contex->loop, UV_RUN_NOWAIT));
	CHECK(0 == uv_loop_close(&contex->loop));
	uv_mutex_destroy(&contex->mutex);

	if (contex->close_cb)
		contex->close_cb(contex);
}

static void mcl_worker__on_async(uv_async_t *async)
{
	unsigned int flags;
	mcl_worker_t *contex;
	contex = container_of(async, mcl_worker_t, async);

	uv_mutex_lock(&contex->mutex);
	flags = contex->flags;
	if (contex->flags & MCL_WORKER_THREAD_REF)
		contex->flags &= ~MCL_WORKER_THREAD_REF;
	uv_mutex_unlock(&contex->mutex);

	if (flags & MCL_HANDLE_CLOSED) {
		uv_close((uv_handle_t *)async, mcl_worker__on_async_close);
	}
	else if (flags & MCL_WORKER_THREAD_REF) {
		if (!uv_has_ref((uv_handle_t *)async))
			uv_ref((uv_handle_t *)async);
		if (flags & MCL_WORKER_THREAD_UNREF)
			uv_async_send(async);
	}
	else if (flags & MCL_WORKER_THREAD_UNREF) {
		if (uv_has_ref((uv_handle_t *)async))
			uv_unref((uv_handle_t *)async);
	}
}

static void mcl_worker__wait_cb(mcl_loopex_t *worker, int status)
{
	mcl_worker_t *contex;
	contex = container_of(worker, mcl_worker_t, loopex);

	uv_mutex_lock(&contex->mutex);
	if (status == 0)
		contex->flags |= MCL_WORKER_THREAD_UNREF;
	else {
		contex->flags |= MCL_WORKER_THREAD_REF;
		contex->flags &= ~MCL_WORKER_THREAD_UNREF;
	}
	uv_async_send(&contex->async);
	uv_mutex_unlock(&contex->mutex);
}

static void mcl_worker__on_thread(void *arg)
{
	mcl_worker_t *contex = (mcl_worker_t *)arg;
	mcl_loopex_t *worker = mcl_worker_get_loopex(contex);

	uv_mutex_lock(&contex->mutex);
	while (!(contex->flags & MCL_HANDLE_CLOSING)) {
		uv_mutex_unlock(&contex->mutex);
		mcl_loopex_wait(worker, mcl_worker__wait_cb);

		while (uv_run(&contex->loop, UV_RUN_DEFAULT))
			fprintf(stderr, "The event loop was accidentally interrupted, the pointer of loop is %p.\n", &contex->loop);

		uv_mutex_lock(&contex->mutex);
	}
	contex->flags |= MCL_HANDLE_CLOSED;
	uv_async_send(&contex->async);
	uv_mutex_unlock(&contex->mutex);
}


int mcl_worker_init(mcl_worker_t *contex, uv_loop_t *loop)
{
	contex->flags = 0;
	contex->close_cb = NULL;

	CHECK(0 == uv_loop_init(&contex->loop));
	CHECK(0 == mcl_loopex_init(&contex->loopex, &contex->loop));
	CHECK(0 == uv_async_init(loop, &contex->async, mcl_worker__on_async));
	CHECK(0 == uv_mutex_init(&contex->mutex));
	CHECK(0 == uv_thread_create(&contex->thread, mcl_worker__on_thread, contex));

	return 0;
}

void mcl_worker_close(mcl_worker_t *contex, mcl_worker_cb cb)
{
	ASSERT(!(contex->flags & MCL_HANDLE_CLOSING));
	contex->close_cb = cb;

	uv_mutex_lock(&contex->mutex);
	contex->flags |= MCL_HANDLE_CLOSING;
	uv_mutex_unlock(&contex->mutex);

	uv_ref((uv_handle_t *)&contex->async);
	mcl_loopex_post(mcl_worker_get_loopex(contex), NULL, NULL);
}

mcl_loopex_t *mcl_worker_get_loopex(mcl_worker_t *contex)
{
	return &contex->loopex;
}
