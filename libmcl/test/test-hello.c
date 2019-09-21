/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "uv.h"
#include "task.h"
#include "mcl/worker.h"

#include <time.h>


static mcl_worker_t *workers = NULL;
static unsigned int nworkers = 0;
static unsigned int round_robin_counter = 0;


static void fps_setup_workers__on_start(mcl_work_t *req)
{
	uv_sem_post((uv_sem_t *)req->data);
}

void fps_setup_workers(uv_loop_t *loop)
{
	int cpu_count;
	unsigned int i;
	mcl_work_t req;
	uv_sem_t sem;
	uv_cpu_info_t *info;

	if (uv_sem_init(&sem, 0))
		abort();

	uv_cpu_info(&info, &cpu_count);
	uv_free_cpu_info(info, cpu_count);
	nworkers = cpu_count + 10;
	workers = (mcl_worker_t *)calloc(sizeof(mcl_worker_t), nworkers);

	for (i = 0; i < nworkers; ++i) {
		mcl_worker_t *worker;

		if (mcl_worker_init(&workers[i], loop))
			abort();

		worker = &workers[i];
		req.data = &sem;
		if (mcl_worker_post(worker, &req, fps_setup_workers__on_start))
			abort();

		uv_sem_wait(&sem);
	}

	uv_sem_destroy(&sem);
}
mcl_worker_t *fps_shared_worker()
{
	mcl_worker_t *worker;

	worker = &workers[round_robin_counter];
	round_robin_counter = (round_robin_counter + 1) % nworkers;

	return worker;
}
void fps_cleanup_workers()
{
	unsigned int i;

	for (i = 0; i < nworkers; ++i) {
		mcl_worker_close(&workers[i], NULL);
	}
}



typedef struct {
	mcl_work_t req;
	int count;
	int max_count;
	int sum_count;
	char name[32];
} test_job;

void do_job(mcl_work_t *req)
{
	mcl_worker_t *wk = req->worker;
	test_job *job = container_of(req, test_job, req);

	//if (job->count % 5 == 0)
	//	uv_sleep(1);
	job->sum_count += job->count;

	if (job->count < job->max_count) {
		job->count += 1;
		wk = fps_shared_worker();
		mcl_worker_post(wk, req, do_job);
	}
}

static void on_async(uv_async_t *async)
{
	uv_close((uv_handle_t *)async, NULL);
}

static uv_loop_t *loop;
static uint64_t run_test(test_job *job, int count)
{
	int r;
	uint64_t hrtime;
	mcl_worker_t *worker;
	uv_async_t async;
	int s = 0;

	hrtime = uv_hrtime();
	for (r = 0; r < count; ++r) {
		job[r].count = 1000 / count * r;
		job[r].max_count = 1000 / count * (r + 1);
		job[r].sum_count = 0;
		worker = fps_shared_worker();
		mcl_worker_post(worker, &job[r].req, do_job);
	}

	uv_async_init(loop, &async, on_async);
	uv_async_send(&async);
	uv_run(loop, UV_RUN_DEFAULT);

	for (r = 0; r < count; ++r) {
		if (job[r].count != job[r].max_count) {
			s += 1;
			printf("job %d padding, %d/%d\n", r, job[r].count, job[r].max_count);
		}
	}
	ASSERT(s == 0);
	return uv_hrtime() - hrtime;
}





TEST_IMPL(hello)
{
	int r;
	test_job job[16];
	uint64_t hrtime[16];

	loop = uv_default_loop();
	fps_setup_workers(loop);
	srand((unsigned int)time(0));

	for (r = 1; r <= ARRAY_SIZE(job); r *= 2) {
		uint64_t hrtime0 = run_test(job, r);
		uint64_t hrtime1 = run_test(job, r);
		uint64_t hrtime2 = run_test(job, r);
		hrtime[r - 1] = (hrtime0 + hrtime1 + hrtime2) / 3;
	}
	for (r = 1; r <= ARRAY_SIZE(job); r *= 2)
		printf("%d: %llu\n", r, hrtime[r - 1]);
	
	//uv_sleep(500);
	fps_cleanup_workers();
	r = uv_run(loop, UV_RUN_DEFAULT);
	printf("======uv_run: %d\n", r);

	r = uv_loop_close(loop);
	printf("======final result: %d\n", r);
	ASSERT(r == 0);
	MAKE_VALGRIND_HAPPY();
	return 0;
}
