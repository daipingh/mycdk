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
#include "mcl/loopex.h"

#include <time.h>


static mcl_loopex_t default_worker_struct;
static mcl_worker_t *workers = NULL;
static unsigned int nworkers = 0;
static unsigned int round_robin_counter = 0;


static void fps_setup_workers__on_start(mcl_loopex_req_t *req)
{
	uv_sem_post((uv_sem_t *)req->data);
}

void fps_setup_workers(uv_loop_t *loop)
{
	int cpu_count;
	unsigned int i;
	mcl_loopex_req_t req;
	uv_sem_t sem;
	uv_cpu_info_t *info;

	if (uv_sem_init(&sem, 0))
		abort();

	if (mcl_loopex_init(&default_worker_struct, loop))
		abort();

	uv_cpu_info(&info, &cpu_count);
	uv_free_cpu_info(info, cpu_count);
	nworkers = cpu_count + 10;
	workers = (mcl_worker_t *)calloc(sizeof(mcl_worker_t), nworkers);

	for (i = 0; i < nworkers; ++i) {
		mcl_loopex_t *worker;

		if (mcl_worker_init(&workers[i], loop))
			abort();

		worker = mcl_worker_get_loopex(&workers[i]);
		req.data = &sem;
		if (mcl_loopex_post(worker, &req, fps_setup_workers__on_start))
			abort();

		uv_sem_wait(&sem);
	}

	uv_sem_destroy(&sem);
}
mcl_loopex_t *fps_default_worker()
{
	return &default_worker_struct;
}
mcl_loopex_t *fps_shared_worker()
{
	mcl_loopex_t *worker;

	worker = &workers[round_robin_counter].loopex;
	round_robin_counter = (round_robin_counter + 1) % nworkers;

	return worker;
}
void fps_cleanup_workers()
{
	unsigned int i;

	mcl_loopex_destroy(&default_worker_struct);
	for (i = 0; i < nworkers; ++i) {
		mcl_worker_close(&workers[i], NULL);
	}
}


typedef struct {
	mcl_loopex_req_t req;
	int count;
	int max_count;
	int sum_count;
	char name[32];
} test_job;

void do_job(mcl_loopex_req_t *req)
{
	mcl_loopex_t *wk = req->loopex;
	test_job *job = container_of(req, test_job, req);

	if (job->count % 5 == 0)
		uv_sleep(1);
	job->sum_count += job->count;

	if (job->count < job->max_count) {
		job->count += 1;
		wk = fps_shared_worker();
		mcl_loopex_post(wk, req, do_job);
	}
	else {
		printf("job done %d\n", job->sum_count);
	}
}


static uv_loop_t *loop;
static uint64_t run_test(test_job *job, int count)
{
	int r;
	uint64_t hrtime;

	hrtime = uv_hrtime();
	for (r = 0; r < count; ++r) {
		job[r].count = 1000 / count * r;
		job[r].max_count = 1000 / count * (r + 1);
		job[r].sum_count = 0;
		mcl_loopex_post(fps_default_worker(), &job[r].req, do_job);
	}
	mcl_loopex_wait(fps_default_worker(), NULL);
	r = uv_run(loop, UV_RUN_DEFAULT);
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

	for (r = 0; r < ARRAY_SIZE(job); r += 3) {
		uint64_t hrtime0 = run_test(job, r + 1);
		uint64_t hrtime1 = run_test(job, r + 1);
		uint64_t hrtime2 = run_test(job, r + 1);
		hrtime[r] = (hrtime0 + hrtime1 + hrtime2) / 3;
	}
	for (r = 0; r < ARRAY_SIZE(job); r += 3)
		printf("%llu\n", hrtime[r]);
	
	uv_sleep(500);
	fps_cleanup_workers();
	r = uv_run(loop, UV_RUN_DEFAULT);
	printf("======uv_run: %d\n", r);

	r = uv_loop_close(loop);
	printf("======final result: %d\n", r);
	ASSERT(r == 0);
	MAKE_VALGRIND_HAPPY();
	return 0;
}
