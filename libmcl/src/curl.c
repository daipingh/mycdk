
#include "curl.h"
#include "defs.h"
#include <stdlib.h>
#include "queue.h"


typedef struct {
	uv_poll_t poll_handle;
	curl_socket_t sockfd;
	mcl_curlm_t *curlm;
	void *list_to[2];
} poll_context_t;


static poll_context_t *poll_context_create(mcl_curlm_t *curlm, curl_socket_t sockfd)
{
	int err;
	poll_context_t *context;

	context = (poll_context_t *)malloc(sizeof(*context));
	if (context == NULL)
		return NULL;

	context->sockfd = sockfd;
	context->curlm = curlm;
	err = uv_poll_init_socket(curlm->loop, &context->poll_handle, sockfd);
	if (err != 0) {
		free(context);
		return NULL;
	}

	//context->poll_handle.data = context;
	return context;
}
static void poll_context__on_poll_close(uv_handle_t *handle)
{
	free(container_of(handle, poll_context_t, poll_handle));
}
static void poll_context_destroy(poll_context_t *context)
{
	uv_close((uv_handle_t *)&context->poll_handle, poll_context__on_poll_close);
}


static void check_multi_info(mcl_curlm_t *curlm)
{
	int pending;
	int result;
	CURLMsg *message;
	CURL *handle;
	mcl_curl_t *curl;

	while ((message = curl_multi_info_read(curlm->handle, &pending)) != NULL) {
		switch (message->msg) {
		case CURLMSG_DONE:
			/* Do not use message data after calling curl_multi_remove_handle() and
			   curl_easy_cleanup(). As per curl_multi_info_read() docs:
			   "WARNING: The data the returned pointer points to will not survive
			   calling curl_multi_cleanup, curl_multi_remove_handle or
			   curl_easy_cleanup." */
			handle = message->easy_handle;
			result = message->data.result;

			curl = NULL;
			curl_easy_getinfo(handle, CURLINFO_PRIVATE, &curl);
			CHECK(curl && curl->handle == handle);

			QUEUE_REMOVE(&curl->list_to);
			QUEUE_INIT(&curl->list_to);
			curl_multi_remove_handle(curlm->handle, curl->handle);
			curlm->active_cnt -= 1;

			curl->perform_cb(curl, result);
			break;

		default:
			fprintf(stderr, "CURLMSG default\n");
			break;
		}
	}
}


static void curl_perform(uv_poll_t *handle, int status, int events)
{
	int running_handles;
	int flags = 0;
	poll_context_t *context = container_of(handle, poll_context_t, poll_handle);
	ASSERT(context->curlm != NULL);

	if (events & UV_READABLE)
		flags |= CURL_CSELECT_IN;
	if (events & UV_WRITABLE)
		flags |= CURL_CSELECT_OUT;

	curl_multi_socket_action(context->curlm->handle, context->sockfd, flags, &running_handles);
	check_multi_info(context->curlm);
}
static int handle_socket(CURL *easy, curl_socket_t s, int action, void *userp, void *socketp)
{
	int events = 0;
	mcl_curlm_t *curlm = (mcl_curlm_t *)userp;
	poll_context_t *poll_context = (poll_context_t *)socketp;
	ASSERT(curlm != NULL);

	switch (action) {
	case CURL_POLL_IN:
	case CURL_POLL_OUT:
	case CURL_POLL_INOUT:
		if (poll_context == NULL) {
			poll_context = poll_context_create(curlm, s);
			if (poll_context == NULL)
				return -1;
			curl_multi_assign(curlm->handle, s, poll_context);
			QUEUE_INSERT_TAIL(&curlm->context_list, &poll_context->list_to);
		}

		if (action != CURL_POLL_IN)
			events |= UV_WRITABLE;
		if (action != CURL_POLL_OUT)
			events |= UV_READABLE;

		uv_poll_start(&poll_context->poll_handle, events, curl_perform);
		break;

	case CURL_POLL_REMOVE:
		if (poll_context != NULL) {
			uv_poll_stop(&poll_context->poll_handle);
			QUEUE_REMOVE(&poll_context->list_to);
			curl_multi_assign(curlm->handle, s, NULL);
			poll_context_destroy(poll_context);
		}
		break;

	default:
		abort();
	}

	return 0;
}


static void on_timeout(uv_timer_t *timer)
{
	int running_handles;
	mcl_curlm_t *curlm = container_of(timer, mcl_curlm_t, timer);

	curl_multi_socket_action(curlm->handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
	check_multi_info(curlm);
}
static int start_timeout(CURLM *multi, long timeout_ms, void *userp)
{
	mcl_curlm_t *curlm = (mcl_curlm_t *)userp;
	ASSERT(curlm->handle == multi);

	if (timeout_ms < 0)
		uv_timer_stop(&curlm->timer);
	else
		uv_timer_start(&curlm->timer, on_timeout, timeout_ms > 1 ? timeout_ms : 1, 0);

	return 0;
}


int mcl_curl_init(mcl_curl_t *curl)
{
	curl->curlm = NULL;
	curl->perform_cb = NULL;
	QUEUE_INIT(&curl->list_to);

	curl->private_data = NULL;
	curl->handle = curl_easy_init();
	if (curl->handle == NULL)
		return CURLE_FAILED_INIT;

	curl_easy_setopt(curl->handle, CURLOPT_PRIVATE, curl);
	return 0;
}

void mcl_curl_cleanup(mcl_curl_t *curl)
{
	if (curl->handle == NULL)
		return;

	if (!QUEUE_EMPTY(&curl->list_to)) {
		QUEUE_REMOVE(&curl->list_to);
		QUEUE_INIT(&curl->list_to);
		curl_multi_remove_handle(curl->curlm->handle, curl->handle);
		curl->curlm->active_cnt -= 1;
	}
	curl_easy_cleanup(curl->handle);
	curl->handle = NULL;
}

int mcl_curl_perform(mcl_curl_t *curl, mcl_curlm_t *curlm, mcl_curl_perform_cb cb)
{
	int err;
	ASSERT(curl && curl->handle);

	if (cb == NULL)
		err = curl_easy_perform(curl->handle);
	else {
		ASSERT(curlm && curlm->handle);
		err = curl_multi_add_handle(curlm->handle, curl->handle);
		if (err == 0) {
			curl->curlm = curlm;
			curl->perform_cb = cb;
			QUEUE_INSERT_TAIL(&curlm->curl_list, &curl->list_to);
			curlm->active_cnt += 1;
		}
	}
	return err;
}

CURL *mcl_curl_get_handle(mcl_curl_t *curl)
{
	return curl->handle;
}

int mcl_curl_setopt_private(mcl_curl_t *curl, CURLoption opt, ...)
{
	va_list argv;
	va_start(argv, opt);

	switch (opt) {
	case CURLOPT_PRIVATE:
		curl->private_data = va_arg(argv, void *);
		break;
	default:
		abort();
		break;
	}

	va_end(argv);
	return 0;
}
int mcl_curl_getinfo_private(mcl_curl_t *curl, CURLINFO info, ...)
{
	va_list argv;
	va_start(argv, info);

	switch (info) {
	case CURLINFO_PRIVATE:
		*(va_arg(argv, void **)) = curl->private_data;
		break;
	default:
		abort();
		break;
	}

	va_end(argv);
	return 0;
}


static void mcl__curlm__check_close(mcl_curlm_t *curlm)
{
	ASSERT(curlm->active_cnt > 0);
	curlm->active_cnt -= 1;
	if (curlm->active_cnt == 0) {
		if (curlm->close_cb)
			curlm->close_cb(curlm);
	}
}
static void mcl_curlm__on_check_close(uv_handle_t *handle)
{
	mcl__curlm__check_close(container_of(handle, mcl_curlm_t, check));
}
static void mcl_curlm__on_timer_close(uv_handle_t *handle)
{
	mcl__curlm__check_close(container_of(handle, mcl_curlm_t, timer));
}

static void mcl_curlm__on_check(uv_check_t *check)
{
	mcl_curl_t *curl;
	poll_context_t *context;
	mcl_curlm_t *curlm = container_of(check, mcl_curlm_t, check);

	if (curlm->closing) {
		while (!QUEUE_EMPTY(&curlm->curl_list)) {
			curl = QUEUE_DATA(QUEUE_HEAD(&curlm->curl_list), mcl_curl_t, list_to);
			QUEUE_REMOVE(&curl->list_to);
			QUEUE_INIT(&curl->list_to);
			curl_multi_remove_handle(curlm->handle, curl->handle);
			curlm->active_cnt -= 1;

			curl->perform_cb(curl, CURLE_ABORTED_BY_CALLBACK);
		}
		ASSERT(curlm->active_cnt == 0);
		curl_multi_cleanup(curlm->handle);
		curlm->handle = NULL;

		while (!QUEUE_EMPTY(&curlm->context_list)) {
			context = QUEUE_DATA(QUEUE_HEAD(&curlm->context_list), poll_context_t, list_to);
			QUEUE_REMOVE(&context->list_to);
			poll_context_destroy(context);
		}
		curlm->active_cnt = 2;
		uv_close((uv_handle_t *)&curlm->check, mcl_curlm__on_check_close);
		uv_close((uv_handle_t *)&curlm->timer, mcl_curlm__on_timer_close);
	}
}

int mcl_curlm_init(mcl_curlm_t *curlm, uv_loop_t *loop)
{
	curlm->closing = 0;
	curlm->active_cnt = 0;
	curlm->loop = loop;
	QUEUE_INIT(&curlm->curl_list);
	QUEUE_INIT(&curlm->context_list);

	curlm->handle = curl_multi_init();
	if (curlm->handle == NULL)
		return CURLE_FAILED_INIT;

	uv_timer_init(loop, &curlm->timer);
	uv_check_init(loop, &curlm->check);

	curl_multi_setopt(curlm->handle, CURLMOPT_SOCKETDATA, curlm);
	curl_multi_setopt(curlm->handle, CURLMOPT_SOCKETFUNCTION, handle_socket);
	curl_multi_setopt(curlm->handle, CURLMOPT_TIMERDATA, curlm);
	curl_multi_setopt(curlm->handle, CURLMOPT_TIMERFUNCTION, start_timeout);

	return 0;
}

void mcl_curlm_close(mcl_curlm_t *curlm, mcl_curlm_close_cb cb)
{
	ASSERT(!curlm->closing);
	curlm->closing = 1;
	curlm->close_cb = cb;
	uv_check_start(&curlm->check, mcl_curlm__on_check);
}

CURLM *mcl_curlm_get_handle(mcl_curlm_t *curlm)
{
	return curlm->handle;
}
