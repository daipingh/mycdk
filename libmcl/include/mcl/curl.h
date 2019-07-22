
#ifndef MCL_CURL_H_
#define MCL_CURL_H_

#include "lang.h"
#include <uv.h>
#include <curl/curl.h>


MCL_BEGIN_EXTERN_C

typedef struct mcl_curl_s mcl_curl_t;
typedef struct mcl_curlm_s mcl_curlm_t;
typedef void(*mcl_curl_perform_cb)(mcl_curl_t *curl, int status);
typedef void(*mcl_curl_close_cb)(mcl_curl_t *curl);
typedef void(*mcl_curlm_close_cb)(mcl_curlm_t *curlm);

struct mcl_curl_s
{
	CURL *handle;
	void *private_data;
	mcl_curlm_t *curlm;
	mcl_curl_perform_cb perform_cb;
	void *list_to[2];
};
struct mcl_curlm_s
{
	CURLM *handle;
	int closing;
	int active_cnt;
	uv_loop_t *loop;
	uv_timer_t timer;
	uv_check_t check;
	void *context_list[2];
	void *curl_list[2];
	mcl_curlm_close_cb close_cb;
	void *data;
};

#define mcl_curl_setopt(curl, option, ...)                         \
		(((option) == CURLOPT_PRIVATE)                             \
		? mcl_curl_setopt_private((curl), (option), ##__VA_ARGS__) \
		: curl_easy_setopt(mcl_curl_get_handle(curl), (option), ##__VA_ARGS__))

#define mcl_curl_getinfo(curl, info, ...)                          \
		(((info) == CURLINFO_PRIVATE)                              \
		? mcl_curl_getinfo_private((curl), (info), ##__VA_ARGS__)  \
		: curl_easy_getinfo(mcl_curl_get_handle(curl), (info), ##__VA_ARGS__))



MCL_APIDECL int mcl_curl_init(mcl_curl_t *curl);
MCL_APIDECL void mcl_curl_cleanup(mcl_curl_t *curl);
MCL_APIDECL int mcl_curl_perform(mcl_curl_t *curl, mcl_curlm_t *curlm, mcl_curl_perform_cb cb);

MCL_APIDECL CURL *mcl_curl_get_handle(mcl_curl_t *curl);
MCL_APIDECL int mcl_curl_setopt_private(mcl_curl_t *curl, CURLoption opt, ...);
MCL_APIDECL int mcl_curl_getinfo_private(mcl_curl_t *curl, CURLINFO info, ...);

MCL_APIDECL int mcl_curlm_init(mcl_curlm_t *curlm, uv_loop_t *loop);
MCL_APIDECL void mcl_curlm_close(mcl_curlm_t *curlm, mcl_curlm_close_cb cb);
MCL_APIDECL CURLM *mcl_curlm_get_handle(mcl_curlm_t *curl);

MCL_END_EXTERN_C
#endif
