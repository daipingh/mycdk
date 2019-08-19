
#ifndef MCL_HTTP_H_
#define MCL_HTTP_H_

#include "stream.h"
#include <uv/tree.h>


MCL_BEGIN_EXTERN_C

typedef struct mcl_http_s mcl_http_t;
typedef struct mcl_http_cgi_s mcl_http_cgi_t;
typedef struct mcl_http_conn_s mcl_http_conn_t;
typedef struct mcl_http_write_s mcl_http_write_t;

typedef void(*mcl_http_cgi_cb)(mcl_http_conn_t *conn);
typedef void(*mcl_http_data_cb)(mcl_http_conn_t *conn, void *args, const char *at, ssize_t length);
typedef void(*mcl_http_write_cb)(mcl_http_write_t *req, int status);

struct mcl_http_cgi_s
{
	void *reflist[2];
	RB_ENTRY(mcl_http_cgi_s) rb_entry;
	unsigned int hash;

	const char *path;
	mcl_http_cgi_cb cb;
};

struct mcl_http_write_s
{
	mcl_http_conn_t *conn;
	void(*write_cb)(struct mcl_http_write_s *req, int status);
	void *data;
};

MCL_APIDECL mcl_http_t *mcl_http_create();
MCL_APIDECL void mcl_http_destroy(mcl_http_t *server);
MCL_APIDECL int mcl_http_register(mcl_http_t *server, mcl_http_cgi_t *req, const char *path, mcl_http_cgi_cb cb);
MCL_APIDECL void mcl_http_unregister(mcl_http_t *server, mcl_http_cgi_t *req);
MCL_APIDECL int mcl_http_new_connection(mcl_http_t *server, mcl_stream_t *stream);

MCL_APIDECL mcl_stream_t *mcl_http_get_stream(mcl_http_conn_t *conn);
MCL_APIDECL mcl_http_cgi_t *mcl_http_get_cgi(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_method(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_path(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_query(mcl_http_conn_t *conn, const char *name);
MCL_APIDECL const char *mcl_http_get_header(mcl_http_conn_t *conn, const char *name);
MCL_APIDECL int mcl_http_query_foreach(mcl_http_conn_t *conn, void *args, int(*cb)(void *args, const char *name, const char *value));
MCL_APIDECL int mcl_http_header_foreach(mcl_http_conn_t *conn, void *args, int(*cb)(void *args, const char *name, const char *value));
MCL_APIDECL int mcl_http_on_data(mcl_http_conn_t *conn, void *args, mcl_http_data_cb data_cb);
MCL_APIDECL int mcl_http_set_status(mcl_http_conn_t *conn, unsigned int status);
MCL_APIDECL int mcl_http_set_header(mcl_http_conn_t *conn, const char *name, const char *value);
MCL_APIDECL int mcl_http_write_data(mcl_http_conn_t *conn, const void *data, size_t length);
MCL_APIDECL int mcl_http_write_static(mcl_http_conn_t *conn, const void *data, size_t length);
MCL_APIDECL int mcl_http_write_bufs(mcl_http_conn_t *conn, mcl_http_write_t *req, const uv_buf_t bufs[], unsigned int nbufs, mcl_http_write_cb write_cb);
MCL_APIDECL int mcl_http_query_parse(mcl_http_conn_t *conn, char *query);
MCL_APIDECL void mcl_http_hold_lock(mcl_http_conn_t *conn);
MCL_APIDECL void mcl_http_hold_unlock(mcl_http_conn_t *conn);
MCL_APIDECL void mcl_http_connection_close(mcl_http_conn_t *conn);

MCL_END_EXTERN_C
#endif
