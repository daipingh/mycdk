
#ifndef MCL_HTTP_H_
#define MCL_HTTP_H_

#include <uv.h>
#include "stream.h"


MCL_BEGIN_EXTERN_C

typedef struct mcl_urlparser_s mcl_urlparser_t;
struct mcl_urlparser_s
{
	const char *url;
	int result;
	char urlparser[48];
};

MCL_APIDECL int mcl_url_parse(mcl_urlparser_t *parser, const char *url, size_t len);
MCL_APIDECL const char *mcl_url_get_schema(const mcl_urlparser_t *parser, int *result);
MCL_APIDECL const char *mcl_url_get_host(const mcl_urlparser_t *parser, int *result);
MCL_APIDECL const char *mcl_url_get_port(const mcl_urlparser_t *parser, int *result);
MCL_APIDECL const char *mcl_url_get_path(const mcl_urlparser_t *parser, int *result);
MCL_APIDECL const char *mcl_url_get_query(const mcl_urlparser_t *parser, int *result);
MCL_APIDECL const char *mcl_url_get_fragment(const mcl_urlparser_t *parser, int *result);
MCL_APIDECL const char *mcl_url_get_userinfo(const mcl_urlparser_t *parser, int *result);


typedef struct mcl_http_s mcl_http_t;
typedef struct mcl_http_conn_s mcl_http_conn_t;

typedef void(*mcl_http_connection_cb)(void *arg, mcl_http_conn_t *conn);
typedef int(*mcl_http_header_cb)(void *arg, const char *name, const char *value);
typedef void(*mcl_http_data_cb)(void *arg, const char *chunk, ssize_t length);
typedef void(*mcl_http_write_cb)(void *arg, int status);

MCL_APIDECL mcl_http_t *mcl_http_create();
MCL_APIDECL void mcl_http_destroy(mcl_http_t *hs);
MCL_APIDECL int mcl_http_new_connection(mcl_http_t *hs, mcl_stream_t *stream, void *arg, mcl_http_connection_cb cb);

MCL_APIDECL const mcl_urlparser_t *mcl_http_get_urlparser(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_method(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_path(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_query(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_header(mcl_http_conn_t *conn, const char *name);
MCL_APIDECL int mcl_http_header_foreach(mcl_http_conn_t *conn, void *arg, mcl_http_header_cb cb);
MCL_APIDECL int mcl_http_on_content(mcl_http_conn_t *conn, void *arg, mcl_http_data_cb cb);

MCL_APIDECL int mcl_http_set_status(mcl_http_conn_t *conn, unsigned int status);
MCL_APIDECL int mcl_http_set_header(mcl_http_conn_t *conn, const char *name, const char *value);
MCL_APIDECL int mcl_http_write(mcl_http_conn_t *conn, void *arg, const void *data, size_t length, mcl_http_write_cb write_cb);
MCL_APIDECL int mcl_http_write_data(mcl_http_conn_t *conn, void *arg, const void *data, size_t length, mcl_http_write_cb write_cb);

MCL_APIDECL mcl_http_conn_t *mcl_http_hold(mcl_http_conn_t *conn);
MCL_APIDECL void mcl_http_release(mcl_http_conn_t *conn);

MCL_END_EXTERN_C


#endif
