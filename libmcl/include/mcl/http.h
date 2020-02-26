
#ifndef MCL_HTTP_H_
#define MCL_HTTP_H_

#include <uv.h>
#include "stream.h"


MCL_BEGIN_EXTERN_C

typedef struct mcl_urlparser_s mcl_urlparser_t;
struct mcl_urlparser_s
{
	const char *url;
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


typedef struct mcl_http_conf_s mcl_http_conf_t;
typedef struct mcl_http_conn_s mcl_http_conn_t;

typedef void(*mcl_http_connection_cb)(void *arg, mcl_http_conn_t *conn);
typedef void(*mcl_http_data_cb)(void *arg, const char *chunk, ssize_t length);
typedef void(*mcl_http_send_cb)(void *arg, int status);
typedef int(*mcl_http_field_cb)(void *arg, const char *name, const char *value);

MCL_APIDECL mcl_http_conf_t *mcl_http_conf_create();
MCL_APIDECL void mcl_http_conf_destroy(mcl_http_conf_t *conf);
MCL_APIDECL void mcl_http_conf_set_strict(mcl_http_conf_t *conf, int mode);
MCL_APIDECL void mcl_http_conf_set_header_buf_size(mcl_http_conf_t *conf, unsigned int size);
MCL_APIDECL int mcl_http_conf_get_strict(mcl_http_conf_t *conf);
MCL_APIDECL unsigned int mcl_http_conf_get_header_buf_size(mcl_http_conf_t *conf);

MCL_APIDECL int mcl_http_new_connection(mcl_stream_t *stream, mcl_http_conf_t *conf, void *arg, mcl_http_connection_cb cb);

MCL_APIDECL const mcl_urlparser_t *mcl_http_get_urlparser(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_method(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_path(mcl_http_conn_t *conn);
MCL_APIDECL const char *mcl_http_get_query(mcl_http_conn_t *conn, const char *name);
MCL_APIDECL const char *mcl_http_get_header(mcl_http_conn_t *conn, const char *name);
MCL_APIDECL int mcl_http_query_parse(mcl_http_conn_t *conn, char *query);
MCL_APIDECL int mcl_http_query_foreach(mcl_http_conn_t *conn, void *arg, mcl_http_field_cb cb);
MCL_APIDECL int mcl_http_header_foreach(mcl_http_conn_t *conn, void *arg, mcl_http_field_cb cb);
MCL_APIDECL int mcl_http_on_content(mcl_http_conn_t *conn, void *arg, mcl_http_data_cb cb);

MCL_APIDECL int mcl_http_set_status(mcl_http_conn_t *conn, unsigned int status);
MCL_APIDECL int mcl_http_set_header(mcl_http_conn_t *conn, const char *name, const char *value);
MCL_APIDECL int mcl_http_send(mcl_http_conn_t *conn, const void *data, size_t length, void *arg, mcl_http_send_cb write_cb);
MCL_APIDECL int mcl_http_send_data(mcl_http_conn_t *conn, const void *data, size_t length, void *arg, mcl_http_send_cb write_cb);

MCL_APIDECL mcl_http_conn_t *mcl_http_hold(mcl_http_conn_t *conn);
MCL_APIDECL void mcl_http_release(mcl_http_conn_t *conn);

MCL_END_EXTERN_C


#endif
