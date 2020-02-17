
#include "http.h"
#include "defs.h"
#include "queue.h"
#include "utils.h"

#include <llhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MCL_HTTP__HEADER_BUF_MIN_SIZE ( 4 * 1024)
#define MCL_HTTP__HEADER_BUF_DEF_SIZE (32 * 1024)

#define TEST_BIT(s, n)  ((s) & (1 << (n)))
#define SET_BIT(s, n)   ((s) |= (1 << (n)))
#define CLEAR_BIT(s, n) ((s) &= ~(1 << (n)))

#ifndef HTTP_STATUS_MAP
/* Status Codes */
#define HTTP_STATUS_MAP(XX)                                                 \
  XX(100, CONTINUE,                        Continue)                        \
  XX(101, SWITCHING_PROTOCOLS,             Switching Protocols)             \
  XX(102, PROCESSING,                      Processing)                      \
  XX(200, OK,                              OK)                              \
  XX(201, CREATED,                         Created)                         \
  XX(202, ACCEPTED,                        Accepted)                        \
  XX(203, NON_AUTHORITATIVE_INFORMATION,   Non-Authoritative Information)   \
  XX(204, NO_CONTENT,                      No Content)                      \
  XX(205, RESET_CONTENT,                   Reset Content)                   \
  XX(206, PARTIAL_CONTENT,                 Partial Content)                 \
  XX(207, MULTI_STATUS,                    Multi-Status)                    \
  XX(208, ALREADY_REPORTED,                Already Reported)                \
  XX(226, IM_USED,                         IM Used)                         \
  XX(300, MULTIPLE_CHOICES,                Multiple Choices)                \
  XX(301, MOVED_PERMANENTLY,               Moved Permanently)               \
  XX(302, FOUND,                           Found)                           \
  XX(303, SEE_OTHER,                       See Other)                       \
  XX(304, NOT_MODIFIED,                    Not Modified)                    \
  XX(305, USE_PROXY,                       Use Proxy)                       \
  XX(307, TEMPORARY_REDIRECT,              Temporary Redirect)              \
  XX(308, PERMANENT_REDIRECT,              Permanent Redirect)              \
  XX(400, BAD_REQUEST,                     Bad Request)                     \
  XX(401, UNAUTHORIZED,                    Unauthorized)                    \
  XX(402, PAYMENT_REQUIRED,                Payment Required)                \
  XX(403, FORBIDDEN,                       Forbidden)                       \
  XX(404, NOT_FOUND,                       Not Found)                       \
  XX(405, METHOD_NOT_ALLOWED,              Method Not Allowed)              \
  XX(406, NOT_ACCEPTABLE,                  Not Acceptable)                  \
  XX(407, PROXY_AUTHENTICATION_REQUIRED,   Proxy Authentication Required)   \
  XX(408, REQUEST_TIMEOUT,                 Request Timeout)                 \
  XX(409, CONFLICT,                        Conflict)                        \
  XX(410, GONE,                            Gone)                            \
  XX(411, LENGTH_REQUIRED,                 Length Required)                 \
  XX(412, PRECONDITION_FAILED,             Precondition Failed)             \
  XX(413, PAYLOAD_TOO_LARGE,               Payload Too Large)               \
  XX(414, URI_TOO_LONG,                    URI Too Long)                    \
  XX(415, UNSUPPORTED_MEDIA_TYPE,          Unsupported Media Type)          \
  XX(416, RANGE_NOT_SATISFIABLE,           Range Not Satisfiable)           \
  XX(417, EXPECTATION_FAILED,              Expectation Failed)              \
  XX(421, MISDIRECTED_REQUEST,             Misdirected Request)             \
  XX(422, UNPROCESSABLE_ENTITY,            Unprocessable Entity)            \
  XX(423, LOCKED,                          Locked)                          \
  XX(424, FAILED_DEPENDENCY,               Failed Dependency)               \
  XX(426, UPGRADE_REQUIRED,                Upgrade Required)                \
  XX(428, PRECONDITION_REQUIRED,           Precondition Required)           \
  XX(429, TOO_MANY_REQUESTS,               Too Many Requests)               \
  XX(431, REQUEST_HEADER_FIELDS_TOO_LARGE, Request Header Fields Too Large) \
  XX(451, UNAVAILABLE_FOR_LEGAL_REASONS,   Unavailable For Legal Reasons)   \
  XX(500, INTERNAL_SERVER_ERROR,           Internal Server Error)           \
  XX(501, NOT_IMPLEMENTED,                 Not Implemented)                 \
  XX(502, BAD_GATEWAY,                     Bad Gateway)                     \
  XX(503, SERVICE_UNAVAILABLE,             Service Unavailable)             \
  XX(504, GATEWAY_TIMEOUT,                 Gateway Timeout)                 \
  XX(505, HTTP_VERSION_NOT_SUPPORTED,      HTTP Version Not Supported)      \
  XX(506, VARIANT_ALSO_NEGOTIATES,         Variant Also Negotiates)         \
  XX(507, INSUFFICIENT_STORAGE,            Insufficient Storage)            \
  XX(508, LOOP_DETECTED,                   Loop Detected)                   \
  XX(510, NOT_EXTENDED,                    Not Extended)                    \
  XX(511, NETWORK_AUTHENTICATION_REQUIRED, Network Authentication Required) \

#endif

typedef struct mcl_http_write_s mcl_http_write_t;
typedef struct mcl_http_field_s mcl_http_field_t;

struct mcl_http_s
{
	int closing;
	unsigned int strict_mode;
	unsigned int header_buf_size;
	unsigned int ref_count;
};

struct mcl_http_write_s
{
	char chunk_header[16];
	void *arg;
	mcl_http_write_cb write_cb;
	mcl_http_conn_t *conn;
};

struct mcl_http_field_s
{
	const char *key;
	const char *val;
	mcl_http_field_t *next;
};


#define RF_MAP(XX)                                    \
	XX(RF_CONNECTION,        "Connection")            \
	XX(RF_CONTENT_TYPE,      "Content-Type")          \
	XX(RF_CONTENT_LENGTH,    "Content-Length")        \
	XX(RF_TRANSFER_ENCODING, "Transfer-Encoding")     \

enum
{
#define XX(_n, _s) _n,
	RF_MAP(XX)
#undef XX
	RF_MAX = 7
};

static struct
{
	const char *field;
	unsigned int length;
}
rf_map_info[RF_MAX] =
{
#define XX(_code, _name) { _name, sizeof(_name) - 1 },
	RF_MAP(XX)
#undef XX
};


struct mcl_http_conn_s
{
	mcl_http_t *hs;
	mcl_stream_t *stream;

	llhttp_t parser;
	mcl_urlparser_t urlparser;

	unsigned short f_closing;
	unsigned short f_req_begin;
	unsigned short f_req_complete;
	unsigned short f_cgi_complete;
	unsigned short f_resp_begin;
	unsigned short f_resp_complete;
	unsigned short f_internal_error;
	unsigned int error_code;
	unsigned int ref_count;

	char *data_buf;
	uint32_t data_buf_size;
	uint32_t data_received;
	uint32_t data_parsed;
	uint32_t header_size;

	char *current_buf;
	uint32_t current_len;
	char *url;
	mcl_http_field_t *field_first;

	// 请求回调.
	mcl_http_connection_cb connection_cb;
	void *connection_arg;
	mcl_http_data_cb req_data_cb;
	void *req_data_arg;

	// 特殊字段特殊处理，其他字段直接添加到缓冲区，不做重复检查.
	struct {
		unsigned int status_code;
		unsigned short http_major;
		unsigned short http_minor;

		int64_t content_length;
		int64_t content_writes;

		uint32_t field_set;
		uint32_t fields_len;
	} resp;

	char *resp_status_buf;
	uint32_t resp_status_buf_size;
	char *resp_fields_buf;
	uint32_t resp_fields_buf_size;

	mcl_http_field_t *field_pool;
};


static void mcl_http__on_alloc(mcl_stream_t *stream, size_t suggested_size, uv_buf_t *buf);
static void mcl_http__on_read(mcl_stream_t *stream, ssize_t nread, const uv_buf_t *buf);


static void mcl_http__ref(mcl_http_t *hs)
{
	hs->ref_count += 1;
}
static void mcl_http__unref(mcl_http_t *hs)
{
	hs->ref_count -= 1;
	if (hs->ref_count == 0) {
		CHECK(hs->closing);
		free(hs);
	}
}


static mcl_http_field_t *mcl_http_field_new(mcl_http_conn_t *conn)
{
	mcl_http_field_t *field;

	if (conn->field_pool == NULL)
		field = (mcl_http_field_t *)malloc(sizeof(mcl_http_field_t));
	else {
		field = conn->field_pool;
		conn->field_pool = conn->field_pool->next;
	}
	field->key = NULL;
	field->val = NULL;
	field->next = NULL;

	return field;
}
static void mcl_http_field_delete(mcl_http_conn_t *conn, mcl_http_field_t *field)
{
	field->next = conn->field_pool;
	conn->field_pool = field;
}

static void mcl_http_connection_close(mcl_http_conn_t *conn)
{
	conn->f_closing = 1;
}
static mcl_http_conn_t *mcl_http_conn_from_parser(llhttp_t *parser)
{
	return (mcl_http_conn_t *)parser->data;
}

static int on_message_begin(llhttp_t *parser)
{
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);
	conn->f_req_begin = 1;
	return 0;
}
static int on_url(llhttp_t *parser, const char *at, size_t length)
{
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	if (conn->url == NULL) {
		ASSERT(conn->current_buf == NULL);
		conn->current_buf = (char *)at;
		conn->current_len = (uint32_t)length;
		conn->url = conn->current_buf;
	}
	else {
		CHECK(conn->current_buf == conn->url);
		CHECK(conn->current_buf + conn->current_len == at);
		conn->current_len += (uint32_t)length;
	}

	return 0;
}
static int on_url_complete(mcl_http_conn_t *conn)
{
	int res;
	char *ptr;

	ASSERT(conn->url == conn->current_buf);
	mcl_url_parse(&conn->urlparser, conn->url, conn->current_len);

	// url-path.
	ptr = (char *)mcl_url_get_path(&conn->urlparser, &res);
	if (res >= 0)
		ptr[res] = 0;
	else {
		mcl_http_connection_close(conn);
		mcl_http_set_status(conn, 400);
		mcl_http_write_data(conn, NULL, NULL, 0, NULL);
		return -1;
	}

	// url-query.
	ptr = (char *)mcl_url_get_query(&conn->urlparser, &res);
	if (res >= 0)
		ptr[res] = 0;

	// url-fragment.
	ptr = (char *)mcl_url_get_fragment(&conn->urlparser, &res);
	if (res >= 0)
		ptr[res] = 0;

	return 0;
}
static int on_status(llhttp_t *parser, const char *at, size_t length)
{
	UNREACHABLE();
	printf("%s: %.*s\n", __FUNCTION__, (int)length, at);
	return 0;
}
static int on_header_field(llhttp_t *parser, const char *at, size_t length)
{
	mcl_http_field_t *field;
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	ASSERT(conn->url != NULL);

	if (conn->field_first == NULL) {
		ASSERT(conn->current_buf == conn->url);
		conn->current_buf[conn->current_len] = 0;
		if (on_url_complete(conn))
			return -1;

		// empty.
		if (length == 0)
			conn->current_buf += conn->current_len;
		else
			conn->current_buf = (char *)at;
		conn->current_len = (uint32_t)length;
		conn->field_first = mcl_http_field_new(conn);
		conn->field_first->key = conn->current_buf;
	}
	else if (conn->field_first->val != NULL) {
		ASSERT(conn->field_first->key != NULL);
		ASSERT(conn->current_buf == conn->field_first->val);
		conn->current_buf[conn->current_len] = 0;

		// empty.
		if (length == 0)
			conn->current_buf += conn->current_len;
		else
			conn->current_buf = (char *)at;
		conn->current_len = (uint32_t)length;
		field = mcl_http_field_new(conn);
		field->next = conn->field_first;
		conn->field_first = field;
		conn->field_first->key = conn->current_buf;
	}
	else {
		CHECK(conn->current_buf == conn->field_first->key);
		CHECK(conn->current_buf + conn->current_len == at);
		conn->current_len += (uint32_t)length;
	}

	return 0;
}
static int on_header_value(llhttp_t *parser, const char *at, size_t length)
{
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	ASSERT(conn->url != NULL);
	ASSERT(conn->field_first != NULL);
	ASSERT(conn->field_first->key != NULL);

	if (conn->field_first->val == NULL) {
		ASSERT(conn->current_buf == conn->field_first->key);
		conn->current_buf[conn->current_len] = 0;

		// empty.
		if (length == 0)
			conn->current_buf += conn->current_len;
		else
			conn->current_buf = (char *)at;
		conn->current_len = (uint32_t)length;
		conn->field_first->val = conn->current_buf;
	}
	else {
		CHECK(conn->current_buf == conn->field_first->val);
		CHECK(conn->current_buf + conn->current_len == at);
		conn->current_len += (uint32_t)length;
	}

	return 0;
}
static int on_headers_complete(llhttp_t *parser)
{
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	ASSERT(conn->url != NULL);

	if (conn->field_first == NULL) {
		ASSERT(conn->current_buf == conn->url);
		conn->current_buf[conn->current_len] = 0;
		if (on_url_complete(conn))
			return -1;

		conn->current_buf = NULL;
		conn->current_len = 0;
	}
	else {
		ASSERT(conn->field_first->key != NULL);
		ASSERT(conn->current_buf == conn->field_first->val);
		conn->current_buf[conn->current_len] = 0;

		conn->current_buf = NULL;
		conn->current_len = 0;
	}

	if (!conn->f_cgi_complete) {
		conn->connection_cb(conn->connection_arg, conn);
		conn->f_cgi_complete = 1;
	}
	return 0;
}
static int on_body(llhttp_t *parser, const char *at, size_t length)
{
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	if (!conn->header_size)
		conn->header_size = (uint32_t)((char *)at - conn->data_buf);

	if (conn->req_data_cb)
		conn->req_data_cb(conn->req_data_arg, (char *)at, (ssize_t)length);

	return 0;
}
static int on_message_complete(llhttp_t *parser)
{
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	// 消息完成，暂停解析.
	conn->f_req_complete = 1;

	if (conn->req_data_cb) {
		conn->req_data_cb(conn->req_data_arg, NULL, 0);
		conn->req_data_cb = NULL;
	}
	if (!conn->f_cgi_complete) {
		conn->connection_cb(conn->connection_arg, conn);
		conn->f_cgi_complete = 1;
	}

	return HPE_PAUSED;
}

static const llhttp_settings_t __parser_settings =
{
	.on_message_begin = on_message_begin,
	.on_url = on_url,
	.on_status = on_status,
	.on_header_field = on_header_field,
	.on_header_value = on_header_value,
	.on_headers_complete = on_headers_complete,
	.on_body = on_body,
	.on_message_complete = on_message_complete,
	.on_chunk_header = NULL,
	.on_chunk_complete = NULL
};

static mcl_http_conn_t *mcl_http_conn__create(mcl_http_t *hs)
{
	mcl_http_conn_t *conn;
	conn = (mcl_http_conn_t *)malloc(sizeof(mcl_http_conn_t));

	if (conn != NULL) {
		memset(conn, 0, sizeof(mcl_http_conn_t));
		conn->hs = hs;
		conn->stream = NULL;
		conn->data_buf = NULL;

		llhttp_init(&conn->parser, HTTP_REQUEST, &__parser_settings);
		conn->parser.data = conn;

		conn->ref_count = 0;
		mcl_http__ref(hs);
	}

	return conn;
}
static void mcl_http_conn__destroy(mcl_http_conn_t *conn)
{
	mcl_http_field_t *field;

	if (conn->data_buf != NULL)
		free(conn->data_buf);

	while (conn->field_pool != NULL) {
		field = conn->field_pool;
		conn->field_pool = field->next;
		free(field);
	}

	mcl_http__unref(conn->hs);
	free(conn);
}
static void mcl_http_conn__clean(mcl_http_conn_t *conn)
{
	mcl_http_field_t *field;

	while (conn->field_first != NULL) {
		field = conn->field_first;
		conn->field_first = field->next;
		mcl_http_field_delete(conn, field);
	}
}
static void mcl_http_conn__reset(mcl_http_conn_t *conn)
{
	//conn->f_closing = 0;
	conn->f_req_begin = 0;
	conn->f_req_complete = 0;
	conn->f_cgi_complete = 0;
	conn->f_resp_begin = 0;
	conn->f_resp_complete = 0;
	conn->f_internal_error = 0;
	conn->error_code = 0;

	if (conn->data_parsed < conn->data_received)
		memmove(conn->data_buf, conn->data_buf + conn->data_parsed, conn->data_received - conn->data_parsed);
	conn->data_received -= conn->data_parsed;
	conn->data_parsed = 0;
	conn->header_size = 0;

	conn->current_buf = NULL;
	conn->current_len = 0;
	conn->url = NULL;
	//conn->field_first = NULL;

	memset(&conn->resp, 0, sizeof(conn->resp));
}

static void mcl_http_conn__ref(mcl_http_conn_t *conn)
{
	conn->ref_count += 1;
}
static void mcl_http_conn__unref(mcl_http_conn_t *conn)
{
	if (conn->ref_count != 1)
		conn->ref_count -= 1;
	else {
		if (conn->error_code && (conn->f_req_begin && !conn->f_resp_begin)) {
			memset(&conn->resp, 0, sizeof(conn->resp));
			conn->ref_count += 1;
			mcl_http_connection_close(conn);
			mcl_http_set_status(conn, conn->error_code);
			mcl_http_write_data(conn, NULL, NULL, 0, NULL);
			conn->ref_count -= 1;
		}
		if (conn->ref_count == 1) {
			if (conn->f_closing || (conn->f_req_begin && !conn->f_resp_complete)) {
				mcl_http_conn__clean(conn);
				conn->ref_count -= 1;
			}
			else {
				mcl_http_conn__clean(conn);
				mcl_http_conn__reset(conn);

				conn->stream->data = conn;
				if (mcl_stream_read_start(conn->stream, mcl_http__on_alloc, mcl_http__on_read))
					conn->ref_count -= 1;
				else
					mcl_http__on_read(conn->stream, 0, 0);
			}
			if (conn->ref_count == 0) {
				conn->connection_cb(conn->connection_arg, NULL);
				mcl_http_conn__destroy(conn);
			}
		}
	}
}

const mcl_urlparser_t *mcl_http_get_urlparser(mcl_http_conn_t *conn)
{
	return &conn->urlparser;
}
const char *mcl_http_get_method(mcl_http_conn_t *conn)
{
	return llhttp_method_name(conn->parser.method);
}
const char *mcl_http_get_path(mcl_http_conn_t *conn)
{
	const char *p = mcl_url_get_path(&conn->urlparser, NULL);
	return p ? p : "";
}
const char *mcl_http_get_query(mcl_http_conn_t *conn)
{
	const char *p = mcl_url_get_query(&conn->urlparser, NULL);
	return p ? p : "";
}
const char *mcl_http_get_header(mcl_http_conn_t *conn, const char *name)
{
	mcl_http_field_t *field = conn->field_first;
	while (field != NULL) {
		if (mcl_strcasecmp(field->key, name) == 0)
			return field->val;
		field = field->next;
	}
	return NULL;
}
int mcl_http_header_foreach(mcl_http_conn_t *conn, void *arg, mcl_http_header_cb cb)
{
	int n = 0;
	mcl_http_field_t *field = conn->field_first;
	while (field != NULL) {
		n += 1;
		if (cb(arg, field->key, field->val))
			break;
		field = field->next;
	}
	return n;
}

int mcl_http_on_content(mcl_http_conn_t *conn, void *arg, mcl_http_data_cb cb)
{
	if (conn->f_req_complete)
		return UV_EOF;
	conn->req_data_arg = arg;
	conn->req_data_cb = cb;
	return 0;
}

int mcl_http_set_status(mcl_http_conn_t *conn, unsigned int status)
{
	return conn->resp.status_code = status;
}

static int mcl_http__set_header(mcl_http_conn_t *conn, const char *name, const char *value)
{
	unsigned int len;
	len = (unsigned int)snprintf(conn->resp_fields_buf + conn->resp.fields_len, conn->resp_fields_buf_size - conn->resp.fields_len, "%s: %s\r\n", name, value);

	if (len >= conn->resp_fields_buf_size - conn->resp.fields_len)
		return UV_E2BIG;

	conn->resp.fields_len += len;
	return 0;
}
int mcl_http_set_header(mcl_http_conn_t *conn, const char *name, const char *value)
{
	int i;
	unsigned int len = (unsigned int)strlen(name);

	if (conn->hs->strict_mode) {
		// 非法字符检查.
		for (i = 0; name[i]; ++i) {
			if (name[i] == '\r' || name[i] == '\n' || name[i] == ':' || name[i] == ' ') {
				UNREACHABLE_ASSERT();
				return UV_EINVAL;
			}
		}
		for (i = 0; value[i]; ++i) {
			if (value[i] == '\r' || value[i] == '\n') {
				UNREACHABLE_ASSERT();
				return UV_EINVAL;
			}
		}
	}

	for (i = 0; i < RF_MAX; ++i) {
		if (len == rf_map_info[i].length && mcl_strcasecmp(name, rf_map_info[i].field) == 0) {
			if (TEST_BIT(conn->resp.field_set, i))
				return UV_EEXIST;

			switch (i)
			{
			case RF_CONNECTION:
				if (mcl_strcasecmp(value, "close"))
					return UV_EINVAL;
				if (mcl_http__set_header(conn, name, value))
					return UV_E2BIG;
				SET_BIT(conn->resp.field_set, i);
				mcl_http_connection_close(conn);
				break;

			case RF_CONTENT_LENGTH:
				conn->resp.content_length = atoll(value);
				if (conn->resp.content_length < 0)
					return UV_EINVAL;
				else if (conn->resp.content_length == 0)
					return 0;
				if (mcl_http__set_header(conn, name, value))
					return UV_E2BIG;
				SET_BIT(conn->resp.field_set, i);
				break;

			case RF_TRANSFER_ENCODING:
				if (mcl_strcasecmp(value, "chunked"))
					return UV_EINVAL;
				if (mcl_http__set_header(conn, name, value))
					return UV_E2BIG;
				SET_BIT(conn->resp.field_set, i);
				break;

			default:
				if (mcl_http__set_header(conn, name, value))
					return UV_E2BIG;
				SET_BIT(conn->resp.field_set, i);
				break;
			}

			return 0;
		}
	}

	if (mcl_http__set_header(conn, name, value))
		return UV_E2BIG;

	return 0;
}

static const char *mcl_http_status_string(mcl_http_t *hs, unsigned int status_code)
{
	switch (status_code)
	{
#define XX(_c, _n, _s) \
	case _c: return #_s;
		HTTP_STATUS_MAP(XX);
#undef XX
	}

	return "Unknown Status";
}
static const char *mcl_http_guess_content_type(mcl_http_conn_t *conn, const void *data, size_t length)
{
	// TODO: 通过响应内容猜测数据类型.
	const char *suffix = NULL;
	const char *path = mcl_http_get_path(conn);
	const char *content_type = "application/octet-stream";

	if (path != NULL)
		suffix = strrchr(path, '.');

	if (suffix != NULL) {
		if (!strcmp(suffix, ".htm") || !strcmp(suffix, ".html") || !strcmp(suffix, ".htx"))
			content_type = "text/html";
		else if (!strcmp(suffix, ".js"))
			content_type = "application/x-javascript";
		else if (!strcmp(suffix, ".css"))
			content_type = "text/css";
		else if (!strcmp(suffix, ".txt"))
			content_type = "text/plain";
	}

	return content_type;
}

mcl_http_conn_t *mcl_http_hold(mcl_http_conn_t *conn)
{
	mcl_http_conn__ref(conn);
	return conn;
}
void mcl_http_release(mcl_http_conn_t *conn)
{
	mcl_http_conn__unref(conn);
}

static void mcl_http__on_write(void *req, int status)
{
	mcl_http_write_t *write_req = (mcl_http_write_t *)req;
	void *arg = write_req->arg;
	mcl_http_write_cb write_cb = write_req->write_cb;
	mcl_http_conn_t *conn = write_req->conn;

	free(write_req);
	if (status < 0)
		mcl_http_connection_close(conn);
	if (write_cb)
		write_cb(arg, status);

	mcl_http_conn__unref(conn);
}
static void mcl_http__on_write_data(void *req, int status)
{
	mcl_http_write_t *write_req = (mcl_http_write_t *)req;
	void *arg = write_req->arg;
	mcl_http_write_cb write_cb = write_req->write_cb;
	mcl_http_conn_t *conn = write_req->conn;

	free(write_req);
	if (status < 0)
		mcl_http_connection_close(conn);
	if (write_cb)
		write_cb(arg, status);

	mcl_http_conn__unref(conn);
}

int mcl_http__write_data(mcl_http_conn_t *conn, mcl_http_write_t *write_req, const void *data, size_t length, mcl_stream_write_cb write_cb)
{
	int err;
	int transfer_encoding;
	char *header_ptr;
	uint32_t header_len;
	unsigned short http_major;
	unsigned short http_minor;
	unsigned int status_code;
	uv_buf_t bufs[4];
	unsigned int nbufs = 0;

	if (conn->f_resp_complete)
		return UV_EBUSY;
	if (length > INT_MAX)
		return UV_ENOMEM;

	// 传输编码，仅支持chunked方式.
	transfer_encoding = !!TEST_BIT(conn->resp.field_set, RF_TRANSFER_ENCODING);

	// 响应头.
	if (!conn->f_resp_begin) {
		// 状态行.
		http_major = conn->resp.http_major ? conn->resp.http_major : 1;
		http_minor = conn->resp.http_minor ? conn->resp.http_minor : 1;
		status_code = conn->resp.status_code ? conn->resp.status_code : 200;

		header_len = (uint32_t)snprintf(
			conn->resp_status_buf, conn->resp_status_buf_size, "HTTP/%hu.%hu %u %s\r\n",
			http_major, http_minor, status_code, mcl_http_status_string(conn->hs, status_code));

		if (header_len < conn->resp_status_buf_size) {
			header_ptr = conn->resp_status_buf + conn->resp_status_buf_size - header_len;
			memmove(header_ptr, conn->resp_status_buf, header_len);
		}
		else {
			header_len = conn->resp_status_buf_size;
			header_ptr = conn->resp_status_buf;
			header_ptr[header_len - 2] = '\r';
			header_ptr[header_len - 1] = '\n';
		}

		// 头部字段.
		header_len += conn->resp.fields_len;

		if (conn->f_closing && !TEST_BIT(conn->resp.field_set, RF_CONNECTION))
			header_len += sprintf(header_ptr + header_len, "Connection: close\r\n");

		if (data && length && !TEST_BIT(conn->resp.field_set, RF_CONTENT_TYPE))
			header_len += sprintf(header_ptr + header_len, "Content-Type: %s\r\n", mcl_http_guess_content_type(conn, data, length));

		if (!TEST_BIT(conn->resp.field_set, RF_CONTENT_LENGTH) && !TEST_BIT(conn->resp.field_set, RF_TRANSFER_ENCODING))
			header_len += sprintf(header_ptr + header_len, "Content-Length: %u\r\n", (unsigned int)length);

		header_len += sprintf(header_ptr + header_len, "\r\n");

		bufs[nbufs].base = header_ptr;
		bufs[nbufs].len = header_len;
		nbufs += 1;
	}

	// 响应内容.
	if (transfer_encoding) {
		snprintf(write_req->chunk_header, sizeof(write_req->chunk_header), "%x\r\n", (unsigned int)length);

		bufs[nbufs].base = write_req->chunk_header;
		bufs[nbufs].len = (unsigned int)strlen(write_req->chunk_header);
		nbufs += 1;
		if (length > 0) {
			bufs[nbufs].base = (char *)data;
			bufs[nbufs].len = (unsigned int)length;
			nbufs += 1;
		}
		bufs[nbufs].base = "\r\n";
		bufs[nbufs].len = 2;
		nbufs += 1;
	}
	else if (length > 0) {
		if (conn->resp.content_length > 0 && (int64_t)length > conn->resp.content_length - conn->resp.content_writes)
			length = conn->resp.content_length - conn->resp.content_writes;
		bufs[nbufs].base = (char *)data;
		bufs[nbufs].len = (unsigned int)length;
		nbufs += 1;
	}

	err = mcl_stream_write(conn->stream, write_req, bufs, nbufs, write_cb);
	if (err != 0) {
		conn->f_internal_error = 1;
		return err;
	}
	mcl_http_conn__ref(conn);
	conn->f_resp_begin = 1;
	conn->resp.content_writes += length;

	if (transfer_encoding) {
		if (length == 0) {
			conn->f_resp_complete = 1;
		}
	}
	else {
		if (conn->resp.content_writes >= conn->resp.content_length) {
			conn->f_resp_complete = 1;
		}
	}

	return 0;
}

int mcl_http_write(mcl_http_conn_t *conn, void *arg, const void *data, size_t length, mcl_http_write_cb write_cb)
{
	int err;
	mcl_http_write_t *write_req;

	if (length > INT_MAX)
		return UV_ENOMEM;
	if (conn->f_resp_complete)
		return UV_EBUSY;
	if (length == 0)
		return mcl_http_write_data(conn, arg, NULL, 0, write_cb);

	write_req = (mcl_http_write_t *)malloc(sizeof(mcl_http_write_t) + length);
	if (write_req == NULL) {
		conn->f_internal_error = 1;
		return UV_ENOMEM;
	}
	write_req->arg = arg;
	write_req->write_cb = write_cb;
	write_req->conn = conn;
	memcpy(&write_req[1], data, length);
	err = mcl_http__write_data(conn, write_req, &write_req[1], length, mcl_http__on_write);
	if (err < 0) {
		free(write_req);
		return err;
	}
	return 0;
}
int mcl_http_write_data(mcl_http_conn_t *conn, void *arg, const void *data, size_t length, mcl_http_write_cb write_cb)
{
	int err;
	mcl_http_write_t *write_req;

	if (length > INT_MAX)
		return UV_ENOMEM;
	if (conn->f_resp_complete)
		return UV_EBUSY;

	write_req = (mcl_http_write_t *)malloc(sizeof(mcl_http_write_t));
	if (write_req == NULL) {
		conn->f_internal_error = 1;
		return UV_ENOMEM;
	}
	write_req->arg = arg;
	write_req->write_cb = write_cb;
	write_req->conn = conn;
	err = mcl_http__write_data(conn, write_req, data, length, mcl_http__on_write_data);
	if (err < 0) {
		free(write_req);
		return err;
	}
	return 0;
}


static void mcl_http__on_alloc(mcl_stream_t *stream, size_t suggested_size, uv_buf_t *buf)
{
	uint32_t header_buf_size;
	mcl_http_conn_t *conn = (mcl_http_conn_t *)stream->data;

	if (conn->data_buf == NULL) {
		assert(conn->data_received == 0);
		header_buf_size = conn->hs->header_buf_size;
		if (header_buf_size == 0)
			header_buf_size = MCL_HTTP__HEADER_BUF_DEF_SIZE;
		else if (header_buf_size < MCL_HTTP__HEADER_BUF_MIN_SIZE)
			header_buf_size = MCL_HTTP__HEADER_BUF_MIN_SIZE;

		// 请求头、请求内容、响应头、响应头余量.
		conn->data_buf = malloc(header_buf_size + 1024 + header_buf_size + 1024);
		if (conn->data_buf == NULL) {
			buf->base = NULL;
			buf->len = 0;
			return;
		}

		conn->data_buf_size = header_buf_size + 1024;
		conn->resp_status_buf = conn->data_buf + conn->data_buf_size;
		conn->resp_status_buf_size = 256;
		conn->resp_fields_buf = conn->resp_status_buf + conn->resp_status_buf_size;
		conn->resp_fields_buf_size = header_buf_size - conn->resp_status_buf_size;
	}

	buf->base = conn->data_buf + conn->data_received;
	buf->len = conn->data_buf_size - conn->data_received;
}

static void mcl_http__on_read(mcl_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	llhttp_errno_t err;
	mcl_http_conn_t *conn = (mcl_http_conn_t *)stream->data;
	mcl_http_conn__ref(conn);

	if (nread < 0) {
		// 接收数据出错.
		mcl_stream_read_stop(conn->stream);
		mcl_http_conn__unref(conn);
		mcl_http_connection_close(conn);

		llhttp_execute(&conn->parser, conn->data_buf + conn->data_parsed, 0);
		if (conn->req_data_cb) {
			conn->req_data_cb(conn->req_data_arg, NULL, nread);
			conn->req_data_cb = NULL;
		}
	}
	else {
		conn->data_received += (uint32_t)nread;

		if (conn->data_received > conn->data_parsed) {
			err = llhttp_execute(&conn->parser, conn->data_buf + conn->data_parsed, conn->data_received - conn->data_parsed);

			if (conn->f_req_complete) {
				// 请求接收完成.
				mcl_stream_read_stop(conn->stream);
				mcl_http_conn__unref(conn);

				if (err == HPE_OK)
					conn->data_parsed = conn->data_received;
				else if (err == HPE_PAUSED) {
					llhttp_resume(&conn->parser);
					err = HPE_OK;
					conn->data_parsed = (uint32_t)(llhttp_get_error_pos(&conn->parser) - conn->data_buf);
				}
			}
			else {
				if (err == HPE_OK) {
					// 继续接收请求，但body数据处理后不保留.
					conn->data_parsed = conn->data_received;
					if (conn->data_received > conn->header_size && conn->header_size != 0) {
						conn->data_received = conn->header_size;
						conn->data_parsed = conn->header_size;
					}
				}
				else {
					mcl_stream_read_stop(conn->stream);
					mcl_http_conn__unref(conn);
					conn->data_parsed = (uint32_t)(llhttp_get_error_pos(&conn->parser) - conn->data_buf);
				}
			}
			if (err != HPE_OK) {
				// 请求解析失败.
				mcl_http_connection_close(conn);

				if (conn->req_data_cb) {
					conn->req_data_cb(conn->req_data_arg, NULL, UV_UNKNOWN);
					conn->req_data_cb = NULL;
				}
				if (conn->ref_count == 1 && (conn->f_req_begin && !conn->f_resp_begin)) {
					mcl_http_set_status(conn, 400);
					mcl_http_write_data(conn, NULL, NULL, 0, NULL);
				}
			}
		}
	}

	mcl_http_conn__unref(conn);
}


mcl_http_t *mcl_http_create()
{
	mcl_http_t *hs = (mcl_http_t *)malloc(sizeof(mcl_http_t));
	if (hs != NULL) {
		memset(hs, 0, sizeof(mcl_http_t));
		hs->ref_count = 1;
	}
	return hs;
}
void mcl_http_destroy(mcl_http_t *hs)
{
	ASSERT(!hs->closing);
	hs->closing = 1;
	mcl_http__unref(hs);
}

int mcl_http_new_connection(mcl_http_t *hs, mcl_stream_t *stream, void *arg, mcl_http_connection_cb cb)
{
	int err;
	mcl_http_conn_t *conn;

	conn = mcl_http_conn__create(hs);
	if (conn == NULL)
		return UV_ENOMEM;

	conn->stream = stream;
	conn->connection_cb = cb;
	conn->connection_arg = arg;

	conn->stream->data = conn;
	err = mcl_stream_read_start(stream, mcl_http__on_alloc, mcl_http__on_read);
	if (err < 0) {
		mcl_http_conn__destroy(conn);
		return err;
	}

	mcl_http_conn__ref(conn);
	return 0;
}
