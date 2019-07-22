
#include "http.h"
#include "defs.h"
#include "queue.h"
#include "stream.h"
#include "utils.h"

//#include <llhttp.h>
#include <http_parser.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* Macros for character classes; depends on strict-mode  */
#define CR                  '\r'
#define LF                  '\n'
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_NUM(c)           ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_NUM(c))
#define IS_HEX(c)           (IS_NUM(c) || (LOWER(c) >= 'a' && LOWER(c) <= 'f'))
#define IS_MARK(c)          ((c) == '-' || (c) == '_' || (c) == '.' || \
  (c) == '!' || (c) == '~' || (c) == '*' || (c) == '\'' || (c) == '(' || \
  (c) == ')')
#define IS_USERINFO_CHAR(c) (IS_ALPHANUM(c) || IS_MARK(c) || (c) == '%' || \
  (c) == ';' || (c) == ':' || (c) == '&' || (c) == '=' || (c) == '+' || \
  (c) == '$' || (c) == ',')

#define HEX2DEC(c) (IS_NUM(c) ? ((c) - '0') : (LOWER(c) - 'a' + 10))
#define DEC2HEX(d) (IS_NUM((d) + '0') ? ((d) + '0') : ((d) + 'A' - 10))

#define MCL_HTTP__HEADER_BUF_MIN_SIZE ( 4 * 1024)
#define MCL_HTTP__HEADER_BUF_DEF_SIZE (32 * 1024)

#define TEST_BIT(s, n)  ((s) & (1 << (n)))
#define SET_BIT(s, n)   ((s) |= (1 << (n)))
#define CLEAR_BIT(s, n) ((s) &= ~(1 << (n)))

#define MCL_HTTP__STATUS_LINE_MAX 256


typedef struct mcl_http_field_s mcl_http_field_t;

struct mcl_http_s
{
	void *cgilist[2];
	int closing;
	unsigned int strict_mode;
	unsigned int header_buf_size;
	unsigned int refcnt;
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
	mcl_http_t *server;
	mcl_stream_t *stream;

	http_parser parser;
	struct http_parser_url parser_url;
	//unsigned int flags;
	unsigned short f_closing;
	unsigned short f_req_complete;
	unsigned short f_cgi_complete;
	unsigned short f_resp_complete;
	unsigned short f_internal_error;
	unsigned int refcnt;

	char *data_buf;
	uint32_t data_buf_size;
	uint32_t data_received;
	uint32_t data_parsed;
	uint32_t header_size;

	char *current_buf;
	uint32_t current_len;
	char *url;
	char *path;
	mcl_http_field_t *query_first;
	mcl_http_field_t *field_first;

	// 请求回调.
	void *refcgi[2];
	mcl_http_cgi_t *cgi;
	mcl_http_data_cb req_content_cb;

	// 特殊字段特殊处理，其他字段直接添加到缓冲区，不做重复检查.
	struct {
		unsigned short http_major;
		unsigned short http_minor;
		unsigned int status_code;

		uint32_t field_set;
		uint32_t fields_len;
	} resp;

	char *resp_fields_buf;
	uint32_t resp_fields_buf_size;

	void *data;
};


void mcl_fatal_error(const int errorno, const char *syscall)
{
	fprintf(stderr, "%s: (%d) %s", syscall ? syscall : __FUNCTION__, errorno, uv_strerror(uv_translate_sys_error(errorno)));
	abort();
}


static void mcl_http__inc_refcnt(mcl_http_t *server)
{
	server->refcnt += 1;
}
static void mcl_http__dec_refcnt(mcl_http_t *server)
{
	server->refcnt -= 1;
	if (server->refcnt == 0) {
		CHECK(server->closing);
		free(server);
	}
}

static mcl_http_conn_t *mcl_http_conn__create(mcl_http_t *server)
{
	mcl_http_conn_t *conn;
	conn = (mcl_http_conn_t *)malloc(sizeof(mcl_http_conn_t));

	if (conn != NULL) {
		memset(conn, 0, sizeof(mcl_http_conn_t));
		conn->server = server;
		conn->stream = NULL;
		conn->data_buf = NULL;

		QUEUE_INIT(&conn->refcgi);
		http_parser_init(&conn->parser, HTTP_REQUEST);
		conn->parser.data = conn;

		conn->refcnt = 1;
		mcl_http__inc_refcnt(server);
	}

	return conn;
}
static void mcl_http_conn__destroy(mcl_http_conn_t *conn)
{
	if (!QUEUE_EMPTY(&conn->refcgi))
		QUEUE_REMOVE(&conn->refcgi);
	if (conn->stream != NULL)
		mcl_stream_close(conn->stream, NULL);
	if (conn->data_buf != NULL)
		free(conn->data_buf);

	mcl_http__dec_refcnt(conn->server);
	free(conn);
}

static void mcl_http_conn__dec_refcnt(mcl_http_conn_t *conn)
{
	conn->refcnt -= 1;
	if (conn->refcnt == 0) {
		mcl_http_conn__destroy(conn);
	}
}
static void mcl_http_conn__inc_refcnt(mcl_http_conn_t *conn)
{
	conn->refcnt += 1;
}


mcl_stream_t *mcl_http_get_stream(mcl_http_conn_t *conn)
{
	return conn->stream;
}

mcl_http_cgi_t *mcl_http_get_cgi(mcl_http_conn_t *conn)
{
	return conn->cgi;
	//return QUEUE_EMPTY(&conn->refcgi) ? NULL : conn->cgi;
}

const char *mcl_http_get_method(mcl_http_conn_t *conn)
{
	return http_method_str(conn->parser.method);
}

const char *mcl_http_get_path(mcl_http_conn_t *conn)
{
	return conn->path;
}

const char *mcl_http_get_query(mcl_http_conn_t *conn, const char *name)
{
	mcl_http_field_t *field = conn->query_first;
	while (field != NULL) {
		if (strcmp(field->key, name) == 0)
			return field->val;
		field = field->next;
	}
	return NULL;
}
int mcl_http_query_foreach(mcl_http_conn_t *conn, void *data, int(*cb)(void *data, const char *name, const char *value))
{
	int n = 0;
	mcl_http_field_t *field = conn->query_first;
	while (field != NULL) {
		n += 1;
		if (cb(data, field->key, field->val))
			break;
		field = field->next;
	}
	return n;
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
int mcl_http_header_foreach(mcl_http_conn_t *conn, void *data, int(*cb)(void *data, const char *name, const char *value))
{
	int n = 0;
	mcl_http_field_t *field = conn->field_first;
	while (field != NULL) {
		n += 1;
		if (cb(data, field->key, field->val))
			break;
		field = field->next;
	}
	return n;
}

int mcl_http_read_data(mcl_http_conn_t *conn, mcl_http_data_cb data_cb)
{
	if (conn->f_req_complete)
		return UV_EOF;
	conn->req_content_cb = data_cb;
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

	if (conn->server->strict_mode) {
		// 非法字符检查.
		for (i = 0; name[i]; ++i) {
			if (name[i] == CR || name[i] == LF || name[i] == '=' || name[i] == ' ') {
				UNREACHABLE_ASSERT();
				return UV_EINVAL;
			}
		}
		for (i = 0; value[i]; ++i) {
			if (value[i] == CR || value[i] == LF) {
				UNREACHABLE_ASSERT();
				return UV_EINVAL;
			}
		}
	}

	// Transfer-Encoding.
	if (len == rf_map_info[RF_TRANSFER_ENCODING].length && mcl_strcasecmp(name, rf_map_info[RF_TRANSFER_ENCODING].field) == 0) {
		UNREACHABLE_ASSERT();
		return UV_EINVAL;
	}
	// Content-Length.
	if (len == rf_map_info[RF_CONTENT_LENGTH].length && mcl_strcasecmp(name, rf_map_info[RF_CONTENT_LENGTH].field) == 0) {
		UNREACHABLE_ASSERT();
		return UV_EINVAL;
	}

	for (i = 0; i < RF_MAX; ++i) {
		if (len == rf_map_info[i].length && mcl_strcasecmp(name, rf_map_info[i].field) == 0) {
			if (TEST_BIT(conn->resp.field_set, i))
				return UV_EEXIST;

			if (mcl_http__set_header(conn, name, value))
				return UV_E2BIG;

			SET_BIT(conn->resp.field_set, i);

			switch (i)
			{
			case RF_CONNECTION:
				mcl_http_connection_close(conn);
				break;
			default:
				break;
			}

			return 0;
		}
	}

	if (mcl_http__set_header(conn, name, value))
		return UV_E2BIG;

	return 0;
}

static const char *mcl_http_status_string(mcl_http_t *server, unsigned int status_code)
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

static const char *mcl_http_guess_content_type(mcl_http_conn_t *conn, const char *data, size_t length)
{
	// TODO: 通过响应内容猜测数据类型.
	const char *path = mcl_http_get_path(conn);
	const char *suffix = strrchr(path, '.');
	const char *content_type = "application/octet-stream";

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

void mcl_http_connection_close(mcl_http_conn_t *conn)
{
	// TODO: Close Connection.
	if (!conn->f_closing) {
		conn->f_closing = 1;
		mcl_stream_read_stop(conn->stream);
		mcl_http_conn__dec_refcnt(conn);
	}
}
void *mcl_http_connection_get_data(mcl_http_conn_t *conn)
{
	return conn->data;
}
void mcl_http_connection_set_data(mcl_http_conn_t *conn, void *data)
{
	conn->data = data;
}

static void mcl_http__on_write_data(mcl_stream_write_t *req, int status)
{
	mcl_http_conn_t *conn = (mcl_http_conn_t *)req->data;

	free(req);
	if (status < 0) {
		printf("http write data error: %s\n", uv_strerror(status));
		mcl_http_connection_close(conn);
	}

	mcl_http_conn__dec_refcnt(conn);
}

int mcl_http_write_data(mcl_http_conn_t *conn, const char *data, size_t length)
{
	int err;
	int status_len;
	size_t package_len = 0;
	uv_buf_t *buf;
	mcl_stream_write_t *req;
	char status_buf[MCL_HTTP__STATUS_LINE_MAX];

	if (length > INT_MAX)
		return UV_E2BIG;
	if (conn->f_resp_complete)
		return UV_EBUSY;
	if (conn->f_internal_error)
		return UV_EBUSY;

	unsigned short http_major = conn->resp.http_major ? conn->resp.http_major : 1;
	unsigned short http_minor = conn->resp.http_minor ? conn->resp.http_minor : 1;
	unsigned int status_code = conn->resp.status_code ? conn->resp.status_code : 200;

	package_len = 192 + conn->resp.fields_len + length;
	status_len = snprintf(
		status_buf, sizeof(status_buf), "HTTP/%hu.%hu %u %s\r\n",
		http_major, http_minor, status_code, mcl_http_status_string(conn->server, status_code));

	CHECK(status_len > 0);
	if (status_len >= (int)sizeof(status_buf)) {
		status_buf[sizeof(status_buf) - 3] = '\r';
		status_buf[sizeof(status_buf) - 2] = '\n';
		status_buf[sizeof(status_buf) - 1] = '\0';
		status_len = sizeof(status_buf) - 1;
	}

	req = (mcl_stream_write_t *)malloc(sizeof(mcl_stream_write_t) + sizeof(uv_buf_t) + package_len);
	if (req == NULL) {
		conn->f_internal_error = 1;
		return UV_ENOMEM;
	}
	buf = (uv_buf_t *)&req[1];
	buf->base = (char *)&buf[1];
	memcpy(buf->base, status_buf, status_len);
	memcpy(buf->base + status_len, conn->resp_fields_buf, conn->resp.fields_len);
	buf->len = status_len + conn->resp.fields_len;

	// Connection置位，则关闭连接，默认为连接保持.
	if (conn->f_closing && !TEST_BIT(conn->resp.field_set, RF_CONNECTION))
		buf->len += sprintf(buf->base + buf->len, "Connection: close\r\n");

	if (data != NULL && !TEST_BIT(conn->resp.field_set, RF_CONTENT_TYPE))
		buf->len += sprintf(buf->base + buf->len, "Content-Type: %s\r\n", mcl_http_guess_content_type(conn, data, length));

	buf->len += sprintf(buf->base + buf->len, "Content-Length: %u\r\n", (unsigned int)length);
	buf->len += sprintf(buf->base + buf->len, "\r\n");

	if (data != NULL) {
		memcpy(buf->base + buf->len, data, length);
		buf->len += (unsigned long)length;
	}

	req->data = conn;
	err = mcl_stream_write(conn->stream, req, buf, 1, mcl_http__on_write_data);
	if (err != 0) {
		free(req);
		conn->f_internal_error = 1;
		return err;
	}

	conn->f_resp_complete = 1;
	mcl_http_conn__inc_refcnt(conn);
	return err;
}


static void mcl_http__read_alloc(mcl_stream_t *stream, size_t suggested_size, uv_buf_t *buf)
{
	uint32_t header_buf_size;
	mcl_http_conn_t *conn = (mcl_http_conn_t *)stream->data;

	if (conn->data_buf == NULL) {
		assert(conn->data_received == 0);
		header_buf_size = conn->server->header_buf_size;
		if (header_buf_size == 0)
			header_buf_size = MCL_HTTP__HEADER_BUF_DEF_SIZE;
		else if (header_buf_size < MCL_HTTP__HEADER_BUF_MIN_SIZE)
			header_buf_size = MCL_HTTP__HEADER_BUF_MIN_SIZE;

		// 请求头解析、请求内容接收、响应字段.
		conn->data_buf = malloc(header_buf_size + 1024 + header_buf_size);
		if (conn->data_buf == NULL) {
			buf->base = NULL;
			buf->len = 0;
			return;
		}

		conn->data_buf_size = header_buf_size + 1024;
		conn->resp_fields_buf = conn->data_buf + header_buf_size + 1024;
		conn->resp_fields_buf_size = header_buf_size;
	}

	buf->base = conn->data_buf + conn->data_received;
	buf->len = conn->data_buf_size - conn->data_received;
}




mcl_http_field_t *field_pool = NULL;

mcl_http_field_t *mcl_http_field_new(mcl_http_t *server)
{
	mcl_http_field_t *field;

	if (field_pool == NULL)
		field = (mcl_http_field_t *)malloc(sizeof(mcl_http_field_t));
	else {
		field = field_pool;
		field_pool = field_pool->next;
	}
	field->key = NULL;
	field->val = NULL;
	field->next = NULL;

	return field;
}
void mcl_http_field_delete(mcl_http_field_t *field)
{
	field->next = field_pool;
	field_pool = field;
	//free(field);
}




mcl_http_conn_t *mcl_http_conn_from_parser(http_parser *parser)
{
	return (mcl_http_conn_t *)parser->data;
}

static void mcl_http_conn_cleanup(mcl_http_conn_t *conn)
{
	mcl_http_field_t *field;

	conn->current_buf = NULL;
	conn->current_len = 0;
	conn->url = NULL;
	conn->path = NULL;

	conn->f_cgi_complete = 0;
	conn->f_resp_complete = 0;

	memset(&conn->resp, 0, sizeof(conn->resp));

	while (conn->query_first != NULL) {
		field = conn->query_first;
		conn->query_first = field->next;
		mcl_http_field_delete(field);
	}
	while (conn->field_first != NULL) {
		field = conn->field_first;
		conn->field_first = field->next;
		mcl_http_field_delete(field);
	}
}



size_t mcl_urlencode(const char *in, size_t len, char *out, size_t out_size)
{
	size_t i;
	size_t out_len = 0;

	if (out_size == 0)
		return 0;

	for (i = 0; i < len && out_len + 1 < out_size; ++i) {
		if (in[i] == '\0')
			break;

		if (IS_ALPHANUM(in[i]) || IS_MARK(in[i]))
			out[out_len++] = in[i];
		else {
			if (out_len + 3 >= out_size)
				break;

			out[out_len++] = '%';
			out[out_len++] = DEC2HEX(in[i] >> 4);
			out[out_len++] = DEC2HEX(in[i] & 0x0F);
		}
	}
	out[out_len] = '\0';

	return out_len;
}

size_t mcl_urldecode(const char *in, size_t len, char *out, size_t out_size)
{
	size_t i;
	size_t out_len = 0;

	if (out_size == 0)
		return 0;

	for (i = 0; i < len && out_len + 1 < out_size; ++i) {
		if (in[i] == '\0')
			break;

		if (in[i] != '%')
			out[out_len++] = in[i];
		else if (IS_HEX(in[i + 1]) && IS_HEX(in[i + 2])) {
			out[out_len++] = HEX2DEC(in[i + 1]) * 16 + HEX2DEC(in[i + 2]);
			i += 2;
		}
	}
	out[out_len] = '\0';

	return out_len;
}

int mcl_http_query_parse(mcl_http_conn_t *conn, char *query)
{
	int i;
	char *key, *val;
	mcl_http_field_t *field;

	for (i = 0; query[i]; ) {
		key = &query[i];
		while (query[i] && query[i] != '=' && query[i] != '&')
			i++;

		if (query[i] != '=')
			val = &query[i];
		else {
			query[i++] = 0;
			val = &query[i];
			while (query[i] && query[i] != '&')
				i++;
		}

		if (query[i])
			query[i++] = 0;

		mcl_urldecode(key, strlen(key), key, INT_MAX);
		mcl_urldecode(val, strlen(val), val, INT_MAX);
		if (key[0] || val[0]) {
			field = mcl_http_field_new(conn->server);
			field->next = conn->query_first;
			conn->query_first = field;
			conn->query_first->key = key;
			conn->query_first->val = val;
		}
	}

	return 0;
}



static int on_message_begin(http_parser *parser)
{
	//mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	return 0;
}


static int on_url(http_parser *parser, const char *at, size_t length)
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

#define ROL(v, n) (((v) << (n)) | ((v) >> (sizeof(v) * 8 - (n))))
#define ROR(v, n) (((v) >> (n)) | ((v) << (sizeof(v) * 8 - (n))))

static unsigned int mcl_http__hash(const char *path, size_t length)
{
	size_t i;
	unsigned int hash = 0;

	for (i = 0; i < length; ++i) {
		hash = ROL(hash, 8) ^ (unsigned char)path[i];
	}

	return hash;
}

static mcl_http_cgi_t *mcl_http_cgi_find(mcl_http_t *server, const char *path, size_t length)
{
	QUEUE *q;
	mcl_http_cgi_t *cgi;
	unsigned int hash = mcl_http__hash(path, length);

	QUEUE_FOREACH(q, &server->cgilist) {
		cgi = QUEUE_DATA(q, mcl_http_cgi_t, list);
		if (hash == cgi->hash && strncmp(path, cgi->path, length) == 0 && cgi->path[length] == 0)
			return cgi;
	}
	return NULL;
}

#define MCL_HTTP__PAGE_404 "404 Object Not Found"

static int on_url_complete(mcl_http_conn_t *conn)
{
	int err;
	size_t len;
	struct http_parser_url u;
	ASSERT(conn->url == conn->current_buf);

	http_parser_url_init(&u);
	err = http_parser_parse_url(conn->url, conn->current_len, 0, &u);
	if (err != 0) {
		mcl_http_connection_close(conn);
		mcl_http_set_status(conn, 404);
		mcl_http_set_header(conn, "Content-Type", "text/html; charset=utf-8");
		mcl_http_write_data(conn, MCL_HTTP__PAGE_404, strlen(MCL_HTTP__PAGE_404));
		return -1;
	}

	if (!(u.field_set & (1 << UF_PATH))) {
		mcl_http_connection_close(conn);
		mcl_http_set_status(conn, 404);
		mcl_http_set_header(conn, "Content-Type", "text/html; charset=utf-8");
		mcl_http_write_data(conn, MCL_HTTP__PAGE_404, strlen(MCL_HTTP__PAGE_404));
		return -1;
	}

	conn->path = &conn->url[u.field_data[UF_PATH].off];
	conn->path[u.field_data[UF_PATH].len] = 0;
	len = mcl_urldecode(conn->path, u.field_data[UF_PATH].len, conn->path, INT_MAX);

	conn->cgi = mcl_http_cgi_find(conn->server, conn->path, len);
	if (conn->cgi == NULL && conn->path[0] == '/')
		conn->cgi = mcl_http_cgi_find(conn->server, conn->path + 1, len - 1);
	if (conn->cgi == NULL) {
		mcl_http_connection_close(conn);
		mcl_http_set_status(conn, 404);
		mcl_http_set_header(conn, "Content-Type", "text/html; charset=utf-8");
		mcl_http_write_data(conn, MCL_HTTP__PAGE_404, strlen(MCL_HTTP__PAGE_404));
		return -1;
	}
	QUEUE_INSERT_TAIL(&conn->cgi->reflist, &conn->refcgi);

	if (u.field_set & (1 << UF_QUERY)) {
		conn->url[u.field_data[UF_QUERY].off + u.field_data[UF_QUERY].len] = 0;
		mcl_http_query_parse(conn, &conn->url[u.field_data[UF_QUERY].off]);
	}

	return 0;
}

static int on_status(http_parser *parser, const char *at, size_t length)
{
	UNREACHABLE();
	printf("%s: %.*s\n", __FUNCTION__, (int)length, at);
	return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length)
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
		conn->field_first = mcl_http_field_new(conn->server);
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
		field = mcl_http_field_new(conn->server);
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

static int on_header_value(http_parser *parser, const char *at, size_t length)
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

static int on_headers_complete(http_parser *parser)
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

	if (!QUEUE_EMPTY(&conn->refcgi) && conn->cgi->cb) {
		conn->cgi->cb(conn);
		conn->f_cgi_complete = 1;
	}
	return 0;
}

static int on_body(http_parser *parser, const char *at, size_t length)
{
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	if (!conn->header_size)
		conn->header_size = (uint32_t)((char *)at - conn->data_buf);

	if (conn->req_content_cb)
		conn->req_content_cb(conn, at, length);

	return 0;
}

static int on_message_complete(http_parser *parser)
{
	mcl_http_conn_t *conn = mcl_http_conn_from_parser(parser);

	// 消息完成，暂停解析.
	conn->f_req_complete = 1;
	http_parser_pause(parser, 1);

	if (conn->req_content_cb) {
		conn->req_content_cb(conn, NULL, 0);
		conn->req_content_cb = NULL;
	}
	if (!QUEUE_EMPTY(&conn->refcgi) && conn->cgi->cb && !conn->f_cgi_complete && !conn->f_resp_complete) {
		conn->cgi->cb(conn);
		conn->f_cgi_complete = 1;
	}

	if (!conn->f_resp_complete) {
		// TODO: 检查内部错误.
		if (conn->f_internal_error) {
			mcl_http_connection_close(conn);
			mcl_http_set_status(conn, 500);
			mcl_http_write_data(conn, NULL, 0);
		}
		else if (conn->f_cgi_complete) {
			mcl_http_set_status(conn, 200);
			mcl_http_write_data(conn, NULL, 0);
		}
		else {
			mcl_http_set_status(conn, 404);
			mcl_http_write_data(conn, NULL, 0);
		}
	}
	if (!QUEUE_EMPTY(&conn->refcgi)) {
		QUEUE_REMOVE(&conn->refcgi);
		QUEUE_INIT(&conn->refcgi);
	}
	conn->f_internal_error = 0;
	mcl_http_conn_cleanup(conn);
	return 0;
}


static const http_parser_settings __parser_settings =
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

static void mcl_http__on_read(mcl_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	mcl_http_conn_t *conn = (mcl_http_conn_t *)stream->data;
	mcl_http_conn__inc_refcnt(conn);

	if (nread < 0) {
		http_parser_execute(&conn->parser, &__parser_settings, conn->data_buf + conn->data_parsed, 0);
		if (conn->req_content_cb) {
			conn->req_content_cb(conn, NULL, 0);
			conn->req_content_cb = NULL;
		}
		mcl_http_connection_close(conn);
	}
	else if (nread > 0) {
		ASSERT(buf->base == conn->data_buf + conn->data_received);
		conn->data_received += (uint32_t)nread;

		while (conn->data_parsed < conn->data_received) {
			conn->data_parsed += (uint32_t)http_parser_execute(&conn->parser, &__parser_settings, conn->data_buf + conn->data_parsed, conn->data_received - conn->data_parsed);
			if (conn->f_req_complete) {
				// 消息处理完成，清理当前请求数据.
				if (conn->data_parsed < conn->data_received)
					memmove(conn->data_buf, conn->data_buf + conn->data_parsed, conn->data_received - conn->data_parsed);
				conn->data_received -= conn->data_parsed;
				conn->data_parsed = 0;
				conn->header_size = 0;
				conn->f_req_complete = 0;
				http_parser_pause(&conn->parser, 0);
			}
			else if (conn->data_parsed == conn->data_received) {
				if (conn->data_received > conn->header_size && conn->header_size != 0) {
					// Content接收缓冲区设置在Header尾部.
					conn->data_received = conn->header_size;
					conn->data_parsed = conn->header_size;
				}
			}
			else {
				if (conn->req_content_cb) {
					conn->req_content_cb(conn, NULL, 0);
					conn->req_content_cb = NULL;
				}
				mcl_http_connection_close(conn);
				break;
			}
		}
	}

	mcl_http_conn__dec_refcnt(conn);
}


mcl_http_t *mcl_http_create()
{
	mcl_http_t *server = (mcl_http_t *)malloc(sizeof(mcl_http_t));

	if (server != NULL) {
		QUEUE_INIT(&server->cgilist);
		server->closing = 0;
		server->strict_mode = 0;
		server->header_buf_size = 0;
		server->refcnt = 1;
	}
	return server;
}
void mcl_http_destroy(mcl_http_t *server)
{
	QUEUE *q;
	ASSERT(!server->closing);

	server->closing = 1;
	while (!QUEUE_EMPTY(&server->cgilist)) {
		q = QUEUE_HEAD(&server->cgilist);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
	}
	mcl_http__dec_refcnt(server);
}

int mcl_http_register(mcl_http_t *server, mcl_http_cgi_t *req, const char *path, mcl_http_cgi_cb cb)
{
	if (server == NULL || req == NULL || path == NULL || cb == NULL)
		return UV_EINVAL;

	req->path = path;
	req->cb = cb;
	req->hash = mcl_http__hash(path, strlen(path));
	QUEUE_INIT(&req->reflist);
	QUEUE_INSERT_HEAD(&server->cgilist, &req->list);

	return 0;
}
void mcl_http_unregister(mcl_http_t *server, mcl_http_cgi_t *req)
{
	QUEUE *q;

	if (server->strict_mode) {
		QUEUE_FOREACH(q, &server->cgilist) {
			if (q == &req->list)
				goto found;
		}
		UNREACHABLE();
	}

found:
	QUEUE_REMOVE(&req->list);
	QUEUE_INIT(&req->list);
	while (!QUEUE_EMPTY(&req->reflist)) {
		q = QUEUE_HEAD(&req->reflist);
		QUEUE_REMOVE(q);
		QUEUE_INIT(q);
	}
}

// TODO: 开始一个连接.
int mcl_http_new_connection(mcl_http_t *server, mcl_stream_t *stream)
{
	int err;
	mcl_http_conn_t *conn;

	conn = mcl_http_conn__create(server);
	if (conn == NULL)
		return UV_ENOMEM;

	err = mcl_stream_read_start(stream, mcl_http__read_alloc, mcl_http__on_read);
	if (err < 0) {
		mcl_http_conn__destroy(conn);
		return err;
	}

	conn->stream = stream;
	conn->stream->data = conn;
	return 0;
}
