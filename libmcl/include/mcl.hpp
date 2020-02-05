
#ifndef MCL_HPP_
#define MCL_HPP_

#include <mcl/server.h>
#include <mcl/http.h>

#include <memory>
#include <map>
#include <functional>

MCL_BEGIN_NAMESPACE(mcl)

std::shared_ptr<uv_buf_t> uvbuf_create(size_t size)
{
	std::shared_ptr<uv_buf_t> uvbuf;
	uv_buf_t *buf = (uv_buf_t *)malloc(sizeof(uv_buf_t) + size);
	if (buf != nullptr) {
		buf->base = (char *)&buf[1];
		buf->len = (unsigned long)size;
		uvbuf = std::shared_ptr<uv_buf_t>(buf, [](uv_buf_t *buf) { free(buf); });
	}
	return uvbuf;
}

class stream :
	public std::enable_shared_from_this<stream>
{
public:
	typedef std::function<void(const std::shared_ptr<stream> &strm, size_t suggested_size, std::shared_ptr<uv_buf_t> &buf)> alloc_cb_type;
	typedef std::function<void(const std::shared_ptr<stream> &strm, ssize_t nread, const std::shared_ptr<uv_buf_t> &buf)> read_cb_type;
	typedef std::function<void(int status)> write_cb_type;

	std::shared_ptr<stream> get_ptr()
	{
		return shared_from_this();
	}
	std::shared_ptr<mcl_stream_t> get_c_ptr()
	{
		return c_ptr;
	}

	int read_start(const alloc_cb_type &alloc_cb, const read_cb_type &read_cb)
	{
		int err;
		std::shared_ptr<_ReadClosure> closure = std::make_shared<_ReadClosure>(get_ptr(), alloc_cb, read_cb);

		err = mcl_stream_read_start(
			c_ptr.get(),
			[](mcl_stream_t *c_raw_ptr, size_t suggested_size, uv_buf_t *buf) {
			std::shared_ptr<stream> strm = ((stream *)c_raw_ptr->data)->get_ptr();
			std::shared_ptr<_ReadClosure> closure = strm->read_closure;
			closure->alloc_cb(strm, suggested_size, closure->uvbuf);
			if (closure->uvbuf.get()) {
				buf->base = closure->uvbuf->base;
				buf->len = closure->uvbuf->len;
			}
			else {
				buf->base = nullptr;
				buf->len = 0;
			}
		},
			[](mcl_stream_t *c_raw_ptr, ssize_t nread, const uv_buf_t *buf) {
			std::shared_ptr<stream> strm = ((stream *)c_raw_ptr->data)->get_ptr();
			std::shared_ptr<_ReadClosure> closure = strm->read_closure;
			std::shared_ptr<uv_buf_t> uvbuf = std::move(closure->uvbuf);
			if (nread < 0)
				strm->read_closure.reset();
			closure->read_cb(strm, nread,  uvbuf);
		});

		if (err == 0) {
			c_ptr->data = this;
			read_closure = closure;
		}
		return err;
	}
	int read_stop()
	{
		int err;
		err = mcl_stream_read_stop(c_ptr.get());
		if (err == 0) {
			read_closure.reset();
			c_ptr->data = nullptr;
		}
		return err;
	}
	int write(const std::vector<std::shared_ptr<uv_buf_t> > &bufs, const write_cb_type &write_cb)
	{
		struct _Closure
		{
			_Closure(const std::vector<std::shared_ptr<uv_buf_t> > &bufs, const write_cb_type &write_cb) : bufs(bufs), write_cb(write_cb) {}

			std::vector<std::shared_ptr<uv_buf_t> > bufs;
			write_cb_type write_cb;
		};
		int err;
		_Closure *closure = new _Closure(bufs, write_cb);
		std::vector<uv_buf_t> pbufs;

		pbufs.reserve(bufs.size());
		for (auto ite = bufs.begin(); ite != bufs.end(); ++ite) {
			if ((*ite).get() && (*ite)->base && (*ite)->len)
				pbufs.push_back(**ite);
		}

		err = mcl_stream_write(
			c_ptr.get(),
			closure,
			pbufs.data(),
			(unsigned int)pbufs.size(),
			[](void *arg, int status) {
			_Closure *closure = (_Closure *)arg;
			closure->write_cb(status);
			delete closure;
		});

		if (err < 0)
			delete closure;
		return err;
	}
	int crack()
	{
		return mcl_stream_crack(c_ptr.get());
	}
	int get_prop(int name, void *val, int *len)
	{
		return mcl_stream_get_prop(c_ptr.get(), name, val, len);
	}
	int set_prop(int name, const void *val, int len)
	{
		return mcl_stream_set_prop(c_ptr.get(), name, val, len);
	}

	static std::shared_ptr<stream> wrap(const std::shared_ptr<mcl_stream_t> &strm)
	{
		return std::shared_ptr<stream>(new stream(strm));
	}

protected:
	stream(const std::shared_ptr<mcl_stream_t> &strm) : c_ptr(strm) {}
	stream() = delete;
	stream(const stream &) = delete;
	stream(stream &&) = delete;

private:
	struct _ReadClosure
	{
		_ReadClosure(const std::shared_ptr<stream> &strm, const alloc_cb_type &alloc_cb, const read_cb_type &read_cb) : strm(strm), alloc_cb(alloc_cb), read_cb(read_cb) {}

		std::shared_ptr<stream> strm;
		std::shared_ptr<uv_buf_t> uvbuf;
		alloc_cb_type alloc_cb;
		read_cb_type read_cb;
	};

	std::shared_ptr<mcl_stream_t> c_ptr;
	std::shared_ptr<_ReadClosure> read_closure;
};

class urlparser
{
public:
	const mcl_urlparser_t *c_ptr()
	{
		return &parser;
	}

	int parse(const mcl_urlparser_t *p)
	{
		url = p->url;
		memcpy(&parser, p, sizeof(mcl_urlparser_t));
		parser.url = url.c_str();
	}
	int parse(const std::string &u)
	{
		url = u;
		return mcl_url_parse(&parser, url.c_str(), url.length());
	}
	int parse(std::string &&u)
	{
		url = std::move(u);
		return mcl_url_parse(&parser, url.c_str(), url.length());
	}

	std::string get_schema() const { int r; const char *p = mcl_url_get_schema(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_schema(int &r) const { const char *p = mcl_url_get_schema(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_host() const { int r; const char *p = mcl_url_get_host(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_host(int &r) const { const char *p = mcl_url_get_host(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_port() const { int r; const char *p = mcl_url_get_port(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_port(int &r) const { const char *p = mcl_url_get_port (&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_path() const { int r; const char *p = mcl_url_get_path(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_path(int &r) const { const char *p = mcl_url_get_path(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_query() const { int r; const char *p = mcl_url_get_query(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_query(int &r) const { const char *p = mcl_url_get_query(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_fragment() const { int r; const char *p = mcl_url_get_fragment(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_fragment(int &r) const { const char *p = mcl_url_get_fragment(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_userinfo() const { int r; const char *p = mcl_url_get_userinfo(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_userinfo(int &r) const { const char *p = mcl_url_get_userinfo(&parser, &r); return r < 0 ? std::string() : std::string(p, r); }

	urlparser()
	{
		memset(&parser, 0, sizeof(mcl_urlparser_t));
		parser.url = url.c_str();
	}
	urlparser(const mcl_urlparser_t *p) : url(p->url)
	{
		memcpy(&parser, p, sizeof(mcl_urlparser_t));
		parser.url = url.c_str();
	}
	urlparser(const std::string &u) : url(u)
	{
		mcl_url_parse(&parser, url.c_str(), url.length());
	}
	urlparser(std::string &&u) : url(std::move(u))
	{
		mcl_url_parse(&parser, url.c_str(), url.length());
	}

private:
	mcl_urlparser_t parser;
	std::string url;
};

class http_conn :
	public std::enable_shared_from_this<http_conn>
{
public:
	typedef std::function<int(const char *name, const char *value)> header_cb_type;
	typedef std::function<void(const char *chunk, ssize_t length)> data_cb_type;
	typedef std::function<void(int status)> write_cb_type;

	std::shared_ptr<http_conn> get_ptr()
	{
		return shared_from_this();
	}
	std::shared_ptr<mcl_http_conn_t> get_c_ptr()
	{
		return c_ptr;
	}

	const std::shared_ptr<const urlparser> &get_urlparser()
	{
		return uparser;
	}
	const char *get_method()
	{
		return mcl_http_get_method(c_ptr.get());
	}
	const char *get_path()
	{
		return mcl_http_get_path(c_ptr.get());
	}
	const char *get_query()
	{
		return mcl_http_get_query(c_ptr.get());
	}
	const char *get_header(const char *name)
	{
		return mcl_http_get_header(c_ptr.get(), name);
	}

	int header_foreach(const header_cb_type &header_cb)
	{
		header_cb_type _header_cb = header_cb;
		return mcl_http_header_foreach(
			c_ptr.get(), &_header_cb,
			[](void *arg, const char *name, const char *value) {
			return (*(header_cb_type *)arg)(name, value);
		});
	}
	int on_content(const data_cb_type &data_cb)
	{
		struct _Closure
		{
			_Closure(const data_cb_type &data_cb) : data_cb(data_cb) {}

			data_cb_type data_cb;
		};
		int err;
		_Closure *closure = new _Closure(data_cb);

		err = mcl_http_on_content(
			c_ptr.get(), closure,
			[](void *arg, const char *chunk, ssize_t length) {
			_Closure *closure = (_Closure *)arg;
			closure->data_cb(chunk, length);
			delete closure;
		});

		if (err < 0)
			delete closure;
		return err;
	}

	int set_status(unsigned int status)
	{
		return mcl_http_set_status(c_ptr.get(), status);
	}
	int set_header(const char *name, const char *value)
	{
		return mcl_http_set_header(c_ptr.get(), name, value);
	}
	int write(const void *data, size_t length, const write_cb_type &write_cb)
	{
		struct _Closure
		{
			_Closure(const write_cb_type &write_cb) : write_cb(write_cb) {}

			write_cb_type write_cb;
		};
		int err;
		_Closure *closure = new _Closure(write_cb);

		err = mcl_http_write(
			c_ptr.get(), closure, data, length,
			[](void *arg, int status) {
			_Closure *closure = (_Closure *)arg;
			closure->write_cb(status);
			delete closure;
		});

		if (err < 0)
			delete closure;
		return err;
	}
	int write_data(const void *data, size_t length, const write_cb_type &write_cb)
	{
		struct _Closure
		{
			_Closure(const write_cb_type &write_cb) : write_cb(write_cb) {}

			write_cb_type write_cb;
		};
		int err;
		_Closure *closure = new _Closure(write_cb);

		err = mcl_http_write_data(
			c_ptr.get(), closure, data, length,
			[](void *arg, int status) {
			_Closure *closure = (_Closure *)arg;
			closure->write_cb(status);
			delete closure;
		});

		if (err < 0)
			delete closure;
		return err;
	}

	static std::shared_ptr<http_conn> wrap(const std::shared_ptr<mcl_http_conn_t> &conn, void *mem = nullptr)
	{
		return mem ?
			std::shared_ptr<http_conn>(new(mem) http_conn(conn), [](http_conn *conn) { conn->~http_conn(); }) :
			std::shared_ptr<http_conn>(new http_conn(conn));
	}

protected:
	http_conn(const std::shared_ptr<mcl_http_conn_t> &conn) : c_ptr(conn), uparser(std::make_shared<urlparser>(mcl_http_get_urlparser(conn.get()))) {}
	http_conn() = delete;
	http_conn(const http_conn &) = delete;
	http_conn(http_conn &&) = delete;

private:
	std::shared_ptr<mcl_http_conn_t> c_ptr;
	std::shared_ptr<const urlparser> uparser;
};

class http :
	public std::enable_shared_from_this<http>
{
public:
	typedef std::function<void(std::shared_ptr<http_conn>)> connection_cb_type;

	std::shared_ptr<http> get_ptr()
	{
		return shared_from_this();
	}
	std::shared_ptr<mcl_http_t> get_c_ptr()
	{
		return c_ptr;
	}

	int new_connection(const std::shared_ptr<stream> &strm, const connection_cb_type &connection_cb)
	{
		struct _Closure
		{
			_Closure(const std::shared_ptr<stream> &strm, const connection_cb_type &connection_cb) : strm(strm), connection_cb(connection_cb) {}

			std::shared_ptr<stream> strm;
			connection_cb_type connection_cb;
			char conn_storage[sizeof(http_conn)];
		};
		int err;
		_Closure *closure = new _Closure(strm, connection_cb);

		err = mcl_http_new_connection(
			c_ptr.get(), strm->get_c_ptr().get(), closure,
			[](void *arg, mcl_http_conn_t *conn) {
			_Closure *closure = (_Closure *)arg;
			if (conn != nullptr) {
				closure->connection_cb(mcl::http_conn::wrap(
					std::shared_ptr<mcl_http_conn_t>(mcl_http_hold(conn), [](mcl_http_conn_t *conn) { mcl_http_release(conn); }),
					closure->conn_storage));
			}
			else {
				closure->connection_cb(nullptr);
				delete closure;
			}
		});

		if (err < 0)
			delete closure;
		return err;
	}

	static std::shared_ptr<http> create()
	{
		std::shared_ptr<http> r;
		mcl_http_t *hs = mcl_http_create();
		if (hs != nullptr)
			r = std::shared_ptr<http>(new http(std::shared_ptr<mcl_http_t>(hs, [](mcl_http_t *hs) { mcl_http_destroy(hs); })));
		return r;
	}

protected:
	http(const std::shared_ptr<mcl_http_t> &hs) : c_ptr(hs) {}
	http() = delete;
	http(const http &) = delete;
	http(http &&) = delete;

private:
	std::shared_ptr<mcl_http_t> c_ptr;
};

class server :
	public std::enable_shared_from_this<server>
{
public:
	typedef std::function<void(const std::shared_ptr<stream> &strm)> connection_cb_type;

	std::shared_ptr<server> get_ptr()
	{
		return shared_from_this();
	}
	std::shared_ptr<mcl_server_t> get_c_ptr()
	{
		return c_ptr;
	}

	int start(const connection_cb_type &connection_cb)
	{
		int err;
		std::shared_ptr<_Closure> closure = std::make_shared<_Closure>(get_ptr(), connection_cb);

		err = mcl_server_start(
			c_ptr.get(), this,
			[](void *arg, mcl_stream_t *strm) {
			std::shared_ptr<server> serv = ((server *)arg)->get_ptr();
			std::shared_ptr<_Closure> closure = serv->s_closure;
			std::shared_ptr<stream> connection;
			if (strm == nullptr)
				serv->s_closure.reset();
			else
				connection = mcl::stream::wrap(std::shared_ptr<mcl_stream_t>(strm, [](mcl_stream_t *strm) { mcl_stream_close(strm, nullptr); }));
			closure->connection_cb(connection);
		});

		if (err == 0)
			s_closure = closure;
		return err;
	}
	int stop()
	{
		int err;
		err = mcl_server_stop(c_ptr.get());
		if (err == 0)
			s_closure.reset();
		return err;
	}

	struct tcp
	{
		static std::shared_ptr<server> create(uv_loop_t *loop, const struct sockaddr *sa)
		{
			std::shared_ptr<server> r;
			mcl_server_t *serv = mcl_server_tcp_create(loop, sa, nullptr);
			if (serv != nullptr)
				r = std::shared_ptr<server>(new server(std::shared_ptr<mcl_server_t>(serv, [](mcl_server_t *serv) { mcl_server_destroy(serv); })));
			return r;
		}
		static std::shared_ptr<server> create(uv_loop_t *loop, const struct sockaddr *sa, int &result)
		{
			std::shared_ptr<server> r;
			mcl_server_t *serv = mcl_server_tcp_create(loop, sa, &result);
			if (serv != nullptr)
				r = std::shared_ptr<server>(new server(std::shared_ptr<mcl_server_t>(serv, [](mcl_server_t *serv) { mcl_server_destroy(serv); })));
			return r;
		}
	};

	struct pipe
	{
		static std::shared_ptr<server> create(uv_loop_t *loop, const char *name, int ipc)
		{
			std::shared_ptr<server> r;
			mcl_server_t *serv = mcl_server_pipe_create(loop, name, ipc, nullptr);
			if (serv != nullptr)
				r = std::shared_ptr<server>(new server(std::shared_ptr<mcl_server_t>(serv, [](mcl_server_t *serv) { mcl_server_destroy(serv); })));
			return r;
		}
		static std::shared_ptr<server> create(uv_loop_t *loop, const char *name, int ipc, int &err)
		{
			std::shared_ptr<server> r;
			mcl_server_t *serv = mcl_server_pipe_create(loop, name, ipc, &err);
			if (serv != nullptr)
				r = std::shared_ptr<server>(new server(std::shared_ptr<mcl_server_t>(serv, [](mcl_server_t *serv) { mcl_server_destroy(serv); })));
			return r;
		}
	};

protected:
	server(const std::shared_ptr<mcl_server_t> &serv) : c_ptr(serv) {}
	server() = delete;
	server(const server &) = delete;
	server(server &&) = delete;

private:
	struct _Closure
	{
		_Closure(const std::shared_ptr<server> &serv, const connection_cb_type &connection_cb) : serv(serv), connection_cb(connection_cb) {}

		std::shared_ptr<server> serv;
		connection_cb_type connection_cb;
	};

	std::shared_ptr<mcl_server_t> c_ptr;
	std::shared_ptr<_Closure> s_closure;
};

MCL_END_NAMESPACE

#endif
