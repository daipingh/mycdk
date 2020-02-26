
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
			closure->read_cb(strm, nread, uvbuf);
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
			pbufs.data(),
			(unsigned int)pbufs.size(),
			closure,
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
	std::shared_ptr<mcl_urlparser_t> get_c_ptr()
	{
		return parser;
	}
	std::shared_ptr<const mcl_urlparser_t> get_c_ptr() const
	{
		return parser;
	}

	int parse(const std::string &u)
	{
		*url = u;
		return mcl_url_parse(parser.get(), url->c_str(), url->length());
	}
	int parse(std::string &&u)
	{
		*url = std::move(u);
		return mcl_url_parse(parser.get(), url->c_str(), url->length());
	}

	std::string get_schema() const { int r; const char *p = mcl_url_get_schema(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_schema(int &r) const { const char *p = mcl_url_get_schema(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_host() const { int r; const char *p = mcl_url_get_host(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_host(int &r) const { const char *p = mcl_url_get_host(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_port() const { int r; const char *p = mcl_url_get_port(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_port(int &r) const { const char *p = mcl_url_get_port(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_path() const { int r; const char *p = mcl_url_get_path(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_path(int &r) const { const char *p = mcl_url_get_path(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_query() const { int r; const char *p = mcl_url_get_query(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_query(int &r) const { const char *p = mcl_url_get_query(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_fragment() const { int r; const char *p = mcl_url_get_fragment(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_fragment(int &r) const { const char *p = mcl_url_get_fragment(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_userinfo() const { int r; const char *p = mcl_url_get_userinfo(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }
	std::string get_userinfo(int &r) const { const char *p = mcl_url_get_userinfo(parser.get(), &r); return r < 0 ? std::string() : std::string(p, r); }

	urlparser()
	{
		auto s = std::make_shared<std::string>();
		url = s;
		parser = std::shared_ptr<mcl_urlparser_t>(new mcl_urlparser_t, [s](mcl_urlparser_t *p) { delete p; });
		mcl_url_parse(parser.get(), url->c_str(), url->length());
	}
	urlparser(const std::string &u)
	{
		auto s = std::make_shared<std::string>(u);
		url = s;
		parser = std::shared_ptr<mcl_urlparser_t>(new mcl_urlparser_t, [s](mcl_urlparser_t *p) { delete p; });
		mcl_url_parse(parser.get(), url->c_str(), url->length());
	}
	urlparser(std::string &&u)
	{
		auto s = std::make_shared<std::string>(std::move(u));
		url = s;
		parser = std::shared_ptr<mcl_urlparser_t>(new mcl_urlparser_t, [s](mcl_urlparser_t *p) { delete p; });
		mcl_url_parse(parser.get(), url->c_str(), url->length());
	}

	urlparser(const std::shared_ptr<mcl_urlparser_t> &_p)
	{
		auto s = std::make_shared<std::string>();
		url = s;
		parser = std::shared_ptr<mcl_urlparser_t>(_p.get(), [_p, s](mcl_urlparser_t *p) { p = nullptr; });
	}

private:
	std::shared_ptr<mcl_urlparser_t> parser;
	std::shared_ptr<std::string> url;
};

class http
{
public:
	class conn :
		public std::enable_shared_from_this<conn>
	{
	public:
		typedef std::function<int(const char *name, const char *value)> field_cb_type;
		typedef std::function<void(const char *chunk, ssize_t length)> data_cb_type;
		typedef std::function<void(int status)> send_cb_type;

		std::shared_ptr<conn> get_ptr()
		{
			return shared_from_this();
		}
		std::shared_ptr<mcl_http_conn_t> get_c_ptr()
		{
			return c_ptr;
		}

		std::shared_ptr<const urlparser> get_urlparser()
		{
			std::shared_ptr<const urlparser> p = uparser.lock();
			if (!p.get()) {
				std::shared_ptr<mcl_http_conn_t> c = c_ptr;
				p = std::make_shared<const urlparser>(
					std::shared_ptr<mcl_urlparser_t>((mcl_urlparser_t *)mcl_http_get_urlparser(c.get()), [c](mcl_urlparser_t *p) { p = NULL; }));
				uparser = p;
			}
			return p;
		}
		const char *get_method()
		{
			return mcl_http_get_method(c_ptr.get());
		}
		const char *get_path()
		{
			return mcl_http_get_path(c_ptr.get());
		}
		const char *get_query(const char *name)
		{
			return mcl_http_get_query(c_ptr.get(), name);
		}
		const char *get_header(const char *name)
		{
			return mcl_http_get_header(c_ptr.get(), name);
		}

		//int query_parse(char *query)
		//{
		//	return mcl_http_query_parse(c_ptr.get(), query);
		//}

		int header_foreach(const field_cb_type &field_cb)
		{
			field_cb_type _field_cb = field_cb;
			return mcl_http_header_foreach(
				c_ptr.get(), &_field_cb,
				[](void *arg, const char *name, const char *value) {
				return (*(field_cb_type *)arg)(name, value);
			});
		}
		int query_foreach(const field_cb_type &field_cb)
		{
			field_cb_type _field_cb = field_cb;
			return mcl_http_query_foreach(
				c_ptr.get(), &_field_cb,
				[](void *arg, const char *name, const char *value) {
				return (*(field_cb_type *)arg)(name, value);
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
		int send(const void *data, size_t length)
		{
			return mcl_http_send(c_ptr.get(), data, length, nullptr, nullptr);
		}
		int send(const void *data, size_t length, const send_cb_type &send_cb)
		{
			struct _Closure
			{
				_Closure(const send_cb_type &send_cb) : send_cb(send_cb) {}

				send_cb_type send_cb;
			};
			int err;
			_Closure *closure = new _Closure(send_cb);

			err = mcl_http_send(
				c_ptr.get(), data, length,
				closure,
				[](void *arg, int status) {
				_Closure *closure = (_Closure *)arg;
				closure->send_cb(status);
				delete closure;
			});

			if (err < 0)
				delete closure;
			return err;
		}
		int send_data(const void *data, size_t length)
		{
			return mcl_http_send_data(c_ptr.get(), data, length, nullptr, nullptr);
		}
		int send_data(const void *data, size_t length, const send_cb_type &send_cb)
		{
			struct _Closure
			{
				_Closure(const send_cb_type &send_cb) : send_cb(send_cb) {}

				send_cb_type send_cb;
			};
			int err;
			_Closure *closure = new _Closure(send_cb);

			err = mcl_http_send_data(
				c_ptr.get(), data, length,
				closure,
				[](void *arg, int status) {
				_Closure *closure = (_Closure *)arg;
				closure->send_cb(status);
				delete closure;
			});

			if (err < 0)
				delete closure;
			return err;
		}

	protected:
		conn(const std::shared_ptr<mcl_http_conn_t> &con) : c_ptr(con) {}
		conn() = delete;
		conn(const conn &) = delete;
		conn(conn &&) = delete;

	private:
		std::shared_ptr<mcl_http_conn_t> c_ptr;
		std::weak_ptr<const urlparser> uparser;
	};

	class conf :
		public std::enable_shared_from_this<conf>
	{
	public:

		std::shared_ptr<conf> get_ptr()
		{
			return shared_from_this();
		}
		std::shared_ptr<mcl_http_conf_t> get_c_ptr()
		{
			return c_ptr;
		}

		static std::shared_ptr<conf> create()
		{
			std::shared_ptr<conf> cfg;
			mcl_http_conf_t *p = mcl_http_conf_create();
			if (p != nullptr)
				cfg = std::shared_ptr<conf>(new conf(std::shared_ptr<mcl_http_conf_t>(p, [](mcl_http_conf_t *p) { mcl_http_conf_destroy(p); })));
			return cfg;
		}

	protected:
		conf(const std::shared_ptr<mcl_http_conf_t> &cfg) : c_ptr(cfg) {}
		conf() = delete;
		conf(const conf &) = delete;
		conf(conf &&) = delete;

	private:
		std::shared_ptr<mcl_http_conf_t> c_ptr;
	};


	typedef std::function<void(std::shared_ptr<conn>)> connection_cb_type;

	static int new_connection(const std::shared_ptr<stream> &strm, const std::shared_ptr<conf> &conf, const connection_cb_type &connection_cb)
	{
		struct _conn : conn { _conn(const std::shared_ptr<mcl_http_conn_t> &hc) : conn(hc) {} };
		struct _Closure
		{
			_Closure(const std::shared_ptr<stream> &strm, const connection_cb_type &connection_cb) : strm(strm), connection_cb(connection_cb) {}

			std::shared_ptr<stream> strm;
			connection_cb_type connection_cb;
			char conn_storage[sizeof(conn)];
		};
		int err;
		_Closure *closure = new _Closure(strm, connection_cb);

		err = mcl_http_new_connection(
			strm->get_c_ptr().get(), conf->get_c_ptr().get(),
			closure,
			[](void *arg, mcl_http_conn_t *conn) {
			_Closure *closure = (_Closure *)arg;
			if (conn != nullptr) {
				closure->connection_cb(
					std::shared_ptr<_conn>(
						new(closure->conn_storage) _conn(
							std::shared_ptr<mcl_http_conn_t>(mcl_http_hold(conn), [](mcl_http_conn_t *conn) { mcl_http_release(conn); })),
						[](_conn *c) { c->~_conn(); }));
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
