
#include <mcl.hpp>
#include <openssl/ssl.h>
#include <mutex>
#include <thread>


static uv_mutex_t *lockarray;

static void lock_callback(int mode, int type, const char *file, int line)
{
	(void)file;
	(void)line;
	if (mode & CRYPTO_LOCK) {
		uv_mutex_lock(&(lockarray[type]));
	}
	else {
		uv_mutex_unlock(&(lockarray[type]));
	}
}


static unsigned long thread_id(void)
{
#if 0
	uv_thread_t id = uv_thread_self();
	size_t id_val = (size_t)id;
	return (unsigned long)((id_val & 0xFFFFFFFF) ^ (id_val >> 32));
#else
	static unsigned long id = 0;
	static std::map<std::thread::id, unsigned long> map;
	static std::mutex mutex;
	std::lock_guard lg(mutex);
	std::thread::id tid = std::this_thread::get_id();

	auto ite = map.find(tid);
	if (ite != map.end())
		return ite->second;

	auto ret = map.insert(std::make_pair(tid, id++));
	return ret.first->second;
#endif
}

static void init_locks(void)
{
	int i;

	lockarray = (uv_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(uv_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		uv_mutex_init(&lockarray[i]);
	}

	CRYPTO_set_id_callback((unsigned long(*)())thread_id);
	CRYPTO_set_locking_callback(lock_callback);
}
static void kill_locks(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		uv_mutex_destroy(&(lockarray[i]));

	OPENSSL_free(lockarray);
}


std::shared_ptr<mcl::stream> sslstream_wrap(uv_loop_t *loop, const std::shared_ptr<mcl::stream> &s, int is_server, SSL_CTX *ssl_ctx, int &result)
{
	std::shared_ptr<mcl_stream_t> s_c_ptr = s->get_c_ptr();
	std::shared_ptr<mcl_stream_t> ssls_c_ptr(
		mcl_sslstream_wrap(loop, s->get_c_ptr().get(), is_server, ssl_ctx, &result, NULL),
		[s_c_ptr](mcl_stream_t *strm) {
		strm->data = new std::shared_ptr<mcl_stream_t>(s_c_ptr);
		mcl_stream_close(strm, [](mcl_stream_t *strm) {
			delete (std::shared_ptr<mcl_stream_t> *)strm->data;
		});
	});
	return mcl::stream::wrap(ssls_c_ptr);
}


struct demo
{
	SSL_CTX *ssl_ctx;

	demo()
	{
		static uv_once_t once_guard = UV_ONCE_INIT;

		uv_once(&once_guard, []() {
			//init_locks();
			SSL_library_init();
			SSL_load_error_strings();
		});


		ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());

		SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
		//SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_COMPRESSION);
		//SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TICKET);


		static const char *crypto = "HIGH:!aNULL:!MD5";

		if (SSL_CTX_set_cipher_list(ssl_ctx, crypto) == 0) {
			printf("SSL_CTX_set_cipher_list returns 0.\n");
			abort();
		}

		static const char *ca_crt = "https_ca.crt";

		// 不验证证书.
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
		//SSL_CTX_load_verify_locations(ssl_ctx, ca_crt, NULL);
		//SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, "123456");

		static const char *server_crt = "https_server.crt";
		static const char *server_key = "https_server.key";

		if (SSL_CTX_use_certificate_file(ssl_ctx, server_crt, SSL_FILETYPE_PEM) == 0) {
			printf("SSL_CTX_use_certificate_file returns 0.\n");
			abort();
		}
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, server_key, SSL_FILETYPE_PEM) == 0) {
			printf("SSL_CTX_use_PrivateKey_file returns 0.\n");
			abort();
		}
		if (SSL_CTX_check_private_key(ssl_ctx) == 0) {
			printf("SSL_CTX_check_private_key returns 0.\n");
			abort();
		}


		struct sockaddr_in6 sa;
		uv_ip6_addr("::", 1234, &sa);
		std::shared_ptr<mcl::server> serv = mcl::server::tcp::create(uv_default_loop(), (struct sockaddr *)&sa);
		std::shared_ptr<mcl::http::conf> conf = mcl::http::conf::create();

		serv->start(
			[this, conf](const std::shared_ptr<mcl::stream> &_strm) {

			char _ip[64] = { 0 };
			struct sockaddr_in6 peername;
			int buflen = sizeof(peername);

			std::string ip;
			int port;
			std::shared_ptr<mcl::stream> strm;
			int result;

			if (_strm.get())
				strm = sslstream_wrap(uv_default_loop(), _strm, 1, ssl_ctx, result);

			if (strm.get()) {
				buflen = sizeof(peername);
				strm->get_prop(MCL_STREAM_PROP_PEERNAME, &peername, &buflen);
				uv_ip6_name(&peername, _ip, sizeof(_ip));
				ip = _ip;
				port = (int)ntohs(peername.sin6_port);
				printf("New connection: %s:%d\n", ip.c_str(), port);

#if 1
				int count = 0;
				// http server.
				mcl::http::new_connection(strm, conf,
					[ip, port, count, strm](const std::shared_ptr<mcl::http::conn> &conn) mutable {

					if (!conn.get())
						printf("Del connection: %s:%d\n", ip.c_str(), port);
					else {
						//conn->set_header("Content-Type", "text/plain; charset=gb2312");
						conn->set_header("Content-Type", "text/plain; charset=utf-8");
						conn->set_header("Transfer-Encoding", "chunked");

						const char *p;
						std::string s;
						s = conn->get_method() + std::string(" ") + conn->get_path();
						printf("%d  %s\n", count, s.c_str());

						p = conn->get_query(NULL);
						if (p && *p)
							s += std::string("?") + p;
						s += "\r\n";

						conn->send(s.c_str(), s.length(), [](int status) {});

						conn->header_foreach(
							[conn](const char *name, const char *value) {
							std::string s(name + std::string(": ") + value + std::string("\r\n"));
							conn->send(s.c_str(), s.length(), [](int status) {});
							return 0;
						});

						conn->send("\r\n", 2, [](int status) {});

						conn->query_foreach(
							[conn](const char *name, const char *value) {
							std::string s(name + std::string("=") + value + std::string("\r\n"));
							conn->send(s.c_str(), s.length(), [](int status) {});
							return 0;
						});

						conn->send(nullptr, 0, [](int status) {});

						count += 1;
						if (count == 6) {
							int v = 1;
							strm->set_prop(MCL_STREAM_PROP_QUEUEWORK, &v, sizeof(v));
						}
					}
				});
#else
				// echo server.
				strm->read_start(
					[](const std::shared_ptr<mcl::stream> &strm, size_t suggested_size, std::shared_ptr<uv_buf_t> &buf) {
					buf = mcl::uvbuf_create(suggested_size);
				},
					[ip, port](const std::shared_ptr<mcl::stream> &strm, ssize_t nread, const std::shared_ptr<uv_buf_t> &buf) {
					if (nread < 0) {
						printf("Del connection: %s:%d %s\n", ip.c_str(), port, uv_strerror((int)nread));
					}
					else {
						buf->len = (unsigned int)nread;
						strm->write(
							{ buf },
							[ip, port](int status) {
							if (status < 0)
								printf("Write error: %s:%d %s\n", ip.c_str(), port, uv_strerror(status));
						});
					}
				});
#endif
			}
		});
	}
};

int main()
{
	demo d;
	uv_run(uv_default_loop(), UV_RUN_DEFAULT);
	return 0;
}
