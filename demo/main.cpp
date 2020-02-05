
#include <mcl.hpp>

struct demo
{
	demo()
	{
		struct sockaddr_in6 sa;
		uv_ip6_addr("::", 1234, &sa);
		std::shared_ptr<mcl::server> serv = mcl::server::tcp::create(uv_default_loop(), (struct sockaddr *)&sa);
		std::shared_ptr<mcl::http> hs = mcl::http::create();

		serv->start(
			[hs](const std::shared_ptr<mcl::stream> &strm) {

			char _ip[64] = { 0 };
			struct sockaddr_in6 peername;
			int buflen = sizeof(peername);

			std::string ip;
			int port;

			if (strm.get()) {
				buflen = sizeof(peername);
				strm->get_prop(MCL_STREAM_PROP_PEERNAME, &peername, &buflen);
				uv_ip6_name(&peername, _ip, sizeof(_ip));
				ip = _ip;
				port = (int)ntohs(peername.sin6_port);
				printf("New connection: %s:%d\n", ip.c_str(), port);

#if 1
				// http server.
				hs->new_connection(strm,
					[ip, port](const std::shared_ptr<mcl::http_conn> &conn) {

					if (!conn.get())
						printf("Del connection: %s:%d\n", ip.c_str(), port);
					else {
						conn->set_header("Content-Type", "text/plain");
						conn->set_header("Transfer-Encoding", "chunked");

						char buf[256];
						snprintf(buf, sizeof(buf), "%s", conn->get_path());
						conn->write(buf, strlen(buf),
							[conn](int status) {
							const char *query = conn->get_query();
							if (query && *query) {
								char buf[256];
								snprintf(buf, sizeof(buf), "?%s", query);
								conn->write(buf, strlen(buf),
									[conn](int status) {

									conn->write(nullptr, 0,
										[conn](int status) {
										printf("%s\n", conn->get_path());
									});
								});
							}
							else {
								conn->write(nullptr, 0,
									[conn](int status) {
									printf("%s\n", conn->get_path());
								});
							}
						});
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
