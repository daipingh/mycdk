
#include "queue.h"
#include "server.h"
#include <memory.h>


/* ASSERT() is for debug checks, CHECK() for run-time sanity checks.
 * DEBUG_CHECKS is for expensive debug checks that we only want to
 * enable in debug builds but still want type-checked by the compiler
 * in release builds.
 */
#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)    do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS  (0)
#else
# define ASSERT(exp)   assert(exp)
# define CHECK(exp)    assert(exp)
# define DEBUG_CHECKS  (1)
#endif

#define UNREACHABLE() CHECK(!"Unreachable code reached.")
#define UNREACHABLE_ASSERT() ASSERT(!"Unreachable code reached.")



/****************************************************************/

#define UVSTREAM_TYPE_TCP        0x01
#define UVSTREAM_TYPE_PIPE       0x02


struct mcl_server_s
{
	int delay_error;
	int handle_busying;
	int serv_active;
	int serv_closing;

	mcl_connection_cb connection_cb;
	void *connection_arg;

	uv_loop_t *loop;
	uv_timer_t timer;

	int uvstream_type;
	union {
		uv_handle_t handle;
		uv_stream_t stream;
		uv_tcp_t tcp;
		uv_pipe_t pipe;
	};
	union {
		struct sockaddr_storage sock_addr;
		char pipe_path[sizeof(struct sockaddr_storage)];
		struct sockaddr sa;
	};
};


/****************************************************************/

static void mcl_server__check(mcl_server_t *server);


static void mcl_server__on_timer_close(uv_handle_t *handle)
{
	mcl_server_t *server = container_of(handle, mcl_server_t, timer);
	ASSERT(server->serv_closing);
	server->timer.loop = NULL;
	mcl_server__check(server);
}
static void mcl_server__on_stream_close(uv_handle_t *handle)
{
	int err;
	mcl_server_t *server = container_of(handle, mcl_server_t, handle);
	server->handle_busying = 0;

	if (server->serv_active) {
		err = server->delay_error;
		if (err == UV_EAFNOSUPPORT || err == UV_ENOSYS) {
			server->serv_active = 0;
			uv_timer_stop(&server->timer);
			server->connection_cb(server->connection_arg, NULL);
		}
		else {
			if (!uv_is_active((uv_handle_t *)&server->timer))
				mcl_server__check(server);
		}
	}
}
static void mcl_server__on_timeout(uv_timer_t *timer)
{
	mcl_server_t *server = container_of(timer, mcl_server_t, timer);
	ASSERT(server->serv_active);

	if (server->handle_busying == 0)
		mcl_server__check(server);
}
static void mcl_server__on_new_connection(uv_stream_t *stream, int status)
{
	mcl_stream_t *client = NULL;
	mcl_server_t *server = container_of(stream, mcl_server_t, stream);

	if (status == 0) {
		client = mcl_uvstream_accept(server->loop, stream, &status, NULL);
		if (status == 0) {
			CHECK(client != NULL);
			server->connection_cb(server->connection_arg, client);
		}
	}
	if (status < 0) {
		server->delay_error = status;
		uv_close(&server->handle, mcl_server__on_stream_close);
		uv_timer_start(&server->timer, mcl_server__on_timeout, 1000, 0);
	}
}
static void mcl_server__check(mcl_server_t *server)
{
	int err = 0;

	if (server->serv_closing) {
		// Îö¹¹×´Ì¬.
		if (server->handle_busying == 0 && server->timer.loop == NULL) {
			free(server);
		}
	}
	else if (server->serv_active) {
		// ¹¤×÷×´Ì¬.
		if (server->handle_busying == 0) {
			server->handle_busying = 1;
			uv_timer_stop(&server->timer);

			switch (server->uvstream_type)
			{
			case UVSTREAM_TYPE_TCP:
				uv_tcp_init(server->loop, &server->tcp);
				if (!(err = uv_tcp_bind(&server->tcp, &server->sa, 0)))
					err = uv_listen(&server->stream, 5, mcl_server__on_new_connection);
				break;

			case UVSTREAM_TYPE_PIPE:
				uv_pipe_init(server->loop, &server->pipe, 0);
				if (!(err = uv_pipe_bind(&server->pipe, server->pipe_path)))
					err = uv_listen(&server->stream, 5, mcl_server__on_new_connection);
				break;

			default:
				UNREACHABLE();
				break;
			}

			server->delay_error = err;
			if (err < 0) {
				uv_close(&server->handle, mcl_server__on_stream_close);
				if (err == UV_EAFNOSUPPORT || err == UV_ENOSYS)
					;// uv_timer_start(&server->timer, mcl_server__on_timeout, 0, 0);
				else
					uv_timer_start(&server->timer, mcl_server__on_timeout, 3000, 0);
			}
		}
	}
}

static int mcl_server_init(mcl_server_t *server, int type, uv_loop_t *loop, const void *addr, size_t addr_len)
{
	server->delay_error = 0;
	server->handle_busying = 0;
	server->serv_active = 0;
	server->serv_closing = 0;

	server->connection_cb = NULL;
	server->connection_arg = NULL;

	server->loop = loop;
	uv_timer_init(loop, &server->timer);

	server->uvstream_type = type;
	memset(&server->sock_addr, 0, sizeof(server->sock_addr));
	if (server->uvstream_type == UVSTREAM_TYPE_TCP) {
		ASSERT(addr_len <= sizeof(server->sock_addr));
		memcpy(&server->sa, addr, addr_len);
	}
	else if (server->uvstream_type == UVSTREAM_TYPE_PIPE) {
		ASSERT(addr_len < sizeof(server->pipe_path));
		memcpy(&server->pipe_path, addr, addr_len);
		server->pipe_path[addr_len] = 0;
	}

	return 0;
}


/****************************************************************/

mcl_server_t *mcl_server_tcp_create(uv_loop_t *loop, const struct sockaddr *sa, int *result)
{
	mcl_server_t *server;
	size_t sa_len;

	if (sa->sa_family == AF_INET)
		sa_len = sizeof(struct sockaddr_in);
	else if (sa->sa_family == AF_INET6)
		sa_len = sizeof(struct sockaddr_in6);
	else {
		if (result != NULL)
			*result = UV_EINVAL;
		return NULL;
	}

	server = (mcl_server_t *)malloc(sizeof(mcl_server_t));
	if (server == NULL) {
		if (result != NULL)
			*result = UV_ENOMEM;
		return NULL;
	}

	mcl_server_init(server, UVSTREAM_TYPE_TCP, loop, sa, sa_len);
	if (result != NULL)
		*result = 0;
	return server;
}
mcl_server_t *mcl_server_pipe_create(uv_loop_t *loop, const char *name, int ipc, int *result)
{
	mcl_server_t *server;
	size_t name_len;

	name_len = strlen(name);
	if (name_len >= sizeof(server->pipe_path)) {
		if (result != NULL)
			*result = UV_EINVAL;
		return NULL;
	}

	server = (mcl_server_t *)malloc(sizeof(mcl_server_t));
	if (server == NULL) {
		if (result != NULL)
			*result = UV_ENOMEM;
		return NULL;
	}

	mcl_server_init(server, UVSTREAM_TYPE_PIPE, loop, name, strlen(name));
	if (result != NULL)
		*result = 0;
	return server;
}
void mcl_server_destroy(mcl_server_t *serv)
{
	mcl_server_t *server = serv;
	ASSERT(!server->serv_closing);

	server->serv_closing = 1;
	mcl_server_stop(server);
	uv_close((uv_handle_t *)&server->timer, mcl_server__on_timer_close);
}
int mcl_server_start(mcl_server_t *serv, void *arg, mcl_connection_cb cb)
{
	mcl_server_t *server = serv;

	if (server->serv_active)
		return UV_EBUSY;

	server->serv_active = 1;
	server->connection_arg = arg;
	server->connection_cb = cb;

	mcl_server__check(server);
	return 0;
}
int mcl_server_stop(mcl_server_t *serv)
{
	mcl_server_t *server = serv;
	
	if (!server->serv_active)
		return 0;

	if (server->handle_busying && !uv_is_closing(&server->handle))
		uv_close(&server->handle, mcl_server__on_stream_close);
	uv_timer_stop(&server->timer);

	server->serv_active = 0;
	return 0;
}
