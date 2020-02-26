
#ifndef MCL_SERVER_H_
#define MCL_SERVER_H_

#include <uv.h>
#include "stream.h"


MCL_BEGIN_EXTERN_C

typedef struct mcl_server_s mcl_server_t;
typedef void(*mcl_connection_cb)(void *arg, mcl_stream_t *connection);

MCL_APIDECL mcl_server_t *mcl_server_tcp_create(uv_loop_t *loop, const struct sockaddr *sa, int *err);
MCL_APIDECL mcl_server_t *mcl_server_pipe_create(uv_loop_t *loop, const char *name, int ipc, int *err);
MCL_APIDECL void mcl_server_destroy(mcl_server_t *serv);
MCL_APIDECL int mcl_server_start(mcl_server_t *serv, void *arg, mcl_connection_cb cb);
MCL_APIDECL int mcl_server_stop(mcl_server_t *serv);
MCL_APIDECL int mcl_server_get_error(mcl_server_t *serv);


MCL_END_EXTERN_C
#endif
