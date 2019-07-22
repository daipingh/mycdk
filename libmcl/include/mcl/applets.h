
#ifndef MCL_APPLET_H_
#define MCL_APPLET_H_

#include "lang.h"

typedef struct mcl_applet_s mcl_applet_t;
typedef void(*mcl_applet_cb)(mcl_applet_t *);
struct mcl_applet_s { struct mcl_applet_s *next; mcl_applet_cb applet_cb; };

void mcl_setup_applets();
void mcl_cleanup_applets();
void mcl_applet_init_register(mcl_applet_t *req, mcl_applet_cb init_cb);
void mcl_applet_setup_register(mcl_applet_t *req, mcl_applet_cb setup_cb);
void mcl_applet_cleanup_register(mcl_applet_t *req, mcl_applet_cb cleanup_cb);

#define MCL_APPLET_INIT_REGISTER(cb) do { static mcl_applet_t req; mcl_applet_init_register(&req, (cb)); } while (0)
#define MCL_APPLET_SETUP_REGISTER(cb) do { static mcl_applet_t req; mcl_applet_setup_register(&req, (cb)); } while (0)
#define MCL_APPLET_CLEANUP_REGISTER(cb) do { static mcl_applet_t req; mcl_applet_cleanup_register(&req, (cb)); } while (0)
#define MCL_APPLET_INIT_STATIC_REGISTER(cb) MCL_CONSTRUCTOR_REGISTER(mcl_applet_init_register__##cb) { MCL_APPLET_INIT_REGISTER(cb); }
#define MCL_APPLET_SETUP_STATIC_REGISTER(cb) MCL_CONSTRUCTOR_REGISTER(mcl_applet_setup_register__##cb) { MCL_APPLET_SETUP_REGISTER(cb); }
#define MCL_APPLET_CLEANUP_STATIC_REGISTER(cb) MCL_CONSTRUCTOR_REGISTER(mcl_applet_cleanup_register__##cb) { MCL_APPLET_CLEANUP_REGISTER(cb); }

#endif
