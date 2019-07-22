
#include "applets.h"

static mcl_applet_t *applets__init_first = NULL;
static int applets__is_init_done = 0;
static mcl_applet_t *applets__setup_first = NULL;
static int applets__is_setup_done = 0;
static mcl_applet_t *applets__cleanup_first = NULL;
static int applets__is_cleanup_done = 0;


void mcl_setup_applets()
{
	mcl_applet_t *ite;

	if (applets__is_init_done)
		return;
	if (applets__is_setup_done)
		return;

	while (applets__init_first) {
		ite = applets__init_first;
		applets__init_first = ite->next;
		if (ite->applet_cb)
			ite->applet_cb(ite);
	}
	applets__is_init_done = 1;

	while (applets__setup_first) {
		ite = applets__setup_first;
		applets__setup_first = ite->next;
		if (ite->applet_cb)
			ite->applet_cb(ite);
	}
	applets__is_setup_done = 1;
}
void mcl_cleanup_applets()
{
	mcl_applet_t *ite;

	if (applets__is_cleanup_done)
		return;

	while (applets__cleanup_first) {
		ite = applets__cleanup_first;
		applets__cleanup_first = ite->next;
		if (ite->applet_cb)
			ite->applet_cb(ite);
	}
	applets__is_cleanup_done = 1;
}
void mcl_applet_init_register(mcl_applet_t *req, mcl_applet_cb init_cb)
{
	if (applets__is_init_done)
		abort();

	req->applet_cb = init_cb;
	req->next = applets__init_first;
	applets__init_first = req;
}
void mcl_applet_setup_register(mcl_applet_t *req, mcl_applet_cb setup_cb)
{
	if (applets__is_setup_done)
		abort();

	req->applet_cb = setup_cb;
	req->next = applets__setup_first;
	applets__setup_first = req;
}
void mcl_applet_cleanup_register(mcl_applet_t *req, mcl_applet_cb cleanup_cb)
{
	if (applets__is_cleanup_done)
		abort();

	req->applet_cb = cleanup_cb;
	req->next = applets__cleanup_first;
	applets__cleanup_first = req;
}
