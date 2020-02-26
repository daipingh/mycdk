
#include "http.h"
#include <http_parser.h>


STATIC_ASSERT(sizeof(((mcl_urlparser_t *)0)->urlparser) >= sizeof(struct http_parser_url));

int mcl_url_parse(mcl_urlparser_t *parser, const char *url, size_t len)
{
	int result;
	struct http_parser_url *p = (struct http_parser_url *)parser->urlparser;
	parser->url = url;
	http_parser_url_init(p);
	result = http_parser_parse_url(url, len, 0, p);
	return result ? -1 : 0;
}

#define MCL_URL_GET_FUNCTION(_name, _NAME) \
const char *mcl_url_get_##_name(const mcl_urlparser_t *parser, int *result) \
{ \
	int r = -1; \
	const char *p = NULL; \
	struct http_parser_url *u = (struct http_parser_url *)parser->urlparser; \
	if (u->field_set & (1 << UF_##_NAME)) { \
		p = parser->url + u->field_data[UF_##_NAME].off; \
		r = (int)u->field_data[UF_##_NAME].len; \
	} \
	if (result != NULL) \
		*result = r; \
	return p; \
}

MCL_URL_GET_FUNCTION(schema, SCHEMA)
MCL_URL_GET_FUNCTION(host, HOST)
MCL_URL_GET_FUNCTION(port, PORT)
MCL_URL_GET_FUNCTION(path, PATH)
MCL_URL_GET_FUNCTION(query, QUERY)
MCL_URL_GET_FUNCTION(fragment, FRAGMENT)
MCL_URL_GET_FUNCTION(userinfo, USERINFO)
