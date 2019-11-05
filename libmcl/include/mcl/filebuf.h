
#ifndef MCL_FILEBUF_H_
#define MCL_FILEBUF_H_

#include "lang.h"


MCL_BEGIN_EXTERN_C

typedef struct mcl_filebuf_s mcl_filebuf_t;

struct mcl_filebuf_s
{
	int64_t fpos;
	struct mcl_filebuf_impl_s *filp;
};

#define MCL_FILEBUF_CREAT     0x00000010
#define MCL_FILEBUF_TRUNC     0x00000020
#define MCL_FILEBUF_EXCL      0x00000040
#define MCL_FILEBUF_TMPFILE   0x00000080
#define MCL_FILEBUF_RDONLY    0x00001000


MCL_APIDECL void mcl_filebuf_close(mcl_filebuf_t *fp);
MCL_APIDECL int mcl_filebuf_open(mcl_filebuf_t *fp, const char *path, int flags);
MCL_APIDECL int mcl_filebuf_ref_from(mcl_filebuf_t *fp, const mcl_filebuf_t *from);
MCL_APIDECL int mcl_filebuf_move_from(mcl_filebuf_t *fp, mcl_filebuf_t *from);

MCL_APIDECL size_t mcl_filebuf_get_bufsize(mcl_filebuf_t *fp);
MCL_APIDECL void mcl_filebuf_set_bufsize(mcl_filebuf_t *fp, size_t size);

MCL_APIDECL int mcl_filebuf_get_flags(mcl_filebuf_t *fp, int masks);
MCL_APIDECL void mcl_filebuf_set_flags(mcl_filebuf_t *fp, int masks, int flags);

MCL_APIDECL int64_t mcl_filebuf_get_size(const mcl_filebuf_t *fp);
MCL_APIDECL const char *mcl_filebuf_get_path(const mcl_filebuf_t *fp);

MCL_APIDECL ssize_t mcl_filebuf_read(mcl_filebuf_t *fp, void *buf, size_t count);
MCL_APIDECL ssize_t mcl_filebuf_write(mcl_filebuf_t *fp, const void *buf, size_t count);
MCL_APIDECL size_t mcl_filebuf_fread(void *buf, size_t size, size_t count, mcl_filebuf_t *fp);
MCL_APIDECL size_t mcl_filebuf_fwrite(const void *buf, size_t size, size_t count, mcl_filebuf_t *fp);

MCL_APIDECL void mcl_filebuf_flush(const mcl_filebuf_t *fp);


MCL_END_EXTERN_C
#endif
