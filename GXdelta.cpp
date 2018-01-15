#include "stdafx.h"
#include "GXdelta.h"
#include "xdelta3.h"
#include "xdelta3-internal.h"
#include "xdelta3-list.h"
#include <limits.h>

typedef enum
{
	RD_FIRST = (1 << 0),
	RD_NONEXTERNAL = (1 << 1),
	RD_DECOMPSET = (1 << 2),
	RD_MAININPUT = (1 << 3),
} xd3_read_flags;

#define PRINTHDR_SPECIAL -4378291
#define XD3_INVALID_OFFSET XOFF_T_MAX

struct _main_extcomp
{
	const char    *recomp_cmdname;
	const char    *recomp_options;

	const char    *decomp_cmdname;
	const char    *decomp_options;

	const char    *ident;
	const char    *magic;
	usize_t        magic_size;
	int            flags;
};

typedef struct _main_blklru      main_blklru;
typedef struct _main_blklru_list main_blklru_list;

struct _main_blklru_list
{
	main_blklru_list  *next;
	main_blklru_list  *prev;
};

struct _main_blklru
{
	uint8_t          *blk;
	xoff_t            blkno;
	usize_t           size;
	main_blklru_list  link;
};

XD3_MAKELIST(main_blklru_list, main_blklru, link);
static main_blklru *lru = NULL;

int main_file_read(main_file  *ifile,
	uint8_t    *buf,
	size_t      size,
	size_t     *nread);

int main_getblk_lru(xd3_source *source, xoff_t blkno,
	main_blklru** blrup, int *is_new);

static int main_read_seek_source(xd3_stream *stream,
	xd3_source *source,
	xoff_t      blkno);
int main_read_primary_input(main_file   *file,
	uint8_t     *buf,
	size_t       size,
	size_t      *nread);

int main_getblk_func(xd3_stream *stream,
	xd3_source *source,
	xoff_t      blkno);

xoff_t xd3_xoff_roundup(xoff_t x)
{
	xoff_t i = 1;
	while (x > i) {
		i <<= 1U;
	}
	return i;
}

static int get_errno(void)
{
	DWORD err_num = GetLastError();
	if (err_num == NO_ERROR)
	{
		err_num = XD3_INTERNAL;
	}
	return err_num;
}

void main_file_init(main_file *xfile)
{
	memset(xfile, 0, sizeof(*xfile));
	xfile->file = INVALID_HANDLE_VALUE;
}

int main_file_open(main_file *xfile, const char* name, int mode)
{
	int ret = 0;
	xfile->mode = mode;
	XD3_ASSERT(name != NULL);
	XD3_ASSERT(!main_file_isopen(xfile));
	if (name[0] == 0)
	{
		return XD3_INVALID;
	}

	IF_DEBUG1(DP(RINT "[main] open source %s\n", name));
	xfile->file = CreateFile(name,
		(mode == XO_READ) ? GENERIC_READ : GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		(mode == XO_READ) ?
		OPEN_EXISTING :
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (xfile->file == INVALID_HANDLE_VALUE)
	{
		ret = get_errno();
	}
	if (!ret)
	{ 
		xfile->realname = name; xfile->nread = 0; 
	}
	return ret;
}

int main_file_stat(main_file *xfile, xoff_t *size)
{
	int ret = 0;
	if (GetFileType(xfile->file) != FILE_TYPE_DISK)
	{
		return -1;
	}
# if (_WIN32_WINNT >= 0x0500)
	{
		LARGE_INTEGER li;
		if (GetFileSizeEx(xfile->file, &li) == 0)
		{
			return get_errno();
		}
		*size = li.QuadPart;
	}
# else
	{
		DWORD filesize = GetFileSize(xfile->file, NULL);
		if (filesize == INVALID_FILE_SIZE)
		{
			return get_errno()
		}
		*size = filesize;
	}
# endif
	return ret;
}

static usize_t main_get_winsize(main_file *ifile) 
{
	xoff_t file_size = 0;
	usize_t size = XD3_DEFAULT_WINSIZE;

	if (main_file_stat(ifile, &file_size) == 0)
	{
		size = (usize_t)xd3_min(file_size, (xoff_t)size);
	}

	size = xd3_max(size, XD3_ALLOCSIZE);
	return size;
}

static int main_set_source(xd3_stream *stream, main_file *sfile, xd3_source *source)
{
	main_blklru_list  lru_list;
	main_blklru_list_init(&lru_list);
	lru = NULL;
	xoff_t option_srcwinsz = xd3_xoff_roundup(XD3_DEFAULT_SRCWINSZ);
	if ((lru = (main_blklru*)main_malloc(MAX_LRU_SIZE *
		sizeof(main_blklru))) == NULL)
	{
		return ENOMEM;
	}
	memset(lru, 0, sizeof(lru[0]) * MAX_LRU_SIZE);
	/* Allocate the entire buffer. */
	if ((lru[0].blk = (uint8_t*)main_bufalloc(option_srcwinsz)) == NULL)
	{
		return ENOMEM;
	}
	lru[0].blkno = XD3_INVALID_OFFSET;
	usize_t blksize = option_srcwinsz;
	main_blklru_list_push_back(&lru_list, &lru[0]);
	main_file_open(sfile, sfile->filename, XO_READ);
	xoff_t source_size = 0;
	sfile->size_known = (main_file_stat(sfile, &source_size) == 0);
	source->blksize = blksize;
	source->name = sfile->filename;
	source->ioh = sfile;
	source->curblkno = UINT32_MAX;
	source->curblk = NULL;
	source->max_winsize = XD3_DEFAULT_SRCWINSZ;
	int ret;
	if ((ret = main_getblk_func(stream, source, 0)) != 0)
	{
		return ret;
	}

	source->onblk = lru[0].size;  /* xd3 sets onblk */
	ret = xd3_set_source(stream, source);
	return 0;
}

static const char* main_apphead_string(const char* x)
{
	const char *y;

	if (x == NULL) { return ""; }

	if (strcmp(x, "/dev/stdin") == 0 ||
		strcmp(x, "/dev/stdout") == 0 ||
		strcmp(x, "/dev/stderr") == 0) {
		return "-";
	}

	// TODO: this is not portable
	return (y = strrchr(x, '/')) == NULL ? x : y + 1;
}

static int main_set_appheader(xd3_stream *stream, main_file *input, main_file *sfile)
{
	static uint8_t*        appheader_used = NULL;
	/* The user may disable the application header.  Once the appheader
	* is set, this disables setting it again. */
	//if (appheader_used || !option_use_appheader) { return 0; }

	/* The user may specify the application header, otherwise format the
	default header. */
	/*if (option_appheader)
	{
		appheader_used = option_appheader;
	}
	else*/
	{
		const char *iname;
		const char *icomp;
		const char *sname;
		const char *scomp;
		usize_t len;

		iname = main_apphead_string(input->filename);
		icomp = (input->compressor == NULL) ? "" : input->compressor->ident;
		len = (usize_t)strlen(iname) + (usize_t)strlen(icomp) + 2;

		if (sfile->filename != NULL)
		{
			sname = main_apphead_string(sfile->filename);
			scomp = (sfile->compressor == NULL) ? "" : sfile->compressor->ident;
			len += (usize_t)strlen(sname) + (usize_t)strlen(scomp) + 2;
		}
		else
		{
			sname = scomp = "";
		}

		if ((appheader_used = (uint8_t*)main_malloc(len)) == NULL)
		{
			return ENOMEM;
		}

		if (sfile->filename == NULL)
		{
			snprintf_func((char*)appheader_used, len, "%s/%s", iname, icomp);
		}
		else
		{
			snprintf_func((char*)appheader_used, len, "%s/%s/%s/%s",
				iname, icomp, sname, scomp);
		}
	}

	xd3_set_appheader(stream, appheader_used, (usize_t)strlen((char*)appheader_used));

	return 0;
}

static void* main_malloc1(size_t size)
{
	void* r = malloc(size);
	return r;
}

static void* main_alloc(void   *opaque,
	size_t  items,
	usize_t  size)
{
	return main_malloc1(items * size);
}

IF_DEBUG(static int main_mallocs = 0;)
void* main_malloc(size_t size)
{
	void *r = main_malloc1(size);
	if (r)
	{
		IF_DEBUG(main_mallocs += 1);
	}
	return r;
}

int main_open_output(xd3_stream *stream, main_file *ofile)
{
	int ret;

	if (ofile->filename == NULL)
	{
		return 0;
	}
	else
	{
		if ((ret = main_file_open(ofile, ofile->filename, XO_WRITE)))
		{
			return ret;
		}
	}
	return 0;
}
int main_write_output(xd3_stream* stream, main_file *ofile)
{
	int ret;

	if (stream->avail_out > 0 &&
		(ret = main_file_write(ofile, stream->next_out,
			stream->avail_out, "write failed")))
	{
		return ret;
	}

	return 0;
}

int main_file_close(main_file *xfile)
{
	int ret = 0;

	if (!main_file_isopen(xfile))
	{
		return 0;
	}
	if (!CloseHandle(xfile->file)) {
		ret = get_errno();
	}
	xfile->file = INVALID_HANDLE_VALUE;
	return ret;
}

int main_file_isopen(main_file *xfile)
{
	return xfile->file != INVALID_HANDLE_VALUE;
}

int xd3_win32_io(HANDLE file, uint8_t *buf, size_t size,
	int is_read, size_t *nread)
{
	int ret = 0;
	size_t nproc = 0;

	while (nproc < size)
	{
		DWORD nproc2 = 0;  /* hmm */
		DWORD nremain = size - nproc;
		if ((is_read ?
			ReadFile(file, buf + nproc, nremain, &nproc2, NULL) :
			WriteFile(file, buf + nproc, nremain, &nproc2, NULL)) == 0)
		{
			ret = get_errno();
			if (ret != ERROR_HANDLE_EOF && ret != ERROR_BROKEN_PIPE)
			{
				return ret;
			}
			/* By falling through here, we'll break this loop in the
			* read case in case of eof or broken pipe. */
		}

		nproc += nproc2;

		if (nread != NULL && nproc2 == 0) { break; }
	}
	if (nread != NULL) { (*nread) = nproc; }
	return 0;
}

int main_file_write(main_file *ofile, uint8_t *buf, usize_t size, const char *msg)
{
	int ret = 0;

	ret = xd3_win32_io(ofile->file, buf, size, 0, NULL);

	if (ret)
	{
	}
	else
	{
		ofile->nwrite += size;
	}

	return ret;
}

int main_file_read(main_file  *ifile,
	uint8_t    *buf,
	size_t      size,
	size_t     *nread)
{
	int ret = 0;
	ret = xd3_win32_io(ifile->file, buf, size, 1 /* is_read */, nread);

	if (ret)
	{
	}
	else
	{
		ifile->nread += (*nread);
	}
	return ret;
}

void* main_bufalloc(size_t size) 
{
	return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

void main_buffree(void *ptr) 
{
	VirtualFree(ptr, 0, MEM_RELEASE);
}

static int main_file_seek(main_file *xfile, xoff_t pos)
{
	int ret = 0;
# if (_WIN32_WINNT >= 0x0500)
	LARGE_INTEGER move, out;
	move.QuadPart = pos;
	if (SetFilePointerEx(xfile->file, move, &out, FILE_BEGIN) == 0)
	{
		ret = get_errno();
	}
# else
	if (SetFilePointer(xfile->file, (LONG)pos, NULL, FILE_BEGIN) ==
		INVALID_SET_FILE_POINTER)
	{
		ret = get_errno();
	}
# endif
	return ret;
}

int main_getblk_lru(xd3_source *source, xoff_t blkno,
	main_blklru** blrup, int *is_new)
{
	main_blklru *blru = NULL;

	(*is_new) = 0;

	/* Direct lookup assumes sequential scan w/o skipping blocks. */
	int idx = blkno % 1; //todo lrusize
	blru = &lru[idx];
	if (blru->blkno == blkno)
	{
		(*blrup) = blru;
		return 0;
	}
	/* No going backwards in a sequential scan. */
	if (blru->blkno != XD3_INVALID_OFFSET && blru->blkno > blkno)
	{
		return XD3_TOOFARBACK;
	}
	idx = blkno % 1;//todo lrusize
	blru = &lru[idx];

	(*is_new) = 1;
	(*blrup) = blru;
	blru->blkno = XD3_INVALID_OFFSET;
	return 0;
}

int main_read_primary_input(main_file   *file,
	uint8_t     *buf,
	size_t       size,
	size_t      *nread)
{
	return main_file_read(file, buf, size, nread);
}

static int main_read_seek_source(xd3_stream *stream,
	xd3_source *source,
	xoff_t      blkno)
{
	xoff_t pos = blkno * source->blksize;
	main_file *sfile = (main_file*)source->ioh;
	main_blklru *blru;
	int is_new;
	size_t nread = 0;
	int ret = 0;

	if (!sfile->seek_failed)
	{
		ret = main_file_seek(sfile, pos);

		if (ret == 0)
		{
			sfile->source_position = pos;
		}
	}

	if (sfile->seek_failed || ret != 0)
	{
		/* For an unseekable file (or other seek error, does it
		* matter?) */
		if (sfile->source_position > pos)
		{
			sfile->seek_failed = 1;
			stream->msg = "non-seekable source: "
				"copy is too far back (try raising -B)";
			return XD3_TOOFARBACK;
		}

		/* There's a chance here, that an genuine lseek error will cause
		* xdelta3 to shift into non-seekable mode, entering a degraded
		* condition.  */
		sfile->seek_failed = 1;

		while (sfile->source_position < pos)
		{
			xoff_t skip_blkno;
			usize_t skip_offset;

			xd3_blksize_div(sfile->source_position, source,
				&skip_blkno, &skip_offset);

			/* Read past unused data */
			XD3_ASSERT(pos - sfile->source_position >= source->blksize);
			XD3_ASSERT(skip_offset == 0);

			if ((ret = main_getblk_lru(source, skip_blkno,
				&blru, &is_new)))
			{
				return ret;
			}

			XD3_ASSERT(is_new);
			blru->blkno = skip_blkno;

			if ((ret = main_read_primary_input(sfile,
				(uint8_t*)blru->blk,
				source->blksize,
				&nread)))
			{
				return ret;
			}

			if (nread != source->blksize)
			{
				IF_DEBUG1(DP(RINT "[getblk] short skip block nread = %"Z"u\n",
					nread));
				stream->msg = "non-seekable input is short";
				return XD3_INVALID_INPUT;
			}

			sfile->source_position += nread;
			blru->size = nread;

			IF_DEBUG1(DP(RINT "[getblk] skip blkno %"Q"u size %"W"u\n",
				skip_blkno, blru->size));

			XD3_ASSERT(sfile->source_position <= pos);
		}
	}

	return 0;
}

int main_getblk_func(xd3_stream *stream,
	xd3_source *source,
	xoff_t      blkno)
{
	int ret = 0;
	xoff_t pos = blkno * source->blksize;
	main_file *sfile = (main_file*)source->ioh;
	main_blklru *blru;
	int is_new;
	size_t nread = 0;

	if (ret = main_getblk_lru(source, blkno, &blru, &is_new))
	{
		return ret;
	}

	if (!is_new)
	{
		source->curblkno = blkno;
		source->onblk = blru->size;
		source->curblk = blru->blk;
		return 0;
	}

	if (pos != sfile->source_position)
	{
		/* Only try to seek when the position is wrong.  This means the
		* decoder will fail when the source buffer is too small, but
		* only when the input is non-seekable. */
		if ((ret = main_read_seek_source(stream, source, blkno)))
		{
			return ret;
		}
	}

	XD3_ASSERT(sfile->source_position == pos);

	if ((ret = main_read_primary_input(sfile,
		(uint8_t*)blru->blk,
		source->blksize,
		&nread)))
	{
		return ret;
	}

	/* Save the last block read, used to handle non-seekable files. */
	sfile->source_position = pos + nread;
	source->curblk = blru->blk;
	source->curblkno = blkno;
	source->onblk = nread;
	blru->size = nread;
	blru->blkno = blkno;
	return 0;
}

void main_free1(void *opaque, void *ptr)
{
	free(ptr);
}

/* This array of compressor types is compiled even if EXTERNAL_COMPRESSION is
* false just so the program knows the mapping of IDENT->NAME. */
static main_extcomp extcomp_types[] =
{
	{ "bzip2",    "-c",   "bzip2",      "-dc",   "B", "BZh",          3, 0 },
{ "gzip",     "-c",   "gzip",       "-dc",   "G", "\037\213",     2, 0 },
{ "compress", "-c",   "uncompress", "-c",    "Z", "\037\235",     2, 0 },

/* Xz is lzma with a magic number http://tukaani.org/xz/format.html */
{ "xz", "-c", "xz", "-dc", "Y", "\xfd\x37\x7a\x58\x5a\x00", 2, 0 },
};

const main_extcomp* main_ident_compressor(const char *ident)
{
	usize_t i;

	for (i = 0; i < SIZEOF_ARRAY(extcomp_types); i += 1)
	{
		if (strcmp(extcomp_types[i].ident, ident) == 0)
		{
			return &extcomp_types[i];
		}
	}

	return NULL;
}

/* Return the main_extcomp record to use for this identifier, if possible. */
const main_extcomp* main_get_compressor(const char *ident)
{
	const main_extcomp *ext = main_ident_compressor(ident);
	return ext;
}

static void main_get_appheader_params(main_file *file, char **parsed,
	int output, const char *type,
	main_file *other)
{
	/* Set the filename if it was not specified.  If output, option_stdout (-c)
	* overrides. */
	if (file->filename == NULL &&
		strcmp(parsed[0], "-") != 0)
	{
		file->filename = parsed[0];

		if (other->filename != NULL) {
			/* Take directory from the other file, if it has one. */
			/* TODO: This results in nonsense names like /dev/foo.tar.gz
			* and probably the filename-default logic interferes with
			* multi-file operation and the standard file extension?
			* Possibly the name header is bad, should be off by default.
			* Possibly we just want to remember external/compression
			* settings. */
			const char *last_slash = strrchr(other->filename, '/');

			if (last_slash != NULL) {
				usize_t dlen = (usize_t)(last_slash - other->filename);

				XD3_ASSERT(file->filename_copy == NULL);
				file->filename_copy =
					(char*)main_malloc(dlen + 2 + (usize_t)strlen(file->filename));

				strncpy(file->filename_copy, other->filename, dlen);
				file->filename_copy[dlen] = '/';
				strcpy(file->filename_copy + dlen + 1, parsed[0]);

				file->filename = file->filename_copy;
			}
		}
	}

	/* Set the compressor, initiate de/recompression later. */
	if (file->compressor == NULL && *parsed[1] != 0)
	{
		file->flags |= RD_DECOMPSET;
		file->compressor = main_get_compressor(parsed[1]);
	}
}

static void main_get_appheader(xd3_stream *stream, main_file *ifile,
	main_file *output, main_file *sfile)
{
	uint8_t *apphead;
	usize_t appheadsz;
	int ret;

	/* The user may disable the application header.  Once the appheader
	* is set, this disables setting it again. */

	ret = xd3_get_appheader(stream, &apphead, &appheadsz);

	/* Ignore failure, it only means we haven't received a header yet. */
	if (ret != 0) { return; }

	if (appheadsz > 0)
	{
		char *start = (char*)apphead;
		char *slash;
		int   place = 0;
		const int kMaxArgs = 4;
		char *parsed[4];

		memset(parsed, 0, sizeof(parsed));

		while ((slash = strchr(start, '/')) != NULL && place < (kMaxArgs - 1))
		{
			*slash = 0;
			parsed[place++] = start;
			start = slash + 1;
		}

		parsed[place++] = start;

		/* First take the output parameters. */
		if (place == 2 || place == 4)
		{
			main_get_appheader_params(output, parsed, 1, "output", ifile);
		}

		/* Then take the source parameters. */
		if (place == 4)
		{
			main_get_appheader_params(sfile, parsed + 2, 0, "source", ifile);
		}
	}
	return;
}

GXdelta::GXdelta()
{
}


GXdelta::~GXdelta()
{
}

bool GXdelta::diff(const string & srcFile, const string & dstFile, const string & patchFile)
{
	main_file pSrcFile, pDstFile, pPatchFile;
	main_file_init(&pSrcFile);
	main_file_init(&pDstFile);
	main_file_init(&pPatchFile);
	pPatchFile.filename = patchFile.c_str();

	pDstFile.flags = RD_FIRST | RD_MAININPUT;
	pDstFile.filename = dstFile.c_str();
	main_file_open(&pDstFile, pDstFile.filename, XO_READ);

	pSrcFile.flags = RD_FIRST;
	pSrcFile.filename = srcFile.c_str();

	xd3_config config;
	xd3_init_config(&config, 0);
	config.smatch_cfg = XD3_SMATCH_FAST;
	config.alloc = main_alloc;
	config.freef = main_free1;
	usize_t winsize = main_get_winsize(&pDstFile);
	config.winsize = winsize;
	config.getblk = main_getblk_func;
	config.flags = XD3_ADLER32;
	config.sprevsz = XD3_DEFAULT_SPREVSZ;
	config.iopt_size = XD3_DEFAULT_IOPT_SIZE;
	xd3_stream stream;
	int ret = xd3_config_stream(&stream, &config);
	xd3_source source;
	memset(&source, 0, sizeof(source));
	main_set_source(&stream, &pSrcFile, &source);
	uint8_t* main_bdata = (uint8_t*)main_bufalloc(winsize);
	size_t   nread = 0;
	do 
	{
		xoff_t input_remain = XOFF_T_MAX - pSrcFile.nread;
		usize_t try_read = (usize_t)xd3_min((xoff_t)config.winsize, input_remain);
		main_file_read(&pDstFile, main_bdata, try_read, &nread);
		if (nread < try_read)
		{
			stream.flags |= XD3_FLUSH;
		}
		main_set_appheader(&stream, &pDstFile, &pSrcFile);
		xd3_avail_input(&stream, main_bdata, nread);
		if (nread == 0 && stream.current_window > 0)
		{
			break;
		}
	again:
		ret = xd3_encode_input(&stream);
		switch (ret)
		{
		case XD3_INPUT:
			continue;
		case XD3_GOTHEADER:
		case XD3_WINSTART:
			goto again;
		case XD3_OUTPUT:
		{
			if (!main_file_isopen(&pPatchFile) && (ret = main_open_output(&stream, &pPatchFile)) != 0)
			{
				return EXIT_FAILURE;
			}
			if ((ret = main_write_output(&stream, &pPatchFile)) && (ret != PRINTHDR_SPECIAL))
			{
				return EXIT_FAILURE;
			}
			if (ret == PRINTHDR_SPECIAL)
			{
				xd3_abort_stream(&stream);
				return EXIT_SUCCESS;
				goto done;
			}
			ret = 0;
			xd3_consume_output(&stream);
			goto again;
		}
		case XD3_WINFINISH:
			goto again;
		default:
			return EXIT_FAILURE;
		}
	} while (nread == config.winsize);
done:
	main_file_close(&pDstFile);
	main_file_close(&pSrcFile);
	main_file_close(&pPatchFile);
	if (ret = xd3_close_stream(&stream))
	{
		return EXIT_FAILURE;
	}
	xd3_free_stream(&stream);
	main_buffree(main_bdata);
	main_bdata = NULL;
	return EXIT_SUCCESS;
}

bool GXdelta::patch(const string & iFileName, const string & sFileName, const string & oFileName)
{
	main_file iFile, oFile, sFile;
	main_file_init(&iFile);
	main_file_init(&oFile);
	main_file_init(&sFile);

	iFile.flags = RD_FIRST | RD_MAININPUT | RD_NONEXTERNAL;
	iFile.filename = iFileName.c_str();
	main_file_open(&iFile, iFile.filename, XO_READ);

	sFile.flags = RD_FIRST;
	sFile.filename = sFileName.c_str();

	oFile.filename = oFileName.c_str();
	xd3_config config;
	xd3_init_config(&config, 0);
	config.smatch_cfg = XD3_SMATCH_FAST;
	config.alloc = main_alloc;
	config.freef = main_free1;
	usize_t winsize = main_get_winsize(&iFile);
	config.winsize = winsize;
	config.getblk = main_getblk_func;
	config.sprevsz = XD3_DEFAULT_SPREVSZ;
	config.iopt_size = XD3_DEFAULT_IOPT_SIZE;
	config.flags = XD3_ADLER32;
	xd3_stream stream;
	int ret = xd3_config_stream(&stream, &config);
	xd3_source source;
	memset(&source, 0, sizeof(source));
	uint8_t* main_bdata = (uint8_t*)main_bufalloc(winsize);
	size_t   nread = 0;
	do 
	{
		xoff_t input_remain = XOFF_T_MAX - iFile.nread;
		usize_t try_read = (usize_t)xd3_min((xoff_t)config.winsize, input_remain);
		main_file_read(&iFile, main_bdata, try_read, &nread);
		if (nread < try_read)
		{
			stream.flags |= XD3_FLUSH;
		}
		xd3_avail_input(&stream, main_bdata, nread);
		if (nread == 0 && stream.current_window > 0)
		{
			break;
		}
	again:
		ret = xd3_decode_input(&stream);
		switch (ret)
		{
		case XD3_INPUT:
			continue;
		case XD3_GOTHEADER:
		{
			main_get_appheader(&stream, &iFile, &oFile, &sFile);

			/* Now open the source file. */
			if ((sFile.filename != NULL) &&
				(ret = main_set_source(&stream, &sFile, &source)))
			{
				return EXIT_FAILURE;
			}
		}
		case XD3_WINSTART:
			goto again;
		case XD3_OUTPUT:
		{
			if (!main_file_isopen(&oFile) && (ret = main_open_output(&stream, &oFile)) != 0)
			{
				return EXIT_FAILURE;
			}
			if ((ret = main_write_output(&stream, &oFile)) && (ret != PRINTHDR_SPECIAL))
			{
				return EXIT_FAILURE;
			}
			if (ret == PRINTHDR_SPECIAL)
			{
				xd3_abort_stream(&stream);
				return EXIT_SUCCESS;
				goto done;
			}
			ret = 0;
			xd3_consume_output(&stream);
			goto again;
		}
		case XD3_WINFINISH:
			goto again;
		default:
			return EXIT_FAILURE;
		}
	} while (nread == config.winsize);
done:
	main_file_close(&iFile);
	main_file_close(&sFile);
	main_file_close(&oFile);
	if (ret = xd3_close_stream(&stream))
	{
		return EXIT_FAILURE;
	}
	xd3_free_stream(&stream);
	main_buffree(main_bdata);
	main_bdata = NULL;
	return EXIT_SUCCESS;
}