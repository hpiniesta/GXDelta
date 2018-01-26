#include "stdafx.h"
#include <vector>
#include "GXdelta.h"
#include "xdelta3.h"
#include "xdelta3-internal.h"
#include "xdelta3-list.h"

#define PRINTHDR_SPECIAL -4378291
#define XD3_INVALID_OFFSET XOFF_T_MAX

void GPrintf(char *frm, ...)
{
	va_list ap;
	va_start(ap, frm);
	int len = _vscprintf(frm, ap);
	if (len > 0)
	{
		std::string var_str;
		std::vector<char> buf(len + 1);
		vsprintf(&buf.front(), frm, ap);
		var_str.assign(buf.begin(), buf.end() - 1);
		OutputDebugString(var_str.c_str());
	}
	va_end(ap);
}

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

XD3_MAKELIST(main_blklru_list, main_blklru, link);

int main_file_read(main_file  *ifile,
	uint8_t    *buf,
	size_t      size,
	size_t     *nread);

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
		xfile->realname = name; 
		xfile->nread = 0; 
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

	return xd3_max(size, XD3_ALLOCSIZE);
}

int main_open_output(xd3_stream *stream, main_file *ofile)
{
	if (ofile->filename == NULL)
	{
		return 0;
	}
	else
	{
		int ret = main_file_open(ofile, ofile->filename, XO_WRITE);
		if (ret)
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
	if (!CloseHandle(xfile->file)) 
	{
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
	int ret = xd3_win32_io(ofile->file, buf, size, 0, NULL);

	if (!ret)
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
	int ret = xd3_win32_io(ifile->file, buf, size, 1 /* is_read */, nread);

	if (!ret)
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

int main_file_seek(main_file *xfile, xoff_t pos)
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

GXdelta::GXdelta() : lru(NULL), lru_size(0)
{
}


GXdelta::~GXdelta()
{
	if (lru != NULL)
	{
		main_buffree(lru[0].blk);
		free(lru);
	}
	lru = NULL;
}

int GXdelta::diff(const string & srcFile, const string & dstFile, const string & patchFile)
{
	main_file pSrcFile, pDstFile, pPatchFile;
	main_file_init(&pSrcFile);
	main_file_init(&pDstFile);
	main_file_init(&pPatchFile);
	auto cleanUp = [&]()
	{
		main_file_close(&pSrcFile);
		main_file_close(&pDstFile);
		main_file_close(&pPatchFile);
	};
	pSrcFile.filename = srcFile.c_str();
	pPatchFile.filename = patchFile.c_str();
	pDstFile.filename = dstFile.c_str();
	int ret = EXIT_SUCCESS;
	if (ret = main_file_open(&pDstFile, pDstFile.filename, XO_READ))
	{
		GPrintf("main_file_open failure, fileName: %s, error: %d", pDstFile.filename, ret);
		return ret;
	}

	xd3_config config;
	xd3_init_config(&config, 0);
	config.smatch_cfg = XD3_SMATCH_FAST;
	config.winsize = main_get_winsize(&pDstFile);
	config.flags = XD3_ADLER32;
	xd3_stream stream;
	if (ret = xd3_config_stream(&stream, &config))
	{
		cleanUp();
		GPrintf("config_stream failure, error: %d", ret);
		return ret;
	}
	xd3_source source;
	memset(&source, 0, sizeof(source));
	if (ret = main_set_source(&stream, &pSrcFile, &source))
	{
		cleanUp();
		GPrintf("main_set_source failure, error: %d", ret);
		return ret;
	}
	uint8_t* main_bdata = (uint8_t*)main_bufalloc(config.winsize);
	size_t   nread = 0;
	do 
	{
		usize_t try_read = config.winsize;
		if (ret = main_file_read(&pDstFile, main_bdata, try_read, &nread))
		{
			GPrintf("main_file_read failure, fileName: %s, error: %d", pDstFile.filename, ret);
			goto done;
		}
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
		ret = xd3_encode_input(&stream);
		switch (ret)
		{
		case XD3_INPUT:
			continue;
		case XD3_GOTHEADER:
		case XD3_WINSTART:
		case XD3_WINFINISH:
			goto again;
		case XD3_OUTPUT:
		{
			if (!main_file_isopen(&pPatchFile) && (ret = main_open_output(&stream, &pPatchFile)) != 0)
			{
				GPrintf("main_open_output failure, fileName: %s, error: %d", pPatchFile.filename, ret);
				return EXIT_FAILURE;
			}
			if ((ret = main_write_output(&stream, &pPatchFile)) && (ret != PRINTHDR_SPECIAL))
			{
				GPrintf("main_write_output failure, fileName: %s, error: %d", pPatchFile.filename, ret);
				return EXIT_FAILURE;
			}
			if (ret == PRINTHDR_SPECIAL)
			{
				xd3_abort_stream(&stream);
				goto done;
			}
			ret = 0;
			xd3_consume_output(&stream);
			goto again;
		}
		case XD3_GETSRCBLK:
		{
			source.curblkno = source.getblkno;
			main_getblk_func(&stream, &source, source.curblkno);
			goto again;
		}
		default:
			return EXIT_FAILURE;
		}
	} while (nread == config.winsize);
done:
	cleanUp();
	if (ret = xd3_close_stream(&stream))
	{
		GPrintf("xd3_close_stream failure, error:%d", ret);
		return EXIT_FAILURE;
	}
	xd3_free_stream(&stream);
	main_buffree(main_bdata);
	main_bdata = NULL;
	return ret;
}

int GXdelta::patch(const string & iFileName, const string & sFileName, const string & oFileName)
{
	main_file iFile, oFile, sFile;
	main_file_init(&iFile);
	main_file_init(&oFile);
	main_file_init(&sFile);

	auto cleanUp = [&]()
	{
		main_file_close(&iFile);
		main_file_close(&sFile);
		main_file_close(&oFile);
	};

	iFile.filename = iFileName.c_str();
	int ret = EXIT_FAILURE;
	if (ret = main_file_open(&iFile, iFile.filename, XO_READ))
	{
		GPrintf("main_file_open failure, fileName: %s, error: %d", iFile.filename, ret);
		return ret;
	}

	sFile.filename = sFileName.c_str();
	oFile.filename = oFileName.c_str();
	xd3_config config;
	xd3_init_config(&config, 0);
	config.smatch_cfg = XD3_SMATCH_FAST;
	config.winsize = main_get_winsize(&iFile);
	config.flags = XD3_ADLER32;
	xd3_stream stream;
	if (ret = xd3_config_stream(&stream, &config))
	{
		cleanUp();
		GPrintf("config_stream failure, error: %d", ret);
		return ret;
	}
	xd3_source source;
	memset(&source, 0, sizeof(source));
	uint8_t* main_bdata = (uint8_t*)main_bufalloc(config.winsize);
	size_t   nread = 0;
	do 
	{
		usize_t try_read = config.winsize;
		if (ret = main_file_read(&iFile, main_bdata, try_read, &nread))
		{
			GPrintf("main_file_read failure, fileName: %s, error: %d", iFile.filename, ret);
			goto done;
		}
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
			/* Now open the source file. */
			if ((sFile.filename != NULL) &&
				(ret = main_set_source(&stream, &sFile, &source)))
			{
				GPrintf("main_set_source failure, error: %d", ret);
				return EXIT_FAILURE;
			}
		}
		case XD3_WINSTART:
		case XD3_WINFINISH:
			goto again;
		case XD3_OUTPUT:
		{
			if (!main_file_isopen(&oFile) && (ret = main_open_output(&stream, &oFile)) != 0)
			{
				GPrintf("main_open_output failure, fileName: %s, error: %d", oFile.filename, ret);
				return EXIT_FAILURE;
			}
			if ((ret = main_write_output(&stream, &oFile)) && (ret != PRINTHDR_SPECIAL))
			{
				GPrintf("main_write_output failure, fileName: %s, error: %d", oFile.filename, ret);
				return EXIT_FAILURE;
			}
			if (ret == PRINTHDR_SPECIAL)
			{
				xd3_abort_stream(&stream);
				return EXIT_SUCCESS;
			}
			ret = 0;
			xd3_consume_output(&stream);
			goto again;
		}
		case XD3_GETSRCBLK:
		{
			source.curblkno = source.getblkno;
			main_getblk_func(&stream, &source, source.curblkno);
			goto again;
		}
		default:
			return EXIT_FAILURE;
		}
	} while (nread == config.winsize);
done:
	cleanUp();
	if (ret = xd3_close_stream(&stream))
	{
		GPrintf("xd3_close_stream failure, error:%d", ret);
		return EXIT_FAILURE;
	}
	xd3_free_stream(&stream);
	main_buffree(main_bdata);
	main_bdata = NULL;
	return ret;
}

int GXdelta::main_set_source(xd3_stream * stream, main_file * sfile, xd3_source * source)
{
	main_blklru_list  lru_list;
	main_blklru_list_init(&lru_list);
	lru = (main_blklru *)malloc(MAX_LRU_SIZE * sizeof(main_blklru));
	if (NULL == lru)
	{
		return ENOMEM;
	}
	memset(lru, 0, sizeof(lru[0]) * MAX_LRU_SIZE);
	/* Allocate the entire buffer. */
	xoff_t option_srcwinsz = XD3_DEFAULT_SRCWINSZ;
	if ((lru[0].blk = (uint8_t*)main_bufalloc(option_srcwinsz)) == NULL)
	{
		return ENOMEM;
	}
	lru_size = 1;
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
	int ret = main_getblk_func(stream, source, 0);
	if (ret != 0)
	{
		return ret;
	}

	source->onblk = lru[0].size;  /* xd3 sets onblk */
	if (!sfile->size_known && source->onblk < blksize)
	{
		source_size = source->onblk;
		source->onlastblk = source_size;
		sfile->size_known = 1;
	}
	if (!sfile->size_known || source_size > option_srcwinsz)
	{
		/* Modify block 0, change blocksize. */
		blksize = option_srcwinsz / MAX_LRU_SIZE;
		source->blksize = blksize;
		source->onblk = blksize;
		source->onlastblk = blksize;
		source->max_blkno = MAX_LRU_SIZE - 1;

		lru[0].size = blksize;
		lru_size = MAX_LRU_SIZE;

		/* Setup rest of blocks. */
		for (usize_t i = 1; i < lru_size; i += 1)
		{
			lru[i].blk = lru[0].blk + (blksize * i);
			lru[i].blkno = i;
			lru[i].size = blksize;
			main_blklru_list_push_back(&lru_list, &lru[i]);
		}
	}
	if (sfile->size_known)
	{
		ret = xd3_set_source_and_size(stream, source, source_size);
	}
	else
	{
		ret = xd3_set_source(stream, source);
	}
	return 0;
}

int GXdelta::main_getblk_lru(xd3_source * source, xoff_t blkno, main_blklru ** blrup, int * is_new)
{
	(*is_new) = 0;

	/* Direct lookup assumes sequential scan w/o skipping blocks. */
	int idx = blkno % lru_size;
	main_blklru *blru = &lru[idx];
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
	(*is_new) = 1;
	(*blrup) = blru;
	blru->blkno = XD3_INVALID_OFFSET;
	return 0;
}

int GXdelta::main_read_seek_source(xd3_stream * stream, xd3_source * source, xoff_t blkno)
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

			if ((ret = main_file_read(sfile,
				(uint8_t*)blru->blk,
				source->blksize,
				&nread)))
			{
				return ret;
			}

			if (nread != source->blksize)
			{
				stream->msg = "non-seekable input is short";
				return XD3_INVALID_INPUT;
			}

			sfile->source_position += nread;
			blru->size = nread;
			XD3_ASSERT(sfile->source_position <= pos);
		}
	}

	return 0;
}

int GXdelta::main_getblk_func(xd3_stream * stream, xd3_source * source, xoff_t blkno)
{
	int ret = 0;
	xoff_t pos = blkno * source->blksize;
	main_file *sfile = (main_file*)source->ioh;
	main_blklru *blru;
	int is_new;

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
		if (ret = main_read_seek_source(stream, source, blkno))
		{
			return ret;
		}
	}

	XD3_ASSERT(sfile->source_position == pos);
	size_t nread = 0;
	if ((ret = main_file_read(sfile,
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
