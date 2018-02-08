#include <vector>
#include "GXdelta.h"
#include "xdelta3.h"
#include "xdelta3-internal.h"
#include "xdelta3-list.h"

#if XD3_POSIX
#include <unistd.h> /* close, read, write... */
#include <sys/types.h>
#include <fcntl.h>
#endif

#ifndef _WIN32
#include <unistd.h> /* lots */
#include <sys/time.h> /* gettimeofday() */
#include <sys/stat.h> /* stat() and fstat() */
#else
#if defined(_MSC_VER)
#define strtoll _strtoi64
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIFEXITED
#   define WIFEXITED(stat)  (((*((int *) &(stat))) & 0xff) == 0)
#endif
#ifndef WEXITSTATUS
#   define WEXITSTATUS(stat) (((*((int *) &(stat))) >> 8) & 0xff)
#endif
#ifndef S_ISREG
//#   ifdef S_IFREG
//#       define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
//#   else
#       define S_ISREG(m) 1
//#   endif
#endif /* !S_ISREG */

// For standard input/output handles
static STARTUPINFO winStartupInfo;
#endif

#define DEFAULT_VERBOSE 0

/* Program options: various command line flags and options. */
static int         option_stdout             = 0;
static int         option_force              = 0;
static int         option_verbose            = DEFAULT_VERBOSE;
static int         option_quiet              = 0;
static int         option_use_appheader      = 1;
static uint8_t*    option_appheader          = NULL;
static int         option_use_secondary      = 1;
static const char* option_secondary          = NULL;
static int         option_use_checksum       = 1;
static const char* option_smatch_config      = NULL;
static int         option_no_compress        = 0;
static int         option_no_output          = 0; /* do not write output */
static const char *option_source_filename    = NULL;

static int         option_level              = XD3_DEFAULT_LEVEL;
static usize_t     option_iopt_size          = XD3_DEFAULT_IOPT_SIZE;
static usize_t     option_winsize            = XD3_DEFAULT_WINSIZE;

/* option_srcwinsz is restricted to [16kB, 2GB] when usize_t is 32 bits. */
static xoff_t      option_srcwinsz           = XD3_DEFAULT_SRCWINSZ;
static usize_t     option_sprevsz            = XD3_DEFAULT_SPREVSZ;

#define PRINTHDR_SPECIAL -4378291
#define XD3_INVALID_OFFSET XOFF_T_MAX

#define XOPEN_OPNAME (xfile->mode == XO_READ ? "read" : "write")
#define XOPEN_POSIX  (xfile->mode == XO_READ ? \
		      O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC)
#define XOPEN_MODE   (xfile->mode == XO_READ ? 0 : 0666)
#define XF_ERROR(op, name, ret) \
  do { if (!option_quiet) { XPR(NT "file %s failed: %s: %s: %s\n", (op), \
       XOPEN_OPNAME, (name), xd3_mainerror (ret)); } } while (0)

#if XD3_STDIO
#define XFNO(f) fileno(f->file)
#define XSTDOUT_XF(f) { (f)->file = stdout; (f)->filename = "/dev/stdout"; }
#define XSTDIN_XF(f)  { (f)->file = stdin;  (f)->filename = "/dev/stdin"; }

#elif XD3_POSIX
#define XFNO(f) f->file
#define XSTDOUT_XF(f) \
  { (f)->file = STDOUT_FILENO; (f)->filename = "/dev/stdout"; }
#define XSTDIN_XF(f) \
  { (f)->file = STDIN_FILENO;  (f)->filename = "/dev/stdin"; }

#elif XD3_WIN32
#define XFNO(f) -1
#define XSTDOUT_XF(f) { \
  (f)->file = GetStdHandle(STD_OUTPUT_HANDLE); \
  (f)->filename = "(stdout)"; \
  }
#define XSTDIN_XF(f) { \
  (f)->file = GetStdHandle(STD_INPUT_HANDLE); \
  (f)->filename = "(stdin)"; \
  }
#endif

#if XD3_WIN32
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
#endif

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

static void (*xprintf_message_func)(const char*msg) = NULL;

void xprintf (const char *fmt, ...)
{
  char buf[1000];
  va_list a;
  int size;
  va_start (a, fmt);
  size = vsnprintf_func (buf, 1000, fmt, a);
  va_end (a);
  if (size < 0)
    {
      size = sizeof(buf) - 1;
      buf[size] = 0;
    }
  if (xprintf_message_func != NULL) {
    xprintf_message_func(buf);
  } else {
    size_t ignore = fwrite(buf, 1, size, stderr);
    (void) ignore;
  }
}

const char* xd3_mainerror(int err_num) {
#ifndef _WIN32
	const char* x = xd3_strerror (err_num);
	if (x != NULL)
	  {
	    return x;
	  }
	return strerror(err_num);
#else
	static char err_buf[256];
	const char* x = xd3_strerror (err_num);
	if (x != NULL)
	  {
	    return x;
	  }
	memset (err_buf, 0, 256);
	FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM |
		       FORMAT_MESSAGE_IGNORE_INSERTS,
		       NULL, err_num,
		       MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
		       err_buf, 256, NULL);
	if (err_buf[0] != 0 && err_buf[strlen(err_buf) - 1] == '\n')
	  {
	    err_buf[strlen(err_buf) - 1] = 0;
	  }
	return err_buf;
#endif
}

static void* main_malloc1 (size_t size)
{
  void* r = malloc (size);
  if (r == NULL) { XPR(NT "malloc: %s\n", xd3_mainerror (ENOMEM)); }
  return r;
}

static int get_errno(void)
{
#ifndef _WIN32
  if (errno == 0)
    {
      XPR(NT "you found a bug: expected errno != 0\n");
      errno = XD3_INTERNAL;
    }
  return errno;
#else
  DWORD err_num = GetLastError();
  if (err_num == NO_ERROR)
    {
      err_num = XD3_INTERNAL;
    }
  return err_num;
#endif
}

void main_file_init(main_file *xfile)
{
  memset (xfile, 0, sizeof (*xfile));
#if XD3_POSIX
  xfile->file = -1;
#endif
#if XD3_WIN32
  xfile->file = INVALID_HANDLE_VALUE;
#endif
}

int main_file_open (main_file *xfile, const char* name, int mode)
{
  int ret = 0;

  xfile->mode = mode;

  XD3_ASSERT (name != NULL);
  XD3_ASSERT (! main_file_isopen (xfile));
  if (name[0] == 0)
    {
      return XD3_INVALID;
    }

  IF_DEBUG1(DP(RINT "[main] open source %s\n", name));

#if XD3_STDIO
  xfile->file = fopen (name, XOPEN_STDIO);

  ret = (xfile->file == NULL) ? get_errno () : 0;

#elif XD3_POSIX
  /* TODO: Should retry this call if interrupted, similar to read/write */
  if ((ret = open (name, XOPEN_POSIX, XOPEN_MODE)) < 0)
    {
      ret = get_errno ();
    }
  else
    {
      xfile->file = ret;
      ret = 0;
    }

#elif XD3_WIN32
  xfile->file = CreateFile(name,
			   (mode == XO_READ) ? GENERIC_READ : GENERIC_WRITE,
			   FILE_SHARE_READ,
			   NULL,
			   (mode == XO_READ) ?
			   OPEN_EXISTING :
			   (option_force ? CREATE_ALWAYS : CREATE_NEW),
			   FILE_ATTRIBUTE_NORMAL,
			   NULL);
  if (xfile->file == INVALID_HANDLE_VALUE)
    {
      ret = get_errno ();
    }
#endif
  if (ret) { XF_ERROR ("open", name, ret); }
  else     { xfile->realname = name; xfile->nread = 0; }
  return ret;
}

int main_file_stat (main_file *xfile, xoff_t *size)
{
  int ret = 0;
#if XD3_WIN32
  if (GetFileType(xfile->file) != FILE_TYPE_DISK)
    {
      return -1;
    }
# if (_WIN32_WINNT >= 0x0500)
  {
    LARGE_INTEGER li;
    if (GetFileSizeEx(xfile->file, &li) == 0)
      {
	return get_errno ();
      }
    *size = li.QuadPart;
  }
# else
  {
    DWORD filesize = GetFileSize(xfile->file, NULL);
    if (filesize == INVALID_FILE_SIZE)
      {
	return get_errno ()
      }
    *size = filesize;
  }
# endif
#else
  struct stat sbuf;
  if (fstat (XFNO (xfile), & sbuf) < 0)
    {
      ret = get_errno ();
      return ret;
    }

  if (! S_ISREG (sbuf.st_mode))
    {
      return ESPIPE;
    }
  (*size) = sbuf.st_size;
#endif
  return ret;
}

static const char* main_format_bcnt (xoff_t r, shortbuf *buf)
{
  static const char* fmts[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
  usize_t i;

  for (i = 0; i < SIZEOF_ARRAY(fmts) - 1; i += 1)
    {
      xoff_t new_r;

      if (r == 0)
	{
	  short_sprintf (*buf, "0 %s", fmts[i]);
	  return buf->buf;
	}

      if (r >= 1 && r < 10)
	{
	  short_sprintf (*buf, "%.2f %s", (double) r, fmts[i]);
	  return buf->buf;
	}

      if (r >= 10 && r < 100)
	{
	  short_sprintf (*buf, "%.1f %s", (double) r, fmts[i]);
	  return buf->buf;
	}

      if (r >= 100 && r < 1000)
	{
	  short_sprintf (*buf, "%"Q"u %s", r, fmts[i]);
	  return buf->buf;
	}

      new_r = r / 1024;

      if (new_r < 10)
	{
	  short_sprintf (*buf, "%.2f %s", (double) r / 1024.0, fmts[i + 1]);
	  return buf->buf;
	}

      if (new_r < 100)
	{
	  short_sprintf (*buf, "%.1f %s", (double) r / 1024.0, fmts[i + 1]);
	  return buf->buf;
	}

      r = new_r;
    }
  XD3_ASSERT (0);
  return "";
}

static usize_t main_get_winsize (main_file *ifile) {
  xoff_t file_size = 0;
  usize_t size = option_winsize;
  static shortbuf iszbuf;

  if (main_file_stat (ifile, &file_size) == 0)
    {
      size = (usize_t) xd3_min (file_size, (xoff_t) size);
    }

  size = xd3_max (size, XD3_ALLOCSIZE);

  if (option_verbose > 1)
    {
      XPR(NT "input %s window size %s\n",
	  ifile->filename,
	  main_format_bcnt (size, &iszbuf));
    }

  return size;
}

int main_file_exists (main_file *xfile)
{
  struct stat sbuf;
  return stat (xfile->filename, & sbuf) == 0 && S_ISREG (sbuf.st_mode);
}

static int main_open_output (xd3_stream *stream, main_file *ofile)
{
  int ret;

  if (option_no_output)
    {
      return 0;
    }

  if (ofile->filename == NULL)
    {
      XSTDOUT_XF (ofile);

      if (option_verbose > 1)
	{
	  XPR(NT "using standard output: %s\n", ofile->filename);
	}
    }
  else
    {
      /* Stat the file to check for overwrite. */
      if (option_force == 0 && main_file_exists (ofile))
	{
	  if (!option_quiet)
	    {
	      XPR(NT "to overwrite output file specify -f: %s\n",
		  ofile->filename);
	    }
	  return EEXIST;
	}

      if ((ret = main_file_open (ofile, ofile->filename, XO_WRITE)))
	{
	  return ret;
	}

      if (option_verbose > 1) { XPR(NT "output %s\n", ofile->filename); }
    }

#if EXTERNAL_COMPRESSION
  /* Do output recompression. */
  if (ofile->compressor != NULL && option_recompress_outputs == 1)
    {
      if (! option_quiet)
	{
	  XPR(NT "externally compressed output: %s %s%s > %s\n",
	      ofile->compressor->recomp_cmdname,
	      ofile->compressor->recomp_options,
	      (option_force2 ? " -f" : ""),
	      ofile->filename);
	}

      if ((ret = main_recompress_output (ofile)))
	{
	  return ret;
	}
    }
#endif

  return 0;
}

static int main_write_output (xd3_stream* stream, main_file *ofile)
{
  int ret;

  IF_DEBUG1(DP(RINT "[main] write(%s) %"W"u\n bytes", ofile->filename, stream->avail_out));

  if (option_no_output)
    {
      return 0;
    }

  if (stream->avail_out > 0 &&
      (ret = main_file_write (ofile, stream->next_out,
			      stream->avail_out, "write failed")))
    {
      return ret;
    }

  return 0;
}

int main_file_close (main_file *xfile)
{
  int ret = 0;

  if (! main_file_isopen (xfile))
    {
      return 0;
    }

#if XD3_STDIO
  ret = fclose (xfile->file);
  xfile->file = NULL;

#elif XD3_POSIX
  ret = close (xfile->file);
  xfile->file = -1;

#elif XD3_WIN32
  if (!CloseHandle(xfile->file)) {
    ret = get_errno ();
  }
  xfile->file = INVALID_HANDLE_VALUE;
#endif

  if (ret != 0) { XF_ERROR ("close", xfile->filename, ret = get_errno ()); }
  return ret;
}

int main_file_isopen (main_file *xfile)
{
#if XD3_STDIO
  return xfile->file != NULL;

#elif XD3_POSIX
  return xfile->file != -1;

#elif XD3_WIN32
  return xfile->file != INVALID_HANDLE_VALUE;
#endif
}

#if XD3_POSIX
/* POSIX-generic code takes a function pointer to read() or write().
 * This calls the function repeatedly until the buffer is full or EOF.
 * The NREAD parameter is not set for write, NULL is passed.  Return
 * is signed, < 0 indicate errors, otherwise byte count. */
typedef int (xd3_posix_func) (int fd, uint8_t *buf, usize_t size);

static int
xd3_posix_io (int fd, uint8_t *buf, size_t size,
	      xd3_posix_func *func, size_t *nread)
{
  int ret;
  size_t nproc = 0;

  while (nproc < size)
    {
      size_t tryread = xd3_min(size - nproc, 1U << 30);
      ssize_t result = (*func) (fd, buf + nproc, tryread);

      if (result < 0)
	{
	  ret = get_errno ();
	  if (ret != EAGAIN && ret != EINTR)
	    {
	      return ret;
	    }
	  continue;
	}

      if (nread != NULL && result == 0) { break; }

      nproc += result;
    }
  if (nread != NULL) { (*nread) = nproc; }
  return 0;
}
#endif

#if XD3_WIN32
static int xd3_win32_io (HANDLE file, uint8_t *buf, size_t size,
	      int is_read, size_t *nread)
{
  int ret = 0;
  size_t nproc = 0;

  while (nproc < size)
    {
      DWORD nproc2 = 0;  /* hmm */
	  DWORD nremain = size - nproc;
      if ((is_read ?
	   ReadFile (file, buf + nproc, nremain, &nproc2, NULL) :
	   WriteFile (file, buf + nproc, nremain, &nproc2, NULL)) == 0)
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
#endif

int main_file_write (main_file *ofile, uint8_t *buf, usize_t size, const char *msg)
{
  int ret = 0;

  IF_DEBUG1(DP(RINT "[main] write %"W"u\n bytes", size));
  
#if XD3_STDIO
  usize_t result;

  result = fwrite (buf, 1, size, ofile->file);

  if (result != size) { ret = get_errno (); }

#elif XD3_POSIX
  ret = xd3_posix_io (ofile->file, buf, size, (xd3_posix_func*) &write, NULL);

#elif XD3_WIN32
  ret = xd3_win32_io (ofile->file, buf, size, 0, NULL);

#endif

  if (ret)
    {
      XPR(NT "%s: %s: %s\n", msg, ofile->filename, xd3_mainerror (ret));
    }
  else
    {
      if (option_verbose > 5) { XPR(NT "write %s: %"W"u bytes\n",
				    ofile->filename, size); }
      ofile->nwrite += size;
    }

  return ret;
}

int main_file_read (main_file  *ifile,
		uint8_t    *buf,
		size_t      size,
		size_t     *nread,
		const char *msg)
{
  int ret = 0;
  IF_DEBUG1(DP(RINT "[main] read %s up to %"Z"u\n", ifile->filename, size));

#if XD3_STDIO
  size_t result;

  result = fread (buf, 1, size, ifile->file);

  if (result < size && ferror (ifile->file))
    {
      ret = get_errno ();
    }
  else
    {
      *nread = result;
    }

#elif XD3_POSIX
  ret = xd3_posix_io (ifile->file, buf, size, (xd3_posix_func*) &read, nread);
#elif XD3_WIN32
  ret = xd3_win32_io (ifile->file, buf, size, 1 /* is_read */, nread);
#endif

  if (ret)
    {
      XPR(NT "%s: %s: %s\n", msg, ifile->filename, xd3_mainerror (ret));
    }
  else
    {
      if (option_verbose > 4) { XPR(NT "read %s: %"Z"u bytes\n",
				    ifile->filename, (*nread)); }
      ifile->nread += (*nread);
    }

  return ret;
}

void* main_bufalloc (size_t size) {
#if XD3_WIN32
  return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
  return main_malloc1(size);
#endif
}

static void main_free1 (void *opaque, void *ptr)
{
  free (ptr);
}

void main_buffree (void *ptr) {
#if XD3_WIN32
  VirtualFree(ptr, 0, MEM_RELEASE);
#else
  main_free1(NULL, ptr);
#endif
}

static int main_file_seek (main_file *xfile, xoff_t pos)
{
  int ret = 0;

#if XD3_STDIO
  if (fseek (xfile->file, pos, SEEK_SET) != 0) { ret = get_errno (); }

#elif XD3_POSIX
  if ((xoff_t) lseek (xfile->file, pos, SEEK_SET) != pos)
    { ret = get_errno (); }

#elif XD3_WIN32
# if (_WIN32_WINNT >= 0x0500)
  LARGE_INTEGER move, out;
  move.QuadPart = pos;
  if (SetFilePointerEx(xfile->file, move, &out, FILE_BEGIN) == 0)
    {
      ret = get_errno ();
    }
# else
  if (SetFilePointer(xfile->file, (LONG)pos, NULL, FILE_BEGIN) ==
      INVALID_SET_FILE_POINTER)
    {
      ret = get_errno ();
    }
# endif
#endif

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
#if XD3_WIN32
		GPrintf("main_file_open failure, fileName: %s, error: %d", pDstFile.filename, ret);
#endif
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
#if XD3_WIN32
		GPrintf("config_stream failure, error: %d", ret);
#endif
		return ret;
	}
	xd3_source source;
	memset(&source, 0, sizeof(source));
	if (ret = main_set_source(&stream, &pSrcFile, &source))
	{
		cleanUp();
#if XD3_WIN32
		GPrintf("main_set_source failure, error: %d", ret);
#endif
		return ret;
	}
	uint8_t* main_bdata = (uint8_t*)main_bufalloc(config.winsize);
	size_t   nread = 0;
	do 
	{
		usize_t try_read = config.winsize;
		if (ret = main_file_read(&pDstFile, main_bdata, try_read, &nread, "main_file_read failure"))
		{
#if XD3_WIN32
			GPrintf("main_file_read failure, fileName: %s, error: %d", pDstFile.filename, ret);
#endif
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
#if XD3_WIN32
				GPrintf("main_open_output failure, fileName: %s, error: %d", pPatchFile.filename, ret);
#endif
				return EXIT_FAILURE;
			}
			if ((ret = main_write_output(&stream, &pPatchFile)) && (ret != PRINTHDR_SPECIAL))
			{
#if XD3_WIN32
				GPrintf("main_write_output failure, fileName: %s, error: %d", pPatchFile.filename, ret);
#endif
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
#if XD3_WIN32
		GPrintf("xd3_close_stream failure, error:%d", ret);
#endif
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
#if XD3_WIN32
		GPrintf("main_file_open failure, fileName: %s, error: %d", iFile.filename, ret);
#endif
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
#if XD3_WIN32
		GPrintf("config_stream failure, error: %d", ret);
#endif
		return ret;
	}
	xd3_source source;
	memset(&source, 0, sizeof(source));
	uint8_t* main_bdata = (uint8_t*)main_bufalloc(config.winsize);
	size_t   nread = 0;
	do 
	{
		usize_t try_read = config.winsize;
		if (ret = main_file_read(&iFile, main_bdata, try_read, &nread, "main_file_read failure"))
		{
#if XD3_WIN32
			GPrintf("main_file_read failure, fileName: %s, error: %d", iFile.filename, ret);
#endif
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
#if XD3_WIN32
				GPrintf("main_set_source failure, error: %d", ret);
#endif
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
#if XD3_WIN32
				GPrintf("main_open_output failure, fileName: %s, error: %d", oFile.filename, ret);
#endif
				return EXIT_FAILURE;
			}
			if ((ret = main_write_output(&stream, &oFile)) && (ret != PRINTHDR_SPECIAL))
			{
#if XD3_WIN32
				GPrintf("main_write_output failure, fileName: %s, error: %d", oFile.filename, ret);
#endif
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
#if XD3_WIN32
		GPrintf("xd3_close_stream failure, error:%d", ret);
#endif
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
				&nread, "main_file_read failure")))
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
		&nread, "main_file_read failure")))
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
