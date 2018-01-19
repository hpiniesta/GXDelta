#pragma once
#include <xstring>
#include "xdelta3.h"
#include "xdelta3-internal.h"
using namespace std;

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

class GXdelta
{
public:
	GXdelta();
	~GXdelta();
public:
	bool diff(const string &srcFile, const string &dstFile, const string &patchFile);
	bool patch(const string &iFileName, const string &sFileName, const string &oFileName);
private:
	int main_set_source(xd3_stream *stream, main_file *sfile, xd3_source *source);
	int main_getblk_lru(xd3_source *source, xoff_t blkno, main_blklru** blrup, int *is_new);
	int main_read_seek_source(xd3_stream *stream, xd3_source *source, xoff_t blkno);
	int main_getblk_func(xd3_stream *stream, xd3_source *source, xoff_t blkno);
private:
	main_blklru *lru;
	usize_t lru_size;
};

