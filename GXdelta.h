#pragma once
#include <xstring>
using namespace std;

class GXdelta
{
public:
	GXdelta();
	~GXdelta();
public:
	bool diff(const string &srcFile, const string &dstFile, const string &patchFile);
	bool patch(const string &iFileName, const string &sFileName, const string &oFileName);
};

