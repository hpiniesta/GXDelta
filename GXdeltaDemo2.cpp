// GXdeltaDemo2.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "GXdelta.h"


int main()
{
	GXdelta pGXdelta;
	string strSrcFile = "Install1.exe";
	string strDstFile = "Install19.exe";
	string strPatchFile = "InstallExe.patch";
	pGXdelta.diff(strSrcFile, strDstFile, strPatchFile);
	//pGXdelta.patch("InstallExe.patch", "Install1.exe", "InstallNew.exe");
    return 0;
}
