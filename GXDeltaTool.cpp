﻿// GXDeltaTool.cpp: 定义控制台应用程序的入口点。
//

#include "GXdelta.h"
#include <iostream>
//#include "vld.h"

int main(int argc, char *argv[])
{
	if (argc != 5)
	{
		cout << "param is not Correct!" << endl;
		return 0;
	}
	string iCmd = argv[1];
	string sFileName = argv[2];
	string iFileName = argv[3];
	string oFileName = argv[4];
	GXdelta pXDelta;
	if (iCmd == "-d")
	{
		pXDelta.diff(sFileName, iFileName, oFileName);
	}
	else if (iCmd == "-p")
	{
		pXDelta.patch(iFileName, sFileName, oFileName);
	}
	else
	{
		cout << "param not support!" << endl;
	}
    return 0;
}

