#pragma once 
#ifndef WINDOWS_H
#define WINDOWS_H
#include <Windows.h>
#endif

struct FILE_DATE_TIME
{
	DWORD Year;
	DWORD Month;
	DWORD Day;
	DWORD Hour;
	DWORD Min;
	DWORD Sec;
};

class DLLEXPORT cFile
{
	HANDLE        hFile;
    HANDLE        hMapping;
	BOOL		  IsFile;
	BOOL		  isFound;
public:
    DWORD        BaseAddress;
    DWORD        FileLength;
	DWORD		 Attributes;
	FILE_DATE_TIME CreatedTime;
	FILE_DATE_TIME ModifiedTime;
	FILE_DATE_TIME AccessedTime;
	char*		 Filename;
	cFile(char* szFilename);
	cFile(char* buffer,DWORD size);
	int OpenFile(char* szFilename);
	BOOL IsFound();
	~cFile();
};