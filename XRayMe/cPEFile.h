#pragma once
#include "cFile.h"
#include "pe.h"

struct EXPORTFUNCTION {
	char* funcName;
	WORD funcOrdinal;
	DWORD funcRVA;
};
struct EXPORTTABLE 
{
	DWORD nFunctions;
	DWORD nNames;
	DWORD Base;
	PDWORD pFunctions;
	PDWORD pNames;
	PWORD pNamesOrdinals;
	EXPORTFUNCTION *Functions;
};

struct IMPORTTABLE_DLL;
struct IMPORTTABLE_API;

struct SECTION_STRUCT
{
	char* SectionName;
	DWORD VirtualAddress;
	DWORD VirtualSize;
	DWORD PointerToRawData;
	DWORD SizeOfRawData;
	DWORD Characterisics;
	DWORD RealAddr;
};
struct IMPORTTABLE
{
	DWORD nDLLs;
	IMPORTTABLE_DLL* DLL;
};
struct IMPORTTABLE_DLL
{
	char* DLLName;
	DWORD nAPIs;
	IMPORTTABLE_API* API;
};
struct IMPORTTABLE_API
{
	char* APIName;
	DWORD APIAddressPlace;
};
struct RELOCATION_ENTRIES
{
	DWORD Offset;
	char* Type;
};
struct RELOCATIONS
{
	DWORD VirtualAddress;
	unsigned int nEntries;
	RELOCATION_ENTRIES* Entries;
};

#define DATADIRECTORY_EXPORT		0x0001
#define DATADIRECTORY_IMPORT		0x0002
#define DATADIRECTORY_RESOURCE		0x0004
#define DATADIRECTORY_EXCEPTION		0x0008
#define DATADIRECTORY_CERTIFICATE	0x0010
#define DATADIRECTORY_RELOCATION	0x0020
#define DATADIRECTORY_DEBUG			0x0040
#define DATADIRECTORY_ARCHITECT		0x0080
#define DATADIRECTORY_MACHINE		0x0100
#define DATADIRECTORY_TLS			0x0200
#define DATADIRECTORY_CONF			0x0400
#define DATADIRECTORY_BOUNDIMPORT	0x0800
#define DATADIRECTORY_IAT			0x1000
#define DATADIRECTORY_DELAYIMPORT	0x2000
#define DATADIRECTORY_RUNTIME		0x4000
#define DATADIRECTORY_RESERVED		0x8000

class DLLEXPORT cPEFile : public cFile
{
private:

	//Functions:
	bool ParsePE();
	VOID initDataDirectory();
	VOID initSections();
	VOID initImportTable();
	void initExportTable();	//export table
	void initRelocations();
public:
	//Variables
	bool FileLoaded;
	image_header* PEHeader;
	DWORD Magic;
	DWORD Subsystem;
	DWORD Imagebase;
	DWORD SizeOfImage;
	DWORD Entrypoint;
	DWORD FileAlignment;
	DWORD SectionAlignment;
	WORD DataDirectories;
	unsigned long nSections;
	unsigned int nRelocations;
	SECTION_STRUCT* Section;
	IMPORTTABLE ImportTable;
	RELOCATIONS* Relocations;

	/* for exports */
	EXPORTTABLE ExportTable;

	//Functions
	cPEFile(char* szFilename);
	cPEFile(char* buffer,DWORD size);
	~cPEFile();
	static bool identify(cFile* File);
	DWORD RVAToOffset(DWORD RVA);
	DWORD OffsetToRVA(DWORD RawOffset);

};