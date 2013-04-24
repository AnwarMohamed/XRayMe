#pragma once
#include "XRayMe-DLL.h"

struct XRAY_VIRUS_DEFINITION
{
	UCHAR StepSize;					//1, 2 or 4 bytes
	struct
	{
		PDWORD	Ptr;
		DWORD	Size;
		BOOL	IsIgnorableByte;	//You will allow the user to ignore some bytes like {0x55,0x67,??,0x55} and so on
		CHAR	IgnorableByte;		// that's the byte that will represent the "??" byte .. like if it== 0xFF .. the sign will be {0x55,0x67,0xFF,0x55}
	}Signature;
	
	struct
	{
		DWORD	Type; 		//(TYPE_XOR, TYPE_ADD, TYPE_ROL (rotate),TYPE_NEG}
		DWORD	Value; 		//(if the user already know the key .. if not he will set it with null)
		PDWORD	Key;		//(pointer to the buffer that will take the key	... or null if it's not important
	}BufferAlgorithm;
	
	struct
	{
		DWORD	Type; 		//(TYPE_XOR, TYPE_ADD, TYPE_ROL (rotate)}
		DWORD	Value; 
		PDWORD	Key;		//ptr to the buffer that will receive the key ... or null if not important
	}KeyAlgorithm;			//if the virus encrypt the key .. or use to keys .. on key change the other key everytime ... see anti-virut 

};


class DLLEXPORT cXRay
{
	XRAY_VIRUS_DEFINITION* VirusDef;
	DWORD	Buffer;			//The Pointer to the last checked file
	DWORD	Size;
	BOOL	IsInfected;		//true if the last checked file is infected with the virus

	cPEFile*	File;
	BOOL		Scan();

	UINT	InfectedSec;
	DWORD	Entrypoint;
	image_section_header* Sections;

	BOOL FoundEPO;
	PUCHAR CallPtr;
public:
	cXRay(XRAY_VIRUS_DEFINITION* VirusDefinition);
	~cXRay();

	DWORD	CheckFile(CHAR* Buffer, DWORD Size);	//return entrypoint or NULL instead ... and set InInfected = true if it's infected
	DWORD	CheckFile(cFile*  cFilePointer);		//set the Buffer = File->BaseAddress and the Size = FileLength
	DWORD	CheckFile(CHAR* Filename);
	DWORD	GetValue(DWORD* Ptr);					//decrypt 4 bytes and return them
	SHORT	GetValue(SHORT* Ptr);					//decrypt 2 bytes and return them
	CHAR	GetValue(CHAR* Ptr);					//decrypt 1 byte and return it
	CHAR*	Decrypt(CHAR* Buffer, DWORD Size);		//the buffer and the its size must be included inside the buffer and the size that entered into CheckFile

	BOOL	BufferLoaded;
};