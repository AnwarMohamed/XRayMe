#include "cXRay.h"
//#include "XRayMe-DLL.h"
#include <cstdio>

cXRay::cXRay(XRAY_VIRUS_DEFINITION* VirusDefinition)
{
	BufferLoaded = FALSE;
	VirusDef = VirusDefinition;
	IsInfected = FALSE;
}

cXRay::~cXRay(void)
{
	free(VirusDef);
}

DWORD cXRay::CheckFile(CHAR* iBuffer, DWORD iSize)
{
	if (iSize <= 0) return NULL;
	Buffer = (DWORD)iBuffer;
	Size = iSize;
	BufferLoaded = TRUE;
	return Scan();
}

DWORD cXRay::CheckFile(cFile* File)
{
	if (File->FileLength <= 0) return NULL;
	Buffer = File->BaseAddress;
	Size = File->FileLength;
	BufferLoaded = TRUE;
	return Scan();
};


BOOL cXRay::Scan()
{
	UCHAR OKey, TKey;
	BOOL Constant = FALSE;

	for (UINT i=0; i<Size-VirusDef->Signature.Size; i++)
	{
		switch(VirusDef->BufferAlgorithm.Type)
		{ 
		case TYPE_XOR:
			OKey = (((UCHAR*)Buffer)[i])^VirusDef->Signature.Ptr[0];	
			/*for (UINT j=1; j<VirusDef->Signature.Size; j++)
			{
				TKey = (((UCHAR*)Buffer)[i+j])^VirusDef->Signature.Ptr[j];
				if (TKey != OKey) { Constant = FALSE; break; }
				else Constant = TRUE;
			}*/	
		}
	}

	//if (Constant) printf("%02x ", OKey);
	//return NULL;
}

CHAR RecursiveScan(UCHAR Key, UCHAR* Virus, UINT VirusSize, UCHAR* Signature, UINT SignatueSize, UINT Position)
{

}