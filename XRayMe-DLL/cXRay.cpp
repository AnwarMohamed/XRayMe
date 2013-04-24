#include "cXRay.h"
//#include "XRayMe-DLL.h"
#include <cstdio>

cXRay::cXRay(XRAY_VIRUS_DEFINITION* VirusDefinition)
{
	BufferLoaded = FALSE;
	VirusDef = VirusDefinition;
	IsInfected = FALSE;
	FoundEPO = FALSE;
}

cXRay::~cXRay(void)
{
}

DWORD cXRay::CheckFile(CHAR* Buffer, DWORD Size)
{
	File = new cPEFile(Buffer, Size);
	if (File->FileLoaded) return Scan();
	else return NULL;
}

DWORD cXRay::CheckFile(cFile* cFilePointer)
{
	if (cFilePointer->FileLength <= 0) return NULL;
	File = new cPEFile((CHAR*)cFilePointer->BaseAddress, cFilePointer->FileLength);
	if (File->FileLoaded) return Scan();
	else return NULL;
};

DWORD cXRay::CheckFile(CHAR* Filename)
{
	File = new cPEFile(Filename);
	if (File->FileLoaded) return Scan();
	else return NULL;
}

BOOL cXRay::Scan()
{
	if (File->PEHeader != NULL)
    {
		Sections = (image_section_header *) (File->PEHeader->header.size_of_optional_header + (DWORD) & File->PEHeader->optional);
		if ((DWORD)Sections >= (File->BaseAddress + File->FileLength)) return FALSE;

		InfectedSec = File->nSections - 1;

		Size = min(File->Section[InfectedSec].SizeOfRawData,File->Section[InfectedSec].VirtualSize) - VirusDef->Signature.Size;
		Buffer = (File->Section[InfectedSec].PointerToRawData + File->BaseAddress);
		BufferLoaded = TRUE;

		Entrypoint = File->PEHeader->optional.address_of_entry_point - File->Section[0].VirtualAddress + File->Section[0].PointerToRawData;

		printf(" [*] Entrypoint: 0x%08lx\n", (PINT)Entrypoint);

		if ((Buffer + Size)  >= File->BaseAddress + File->FileLength) return FALSE;

		//Check if the last Sections is executable
		if (!(Sections[InfectedSec].characteristics & IMAGE_SCN_MEM_EXECUTE)) return TRUE;

		//take the added BufferSize ONLY to XRAY it (if you can get the added BufferSize)
		if (!strcmp(Sections[InfectedSec].name,".rsrc"))
		{
			if (File->PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE].size < Size)
			{
				Buffer += File->PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE].size;
				Size   -= File->PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE].size;

				if (Buffer >= File->BaseAddress + File->FileLength) return FALSE;
				if ((signed long)Size < (signed long)0) return FALSE;
			}
			else return Entrypoint;

			printf(" [*] Suspicious Resource Section\n");
          
		}
		else if (!strcmp(Sections[InfectedSec].name,".reloc"))
		{
			if (File->PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].size < Size)
			{
				Buffer += File->PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].size;
				Size   -= File->PEHeader->optional.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].size;
			}
			else return Entrypoint;
			
			printf(" [*] Suspicious Relocables Section\n");  
		}

		printf(" [*] Buffer: 0x%08lx Size: %ld bytes\n", (PINT)(Buffer - File->BaseAddress) ,Size);

		//Begin Searching for call/jmp ptr_to_last_section
		DWORD Offset = Buffer - (File->BaseAddress + Entrypoint);
        
		for (PCHAR ptr = (PCHAR)(Entrypoint + File->BaseAddress); ptr <
			(PCHAR)(File->BaseAddress + Sections[0].pointer_to_raw_data + 
			Sections[0].size_of_raw_data); ptr++)
		{
			if(ptr[0] == 0xFFFFFFE8)
			{
				ptr++;
				if (*((PDWORD)ptr) > Offset && *((PDWORD)ptr) < (Buffer + Size - 1))
				{
					printf(" [*] New Eip = 0x%08lx\n", (PINT)((ptr - File->BaseAddress-Sections[0].pointer_to_raw_data+ Sections[0].virtual_address)+0x01000000 -1));
					CallPtr = (PUCHAR)(ptr-2);
					FoundEPO = TRUE;
					break;
				};
				ptr--;
			};                 
		};

		return Entrypoint;
	}
	else return NULL;
}