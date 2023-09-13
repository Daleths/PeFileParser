#ifndef __ReadWrite__
#define __ReadWrite__
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "errorhandling.h"


BYTE* GetFileContent(const wchar_t FilePath[]);
PVOID ExtractDosHeader(const BYTE FileContent[], const BOOL Is32Bit);
PVOID ExtractPEHeader(const BYTE FileContent[], const BOOL Is32Bit);
PVOID ExtractNtHeader(const BYTE FileContent[], const BOOL Is32Bit);

void ExtractImportTable(const BYTE FileContent[], const BOOL Is32Bit);

void GetExePath(wchar_t FileName[]);

#endif
/*rva: This is the RVA that you want to convert to a file offset. An RVA is an address relative to the image's base address when it's loaded into memory.

PImageSectionHeader->VirtualAddress: This is the RVA of the start of the section where you want to perform the conversion. It indicates where the section is loaded into memory when the PE file is executed.

PImageSectionHeader->PointerToRawData: This is the file offset of the start of the section within the PE file on disk. It specifies where the section's data is located within the file.

Here's a step-by-step breakdown of how the calculation is performed:

Subtract PImageSectionHeader->VirtualAddress from rva: This step calculates the offset of the RVA within the section. It essentially determines how far into the section the RVA is located.

Add PImageSectionHeader->PointerToRawData to the result: This step takes the RVA offset calculated in the previous step and adds it to the file offset of the section. This combination gives you the absolute file offset within the PE file where the data corresponding to the input RVA is stored.*/