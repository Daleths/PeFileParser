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
