#include "../header/main.h"

int main(int argc, char const *argv[]){

    wchar_t FileName[260];
    memset(FileName, 0, sizeof(FileName));
    GetExePath(FileName);
    
    DWORD BinType;
    GetBinaryTypeW(FileName, &BinType);
    BOOL Is32Bit = 0;
    Is32Bit = BinType == SCS_32BIT_BINARY;
    
    wprintf(L"File name: %s", FileName);
    BYTE *FileContent = GetFileContent(FileName);
    ExtractDosHeader(FileContent, Is32Bit);
    ExtractNtHeader(FileContent, Is32Bit);
    ExtractImportTable(FileContent, Is32Bit);

    return 0;   
}
