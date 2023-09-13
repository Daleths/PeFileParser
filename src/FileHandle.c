#include "../header/File.h"

BYTE* GetFileContent(const wchar_t FilePath[]){
    HANDLE hFile = CreateFileW(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE){
        DWORD FileSize = 0;
        FileSize = GetFileSize(hFile, NULL);
        if(FileSize!=0 || FileSize <=50000){
            BYTE *FileContent = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize);
            if(FileContent != NULL){
                if(ReadFile(hFile, FileContent, FileSize, NULL, NULL)){
                    return FileContent;
                }
                else DisplayError(L"ReadFile Error in GetFileContent");
                
            }
            else DisplayError(L"HeapAlloc Error in GetFileContent");
        }
        else goto __FILE__READ__WRITE__ERROR;
        
        CloseHandle(hFile);
    }

    else DisplayError(L"CreateFileW Error in GetFileContent");

    __FILE__READ__WRITE__ERROR:
        DisplayError(L"Cannot open file, file size is too big");
        CloseHandle(hFile);
        return NULL;
    
}


void GetExePath(wchar_t FileName[]){
    OPENFILENAMEW ofn;
    wchar_t szFile[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn) == TRUE) {
        wcscpy(FileName, szFile);
    }
}