#include "../header/errorhandling.h"

void DisplayError(const wchar_t ErrorName[]){
    wprintf(L"\nProcess exit with error \"%s\", with error code: %d", ErrorName, GetLastError());
    ExitProcess(0);
}