[+] Usage: Open and chose any PE File

Output should be something like this

```shell
File name: <selected file name>
e_magic: 0x5a4d: MZ Signature
e_lfanew: 0x80: Offset of PE header
File Signature: 0x4550: PE Signature
Machine: 0x8664: Processor
Number of section: 9
SizeOfOptionalHeader: 0xf0
Characteristics: 0x22f: Exe or DLL,...
Magic: 0x20b: 64 bit
Address of entrypoint: 0x14e0
ImageBaseAddress: 0x400000
==================Import Table==================
[+]ADVAPI32.dll - 0xc070
        [-]AdjustTokenPrivileges
        [-]CryptAcquireContextW
        [-]CryptCreateHash
        [-]CryptDestroyHash
        [-]CryptGetHashParam
        [-]CryptHashData
        [-]CryptReleaseContext
        [-]GetSecurityInfo
        [-]LookupAccountSidW
        [-]LookupPrivilegeValueA
        [-]OpenProcessToken

[+]dbghelp.dll - 0xc098
        [-]ImageNtHeader
        [-]StackWalk64
        [-]SymCleanup
        [-]SymFunctionTableAccess64
        [-]SymGetModuleBase64
        [-]SymInitialize

[+]KERNEL32.dll - 0xc17c
        [-]CloseHandle
        [-]CreateFileMappingW
        [-]CreateFileW
        [-]CreateToolhelp32Snapshot
        [-]DeleteCriticalSection
        [-]DuplicateHandle
        [-]EnterCriticalSection
        [-]FileTimeToSystemTime
        [-]GetCurrentProcess
        [-]GetCurrentProcessId
        [-]GetCurrentThreadId
        [-]GetFileSize
        [-]GetFileTime
        [-]GetLastError
        [-]GetModuleHandleA
        [-]GetNativeSystemInfo
        [-]GetProcAddress
        [-]GetProcessHeap
        [-]GetStartupInfoA
        [-]GetSystemTimeAsFileTime
        [-]GetThreadContext
        [-]GetTickCount
        [-]HeapAlloc
        [-]HeapFree
        [-]InitializeCriticalSection
        [-]LeaveCriticalSection
        [-]LoadLibraryA
        [-]MapViewOfFile
        [-]Module32FirstW
        [-]Module32NextW
        [-]OpenProcess
        [-]OpenThread
        [-]Process32FirstW
        [-]Process32NextW
        [-]QueryPerformanceCounter
        [-]ReadFile
        [-]ReadProcessMemory
        [-]RtlAddFunctionTable
        [-]RtlCaptureContext
        [-]RtlLookupFunctionEntry
        [-]RtlVirtualUnwind
        [-]SetUnhandledExceptionFilter
        [-]Sleep
        [-]SystemTimeToTzSpecificLocalTime
        [-]TerminateProcess
        [-]Thread32First
        [-]Thread32Next
        [-]TlsGetValue
        [-]UnhandledExceptionFilter
        [-]UnmapViewOfFile
        [-]VirtualProtect
        [-]VirtualQuery
        [-]VirtualQueryEx
        [-]WriteFile

[+]msvcrt.dll - 0xc220
        [-]__C_specific_handler
        [-]__getmainargs
        [-]__initenv
        [-]__iob_func
        [-]__lconv_init
        [-]__set_app_type
        [-]__setusermatherr
        [-]_acmdln
        [-]_amsg_exit
        [-]_cexit
        [-]_fmode
        [-]_initterm
        [-]_onexit
        [-]_vsnwprintf
        [-]_wcsicmp
        [-]abort
        [-]calloc
        [-]exit
        [-]fprintf
        [-]free
        [-]fwrite
        [-]malloc
        [-]memcmp
        [-]memcpy
        [-]memset
        [-]printf
        [-]putchar
        [-]puts
        [-]signal
        [-]sprintf
        [-]strcmp
        [-]strlen
        [-]strncmp
        [-]swprintf_s
        [-]vfprintf
        [-]wcscpy
        [-]wprintf

[+]PSAPI.DLL - 0xc230
        [-]GetModuleFileNameExW

[+]SHLWAPI.dll - 0xc240
        [-]PathFindExtensionW

[+]WINTRUST.dll - 0xc264
        [-]CryptCATAdminAcquireContext
        [-]CryptCATAdminCalcHashFromFileHandle
        [-]CryptCATAdminEnumCatalogFromHash
        [-]CryptCATAdminReleaseCatalogContext
        [-]CryptCATAdminReleaseContext
        [-]WinVerifyTrust
```
