#include "../header/File.h"
#include "../header/header.h"
#include "../header/errorhandling.h"
#define __PRINTOUT__



PVOID ExtractDosHeader(const BYTE FileContent[], const BOOL Is32Bit){
    PIMAGE_DOS_HEADER FileDosHeader = NULL;

    FileDosHeader = (PIMAGE_DOS_HEADER)FileContent;

    #ifdef __PRINTOUT__
    printf("\ne_magic: 0x%x: MZ Signature", FileDosHeader->e_magic);
    printf("\ne_lfanew: 0x%x: Offset of PE header", FileDosHeader->e_lfanew);
    #endif

    return FileDosHeader;
    
}
/*RVAs are used to specify addresses within the memory image of a PE file, 
while file offsets indicate positions within the PE file on disk.

RVA: constaint
offset: Can be change

*/

/*rva: This is the RVA that you want to convert to a file offset. An RVA is an address relative to the image's base address when it's loaded into memory.

PImageSectionHeader->VirtualAddress: This is the RVA of the start of the section where you want to perform the conversion. It indicates where the section is loaded into memory when the PE file is executed.

PImageSectionHeader->PointerToRawData: This is the file offset of the start of the section within the PE file on disk. It specifies where the section's data is located within the file.

Subtract PImageSectionHeader->VirtualAddress from rva: This step calculates the offset of the RVA within the section. It essentially determines how far into the section the RVA is located.

Add PImageSectionHeader->PointerToRawData to the result: This step takes the RVA offset calculated in the previous step and adds it to the file offset of the section. This combination gives you the absolute file offset within the PE file where the data corresponding to the  input RVA is stored.*/

 /*Convert Virtual Address to File Offset */
DWORD Rva2Offset64(DWORD rva,PIMAGE_SECTION_HEADER psh,PIMAGE_NT_HEADERS PImageNtHeader){
    size_t i = 0;
    PIMAGE_SECTION_HEADER PImageSectionHeader;
    if(rva == 0){
            return (rva);
    }
    PImageSectionHeader = psh;
    for(i = 0; i < PImageNtHeader->FileHeader.NumberOfSections; i++){
        /*
        Iterates through the section headers, comparing the input RVA with the start (VirtualAddress) and end (VirtualAddress + VirtualSize) addresses of each section.
        If the RVA falls within the address range of a section, the loop breaks, and PImageSectionHeader points to the section containing the RVA.
        */
        // Determine which section RVA belongs to
        if(rva >= PImageSectionHeader->VirtualAddress && rva < PImageSectionHeader->VirtualAddress + PImageSectionHeader->Misc.VirtualSize){
                break;
        }
        PImageSectionHeader++;
    }
    /*
    importRva - sectionStart: This part of the calculation computes the offset of the RVA within the section. It subtracts the RVA of the section's start (sectionStart) from the input RVA (importRva). This essentially calculates how far into the section the RVA is located.

    ImportRVA - sectionStart:
    Phần này tính offset RVA trong section, bằng cách trừ đi VirtualAddress của Section đó
    PointerToRawData là section file Offset, cộng lại -> offset của PE file

    + sectionHeader->PointerToRawData: After calculating the offset within the section, you add the section's file offset (PointerToRawData). This addition effectively moves from the RVA-based offset to the file-based offset within the PE file.
    */
    return (rva - PImageSectionHeader->VirtualAddress + PImageSectionHeader->PointerToRawData);
} 


/*
rva: This is the RVA you want to check. An RVA is a relative address within the loaded image in memory.

PImageSectionHeader->VirtualAddress: This is the VirtualAddress (RVA) of the start of the section you are currently examining. It represents where the section is loaded into memory when the PE file is executed.

PImageSectionHeader->Misc.VirtualSize: This field represents the size of the section as specified in the PE file headers. It indicates the range of valid RVAs within the section.

Now, let's break down the condition:

rva >= PImageSectionHeader->VirtualAddress: This part of the condition checks if the input RVA (rva) is greater than or equal to the RVA of the section's starting address (PImageSectionHeader->VirtualAddress). This ensures that the RVA is within the section or at least starts at the section's beginning.

rva < PImageSectionHeader->VirtualAddress + PImageSectionHeader->Misc.VirtualSize: This part checks if the input RVA is less than the sum of the section's starting RVA and its virtual size (PImageSectionHeader->VirtualAddress + PImageSectionHeader->Misc.VirtualSize). This ensures that the RVA does not extend beyond the end of the section.
*/
DWORD Rva2Offset32(DWORD rva,PIMAGE_SECTION_HEADER psh,PIMAGE_NT_HEADERS32 PImageNtHeader)
{
    size_t i = 0;
    PIMAGE_SECTION_HEADER PImageSectionHeader;
    if(rva == 0){
        return (rva);
    }
    PImageSectionHeader = psh;
    
    for(i = 0; i < PImageNtHeader->FileHeader.NumberOfSections; i++){
        // Determine which section RVA belongs to
        if(rva >= PImageSectionHeader->VirtualAddress && rva < PImageSectionHeader->VirtualAddress + PImageSectionHeader->Misc.VirtualSize){
                break;
        }
        PImageSectionHeader++;
    }
    /*
    importRva - sectionStart: This part of the calculation computes the offset of the RVA within the section. It subtracts the RVA of the section's start (sectionStart) from the input RVA (importRva). This essentially calculates how far into the section the RVA is located.

    ImportRVA - sectionStart:
    Phần này tính offset RVA trong section, bằng cách trừ đi VirtualAddress của Section đó
    PointerToRawData là section file Offset, cộng lại -> offset của PE file

    + sectionHeader->PointerToRawData: After calculating the offset within the section, you add the section's file offset (PointerToRawData). This addition effectively moves from the RVA-based offset to the file-based offset within the PE file.
    */
    return (rva - PImageSectionHeader->VirtualAddress + PImageSectionHeader->PointerToRawData);

} 

/*
different 64 - 32:
PIMAGE_NT_HEADERS
PIMAGE_OPTIONAL_HEADER
*/

PVOID ExtractNtHeader(const BYTE FileContent[], const BOOL Is32Bit){
    if(Is32Bit){
        PIMAGE_NT_HEADERS32 FileNtHeader = NULL;
        PIMAGE_DOS_HEADER FileDosHeader = (PIMAGE_DOS_HEADER)FileContent;

        FileNtHeader = (PIMAGE_NT_HEADERS32)(FileContent + FileDosHeader->e_lfanew);
        #ifdef __PRINTOUT__
        printf("\nFile Signature: 0x%x: PE Signature", FileNtHeader->Signature);
        #endif
        PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)&(FileNtHeader->FileHeader);

        PIMAGE_OPTIONAL_HEADER32 OptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&(FileNtHeader->OptionalHeader);
        
        printf("\nMachine: 0x%x: Processor", FileHeader->Machine);
        printf("\nNumber of section: %d", FileHeader->NumberOfSections);
        printf("\nSizeOfOptionalHeader: 0x%x", FileHeader->SizeOfOptionalHeader);
        printf("\nCharacteristics: 0x%x: Exe or DLL,...", FileHeader->Characteristics);

        if(OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ){
            printf("\nMagic: 0x%x: 64 bit", OptionalHeader->Magic);
        }
        else if(OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ){
            printf("\nMagic: 0x%x: 32 bit", OptionalHeader->Magic);
        }
        printf("\nAddress of entrypoint: 0x%x", OptionalHeader->AddressOfEntryPoint);
        printf("\nImageBaseAddress: 0x%x", OptionalHeader->ImageBase);

        return FileNtHeader;
    }
    else{
        PIMAGE_NT_HEADERS64 FileNtHeader = NULL;
        PIMAGE_DOS_HEADER FileDosHeader = (PIMAGE_DOS_HEADER)FileContent;

        FileNtHeader = (PIMAGE_NT_HEADERS64)(FileContent + FileDosHeader->e_lfanew);
        #ifdef __PRINTOUT__
        printf("\nFile Signature: 0x%x: PE Signature", FileNtHeader->Signature);
        #endif
        PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)&(FileNtHeader->FileHeader);

        PIMAGE_OPTIONAL_HEADER64 OptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&(FileNtHeader->OptionalHeader);
        
        printf("\nMachine: 0x%x: Processor", FileHeader->Machine);
        printf("\nNumber of section: %d", FileHeader->NumberOfSections);
        printf("\nSizeOfOptionalHeader: 0x%x", FileHeader->SizeOfOptionalHeader);
        printf("\nCharacteristics: 0x%x: Exe or DLL,...", FileHeader->Characteristics);

        if(OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ){
            printf("\nMagic: 0x%x: 64 bit", OptionalHeader->Magic);
        }
        else if(OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ){
            printf("\nMagic: 0x%x: 32 bit", OptionalHeader->Magic);
        }
        printf("\nAddress of entrypoint: 0x%x", OptionalHeader->AddressOfEntryPoint);
        printf("\nImageBaseAddress: 0x%x", OptionalHeader->ImageBase);

        return FileNtHeader;
    }
}


void ExtractImportTable(const BYTE FileContent[], const BOOL Is32Bit){
    printf("\n==================Import Table==================\n");
    if(Is32Bit){
        PIMAGE_NT_HEADERS32 FileNtHeader = NULL;
        PIMAGE_DOS_HEADER FileDosHeader = (PIMAGE_DOS_HEADER)FileContent;
        
        FileNtHeader = (PIMAGE_NT_HEADERS32)(FileContent + FileDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSech = IMAGE_FIRST_SECTION(FileNtHeader);
        PIMAGE_IMPORT_DESCRIPTOR FileImportDescriptor = NULL;

        if(FileNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0){
            FileImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)FileContent +\
                                Rva2Offset32(FileNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,pSech,FileNtHeader));
        }
        LPSTR libname[256];
        // printf("\nOffset: 0x%x\n", Rva2Offset32(FileNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,pSech,FileNtHeader));
        size_t i=0;
    
        while(FileImportDescriptor->Name != 0){
            libname[i]=(PCHAR)((DWORD_PTR)FileContent + Rva2Offset32(FileImportDescriptor->Name,pSech,FileNtHeader));
            printf("[+]%s - 0x%x", libname[i], FileImportDescriptor->Name);
            
            PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(FileContent + Rva2Offset32(FileImportDescriptor->OriginalFirstThunk, pSech, FileNtHeader));
            while (pThunk->u1.AddressOfData) {
            //     // Resolve the function name or ordinal
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(FileContent + Rva2Offset32(pThunk->u1.AddressOfData, pSech, FileNtHeader));
            
                const char* functionName = pImportByName->Name;
                printf("\n\t[-]%s", functionName);
                
                pThunk++; 
            }
            
            printf("\n\n");
            
            FileImportDescriptor++; 
            i++;
        }
    }
    else{
        PIMAGE_NT_HEADERS64 FileNtHeader = NULL;
        PIMAGE_DOS_HEADER FileDosHeader = (PIMAGE_DOS_HEADER)FileContent;
        
        FileNtHeader = (PIMAGE_NT_HEADERS64)(FileContent + FileDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSech = IMAGE_FIRST_SECTION(FileNtHeader);
        PIMAGE_IMPORT_DESCRIPTOR FileImportDescriptor = NULL;

        if(FileNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0){
            FileImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)FileContent +\
                                Rva2Offset64(FileNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,pSech,FileNtHeader));
        }

        LPSTR libname[256];
        // printf("\nOffset: 0x%x\n", Rva2Offset64(FileNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,pSech,FileNtHeader));
        size_t i=0;
        
        while(FileImportDescriptor->Name != 0){
            libname[i]=(PCHAR)((DWORD_PTR)FileContent + Rva2Offset64(FileImportDescriptor->Name,pSech,FileNtHeader));
            printf("[+]%s - 0x%x", libname[i], FileImportDescriptor->Name);
            
            PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)(FileContent + Rva2Offset64(FileImportDescriptor->OriginalFirstThunk, pSech, FileNtHeader));
            
            while (pThunk->u1.AddressOfData) {
                // Resolve the function name or ordinal
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(FileContent + Rva2Offset64(pThunk->u1.AddressOfData, pSech, FileNtHeader));
                const char* functionName = pImportByName->Name;
                printf("\n\t[-]%s", functionName);
                // Use the functionName to load the imported function (e.g., with GetProcAddress)
                
                pThunk++; // Move to the next entry
            }
            
            printf("\n\n");
            
            FileImportDescriptor++; 
            i++;
        }

    }
}

