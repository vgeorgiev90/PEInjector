#pragma once
#include <windows.h>


#define RTL_MAX_DRIVE_LETTERS 32



/*------------------------
 Simple struct to hold
 the PE and its size
------------------------*/
typedef struct _CONTENT {
	LPVOID data;
	DWORD size;
} CONTENT, * PCONTENT;


/*--------------------------
 Struct to hold the parsed
 headers of the PE
--------------------------*/
typedef struct _PEHDRS {
	PBYTE pPeBuffer;
	DWORD PeSize;

	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSectHeader;

	PIMAGE_DATA_DIRECTORY pImportDir;
	PIMAGE_DATA_DIRECTORY pRelocDir;
	PIMAGE_DATA_DIRECTORY pTslDir;
	PIMAGE_DATA_DIRECTORY pExportDir;
	PIMAGE_DATA_DIRECTORY pExceptDir;

	BOOL IsDLL;

}PEHDRS, * PPEHDRS;


/*---------------------------------
Struct to hold syscall information
---------------------------------*/
typedef struct _SYSCALL
{
	DWORD dwSSn;                    // syscall number
	DWORD dwSyscallHash;            // syscall hash value
	PVOID pSyscallAddress;          // syscall address
	PVOID pSyscallIndJmp;           // address of a different 'syscall' instruction for indirect syscall

}SYSCALL, * PSYSCALL;


/*---------------------------------------------
Struct to hold syscalls funcs that will be used
---------------------------------------------*/
typedef struct _SC_FUNC {
	SYSCALL NtAllocateVirtualMemory;
	SYSCALL NtProtectVirtualMemory;
	SYSCALL NtCreateThreadEx;
	SYSCALL NtWaitForSingleObject;
	SYSCALL NtClose;
} SC_FUNC, * PSC_FUNC;


typedef struct _NTCONF {
	PDWORD pdwAddressesArray;   // VA of the addresses array of all functions exported
	PDWORD pdwNamesArray;       // VA of the names array of all functions exported
	PWORD pwOrdinalsArray;      // VA of the ordinals array of all functions exported
	DWORD dwNamesNumber;        // Number of exported functions
	ULONG_PTR uModule;          // Base address of the module (ntdll.dll), used to calculate RVAs

} NTCONF, * PNTCONF;




/*---------------------------------
    Generic Structs definitions
---------------------------------*/
//Base relocations related struct
typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;  // Specifies where the base relocation is to be applied.
	WORD	Type : 4;     // Indicates the type of base relocation to be applied.
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


//PEB related
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, * PCURDIR;


typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;

	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

	UNICODE_STRING RedirectionDllName;
	UNICODE_STRING HeapPartitionName;
	ULONG_PTR DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
	ULONG DefaultThreadpoolThreadMaximum;
	ULONG HeapMemoryTypeMask;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;


typedef PVOID PACTIVATION_CONTEXT;


typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;


typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;


typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _USTRING {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} USTRING, * PUSTRING;