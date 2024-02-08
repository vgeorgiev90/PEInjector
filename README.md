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


## Credits
- @mr.d0x @NUL0x4C and @5pider and the incredible [Maldev academy](https://maldevacademy.com/)


## Disclaimer
As always this simple tool is created for educational purposes only ! 