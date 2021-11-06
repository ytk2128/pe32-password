#pragma once
#include <string>

std::string szInitializeVariables = R"(
; Get LoadLibraryA
	 push hashGenerate("LoadLibraryA")
	 call ebp
	 mov dword ptr ds:[ebx+funcLoadLibraryA.rva], eax

; Get base address of user32.dll
	 lea edx, ds:[ebx+szUser32.rva]
	 push edx
	 call dword ptr ds:[ebx+funcLoadLibraryA.rva]
	 mov dword ptr ds:[ebx+baseUser32.rva], eax

; Get base address of advapi32.dll
	 lea edx, ds:[ebx+szAdvapi32.rva]
	 push edx
	 call dword ptr ds:[ebx+funcLoadLibraryA.rva]
	 mov dword ptr ds:[ebx+baseAdvapi32.rva], eax

; Get GetProcAddress
	 push hashGenerate"GetProcAddress")
	 call ebp
	 mov dword ptr ds:[ebx+funcGetProcAddress.rva], eax

;Get DialogBoxIndirectParamA
	 lea edx, ds:[ebx+szDialogBoxIndirectParamA.rva]
	 push edx
	 push dword ptr ds:[ebx+baseUser32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcDialogBoxIndirectParamA.rva], eax

	 ;Get GetDlgItemTextA
	 lea edx, ds:[ebx+szGetDlgItemTextA.rva]
	 push edx
	 push dword ptr ds:[ebx+baseUser32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcGetDlgItemTextA.rva], eax

; Get EndDialog
	 lea edx, ds:[ebx+szEndDialog.rva]
	 push edx
	 push dword ptr ds:[ebx+baseUser32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcEndDialog.rva], eax

; Get lstrlenA
	 push hashGenerate("lstrlenA")
	 call ebp
	 mov dword ptr ds:[ebx+funclstrlenA.rva], eax

; Get lstrcmpA
	 push hashGenerate("lstrcmpA")
	 call ebp
	 mov dword ptr ds:[ebx+funclstrcmpA.rva], eax

; Get CryptAcquireContextA
	 lea edx, ds:[ebx+szCryptAcquireContextA.rva]
	 push edx
	 push dword ptr ds:[ebx+baseAdvapi32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcCryptAcquireContextA.rva], eax

; Get CryptCreateHash
	 lea edx, ds:[ebx+szCryptCreateHash.rva]
	 push edx
	 push dword ptr ds:[ebx+baseAdvapi32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcCryptCreateHash.rva], eax

; Get CryptDestroyHash
	 lea edx, ds:[ebx+szCryptDestroyHash.rva]
	 push edx
	 push dword ptr ds:[ebx+baseAdvapi32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcCryptDestroyHash.rva], eax

; Get CryptReleaseContext
	 lea edx, ds:[ebx+szCryptReleaseContext.rva]
	 push edx
	 push dword ptr ds:[ebx+baseAdvapi32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcCryptReleaseContext.rva], eax

; Get CryptGetHashParam
	 lea edx, ds:[ebx+szCryptGetHashParam.rva]
	 push edx
	 push dword ptr ds:[ebx+baseAdvapi32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcCryptGetHashParam.rva], eax

; Get CryptHashData
	 lea edx, ds:[ebx+szCryptHashData.rva]
	 push edx
	 push dword ptr ds:[ebx+baseAdvapi32.rva]
	 call dword ptr ds:[ebx+funcGetProcAddress.rva]
	 mov dword ptr ds:[ebx+funcCryptHashData.rva], eax
)";
