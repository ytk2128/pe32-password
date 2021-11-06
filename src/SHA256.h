#pragma once
#include <string>

std::string szSHA256 = R"(
	 push ebp
	 mov ebp, esp
	 sub esp, 0xC
	 mov dword ptr ss:[ebp-0x8], 0x0
	 mov dword ptr ss:[ebp-0x4], 0x0
	 mov ebx, dword ptr fs:[0x00000030]
	 mov ebx, dword ptr ds:[ebx+0x8]

	 push 0xF0000000
	 push 0x18
	 push 0x0
	 push 0x0
	 lea eax, ss:[ebp-0x8]
	 push eax
	 call dword ptr ds:[ebx+funcCryptAcquireContextA.rva]

	 lea ecx, ss:[ebp-0x4]
	 push ecx
	 push 0x0
	 push 0x0
	 push 0x800C
	 mov edx, dword ptr ss:[ebp-0x8]
	 push edx
	 call dword ptr ds:[ebx+funcCryptCreateHash.rva]

	 push 0x0
	 mov eax, dword ptr ss:[ebp+0x8]
	 push eax
	 call dword ptr ds:[ebx+funclstrlenA.rva]

	 push eax
	 mov ecx, dword ptr ss:[ebp+0x8]
	 push ecx
	 mov edx, dword ptr ss:[ebp-0x4]
	 push edx
	 call dword ptr ds:[ebx+funcCryptHashData.rva]

	 mov dword ptr ss:[ebp-0xC], 0x20
	 push 0x0
	 lea eax, ss:[ebp-0xC]
	 push eax
	 mov ecx, dword ptr ss:[ebp+0xC]
	 push ecx
	 push 0x2
	 mov edx, dword ptr ss:[ebp-0x4]
	 push edx
	 call dword ptr ds:[ebx+funcCryptGetHashParam.rva]

	 mov eax, dword ptr ss:[ebp-0x4]
	 push eax
	 call dword ptr ds:[ebx+funcCryptDestroyHash.rva]

	 push 0x0
	 mov ecx, dword ptr ss:[ebp-0x8]
	 push ecx
	 call dword ptr ds:[ebx+funcCryptReleaseContext.rva]

	 xor eax, eax
	 mov esp, ebp
	 pop ebp
	 ret
)";
