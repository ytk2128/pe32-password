#pragma once
#include <string>

std::string szCheckPassword = R"(
	 push ebp
	 mov ebp, esp
	 lea edx, ds:[ebx+hashBuffer.rva]
	 push edx
	 lea edx, ds:[ebx+pwBuffer.rva]
	 push edx
	 lea edx, ds:[ebx+sha256.rva]
	 call edx
	 push 0x20
	 lea edx, ds:[ebx+hashBuffer.rva]
	 push edx
	 lea edx, ds:[ebx+orgHashBuffer.rva]
	 push edx
	 lea edx, ds:[ebx+rtlCompareMemory.rva]
	 call edx
	 cmp eax, 0x20
	 je label_true
	 xor eax, eax
	 mov esp, ebp
	 pop ebp
	 ret
label_true:
	 lea edx, ds:[ebx+pwBuffer.rva]
	 push edx
	 lea edx, ds:[ebx+roundKeyBuffer.rva]
	 push edx
	 lea edx, ds:[ebx+seedKeySched.rva]
	 call edx
	 xor eax, eax
	 inc eax
	 mov esp, ebp
	 pop ebp
	 ret
)";
