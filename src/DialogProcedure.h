#pragma once
#include <string>

std::string szDialogProcedure = R"(
	 push ebp
	 mov ebp, esp
	 mov ebx, dword ptr fs:[0x00000030]
	 mov ebx, dword ptr ds:[ebx+0x8]
	 cmp dword ptr ss:[ebp+0xC], 0x111
	 jne label_else
	 mov eax, dword ptr ss:[ebp+0x10]
	 and eax, 0xFFFF
	 movzx ecx, ax
	 cmp ecx, 0x3E9
	 jne label_retn
	 mov edx, dword ptr ss:[ebp+0x10]
	 shr edx, 0x10
	 and edx, 0xFFFF
	 movzx eax, dx
	 cmp eax, 0x300
	 jne label_retn
	 push 0x10
	 lea edx, ds:[ebx+pwBuffer.rva]
	 push edx
	 lea edx, ds:[ebx+zeroMemory.rva]
	 call edx
	 push 0x100
	 lea edx, ds:[ebx+pwBuffer.rva]
	 push edx
	 push 0x3E9
	 mov ecx, dword ptr ss:[ebp+0x8]
	 push ecx
	 call dword ptr ds:[ebx+funcGetDlgItemTextA.rva]
	 lea edx, ds:[ebx+pwBuffer.rva]
	 push edx
	 call dword ptr ds:[ebx+funclstrlenA.rva]
	 cmp eax, 0x10
	 jg label_retn
	 lea edx, ds:[ebx+checkPassword.rva]
	 call edx
	 test eax, eax
	 je label_retn
	 push 0x0
	 mov edx, dword ptr ss:[ebp+0x8]
	 push edx
	 call dword ptr ds:[ebx+funcEndDialog.rva]
label_retn:
	 jmp label_exit
label_else:
	 cmp dword ptr ss:[ebp+0xC], 0x10
	 jne label_exit
	 push 0x1
	 mov eax, dword ptr ss:[ebp+0x8]
	 push eax
	 call dword ptr ds:[ebx+funcEndDialog.rva]
label_exit:
	 xor eax, eax
	 pop ebp
	 ret 0x10
)";
