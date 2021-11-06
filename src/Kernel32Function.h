#pragma once
#include <string>

std::string szKernel32Function = R"(
	 push ebp
	 mov ebp, esp
	 sub esp, 0x10
	 push ecx
	 push edx
	 push ebx
	 push esi
	 push edi
	 xor eax, eax
	 mov dword ptr ss:[ebp-0x4], eax
	 mov eax, dword ptr fs:[0x00000030]
	 mov eax, dword ptr ds:[eax+0xC]
	 mov eax, dword ptr ds:[eax+0xC]
	 mov eax, dword ptr ds:[eax]
	 mov eax, dword ptr ds:[eax]
	 mov eax, dword ptr ds:[eax+0x18]
	 mov ecx, dword ptr ds:[eax+0x3C]
	 add ecx, 0x78
	 mov edx, dword ptr ds:[eax+ecx*1]
	 add edx, eax
	 xor ebx, ebx
	 add edx, 0x20
	 mov ebx, dword ptr ds:[edx]
	 add ebx, eax
	 mov edi, eax
label2:
	 add ebx, 0x4
	 inc dword ptr ss:[ebp-0x4]
	 mov esi, dword ptr ds:[ebx]
	 add esi, edi
	 xor ecx, ecx
	 mov eax, 0xEDB88320
	 mov dword ptr ss:[ebp-0x8], eax
	 mov dword ptr ss:[ebp-0x10], ecx
	 xor eax, eax
label1:
	 lodsb
	 mov ecx, dword ptr ss:[ebp-0x8]
	 shl ecx, 0x1
	 mov dword ptr ss:[ebp-0xC], ecx
	 mov ecx, dword ptr ss:[ebp-0x8]
	 shr ecx, 0x1F
	 or ecx, dword ptr ss:[ebp-0xC]
	 mov dword ptr ss:[ebp-0x8], ecx
	 mov ecx, dword ptr ss:[ebp-0x10]
	 push eax
	 push edx
	 mov eax, dword ptr ss:[ebp-0x8]
	 mul ecx
	 mov ecx, eax
	 pop edx
	 pop eax
	 add ecx, eax
	 mov dword ptr ss:[ebp-0x10], ecx
	 test al, al
jne label1
	 cmp ecx, dword ptr ss:[ebp+0x8]
jne label2
	 xor ebx, ebx
	 add edx, 0x4
	 mov ebx, dword ptr ds:[edx]
	 add ebx, edi
	 xor eax, eax
	 mov al, 0x2
	 mov esi, edx
	 mul word ptr ds:[ebp-0x4]
	 mov dword ptr ss:[ebp-0x4], eax
	 xor eax, eax
	 add ebx, dword ptr ss:[ebp-0x4]
	 mov ax, word ptr ds:[ebx]
	 sub esi, 0x8
	 mov ecx, dword ptr ds:[esi]
	 add ecx, edi
	 xor ebx, ebx
	 mov ebx, eax
	 mov eax, 0x4
	 mul ebx
	 add ecx, eax
	 mov ecx, dword ptr ds:[ecx]
	 add ecx, edi
	 mov eax, ecx
	 pop edi
	 pop esi
	 pop ebx
	 pop edx
	 pop ecx
	 mov esp, ebp
	 pop ebp
	 ret 0x4
)";
