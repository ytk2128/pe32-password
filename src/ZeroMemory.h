#pragma once
#include <string>

std::string szZeroMemory = R"(
	push ebp
	mov ebp, esp
	push edi
	push ecx
	mov edi, dword ptr ss:[ebp+0x8]
	mov ecx, dword ptr ss:[ebp+0xC]
label_loop:
	mov byte ptr ds:[edi], 0x0
	inc edi
	loop label_loop
	pop ecx
	pop edi
	mov esp, ebp
	pop ebp
	ret 8
)";
