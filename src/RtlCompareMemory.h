#pragma once
#include <string>

std::string szRtlCompareMemory = R"(
	 push esi
	 push edi
	 cld
	 mov esi, dword ptr ss:[esp+0xC]
	 mov edi, dword ptr ss:[esp+0x10]
	 mov ecx, dword ptr ss:[esp+0x14]
	 shr ecx, 0x2
je label1
	 repe cmpsd
jne label3
label1:
	 mov ecx, dword ptr ss:[esp+0x14]
	 and ecx, 0x3
je label2
	 repe cmpsb
jne label4
label2:
	 mov eax, dword ptr ss:[esp+0x14]
	 pop edi
	 pop esi
	 ret 0xC
label3:
	 sub esi, 0x4
	 sub edi, 0x4
	 mov ecx, 0x4
	 repe cmpsb
label4:
	 dec esi
	 sub esi, dword ptr ss:[esp+0xC]
	 mov eax, esi
	 pop edi
	 pop esi
	 ret 0xC
)";
