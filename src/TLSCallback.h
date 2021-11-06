#pragma once
#include <string>

std::string szTLSCallback = R"(
	 push esi
	 lea esi, ds:[ebx+AddressOfCallBacks.RVA]
	 cld
	 label_get:
	 lodsd
	 test eax, eax
je exit
	 push 0x3
	 pop ecx
	 label_loop:
	 push dword ptr ss:[esp+0x10]
	 loop label_loop
	 call eax
	 jmp label_get
exit:
	 pop esi
	 ret 0xC
)";

