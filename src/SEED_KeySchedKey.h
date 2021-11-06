#pragma once
#include <string>

std::string szSEED_KeySchedKey_A = R"(
	push ebp
	mov ebp, esp
	sub esp, 0x1C
	mov eax, dword ptr ss:[ebp+0x8]
	mov dword ptr ss:[ebp-0x1C], eax
	mov ecx, 0x1
	imul edx, ecx, 0x3
	mov eax, dword ptr ss:[ebp+0xC]
	movzx ecx, byte ptr ds:[eax+edx*1]
	shl ecx, 0x18
	mov edx, 0x1
	shl edx, 0x1
	mov eax, dword ptr ss:[ebp+0xC]
	movzx edx, byte ptr ds:[eax+edx*1]
	shl edx, 0x10
	or ecx, edx
	mov eax, 0x1
	shl eax, 0x0
	mov edx, dword ptr ss:[ebp+0xC]
	movzx eax, byte ptr ds:[edx+eax*1]
	shl eax, 0x8
	or ecx, eax
	mov edx, 0x1
	imul eax, edx, 0x0
	mov edx, dword ptr ss:[ebp+0xC]
	movzx eax, byte ptr ds:[edx+eax*1]
	or ecx, eax
	mov dword ptr ss:[ebp-0xC], ecx
	mov ecx, 0x1
	imul edx, ecx, 0x7
	mov eax, dword ptr ss:[ebp+0xC]
	movzx ecx, byte ptr ds:[eax+edx*1]
	shl ecx, 0x18
	mov edx, 0x1
	imul eax, edx, 0x6
	mov edx, dword ptr ss:[ebp+0xC]
	movzx eax, byte ptr ds:[edx+eax*1]
	shl eax, 0x10
	or ecx, eax
	mov edx, 0x1
	imul eax, edx, 0x5
	mov edx, dword ptr ss:[ebp+0xC]
	movzx eax, byte ptr ds:[edx+eax*1]
	shl eax, 0x8
	or ecx, eax
	mov edx, 0x1
	shl edx, 0x2
	mov eax, dword ptr ss:[ebp+0xC]
	movzx edx, byte ptr ds:[eax+edx*1]
	or ecx, edx
	mov dword ptr ss:[ebp-0x10], ecx
	mov eax, 0x1
	imul ecx, eax, 0xB
	mov edx, dword ptr ss:[ebp+0xC]
	movzx eax, byte ptr ds:[edx+ecx*1]
	shl eax, 0x18
	mov ecx, 0x1
	imul edx, ecx, 0xA
	mov ecx, dword ptr ss:[ebp+0xC]
	movzx edx, byte ptr ds:[ecx+edx*1]
	shl edx, 0x10
	or eax, edx
	mov ecx, 0x1
	imul edx, ecx, 0x9
	mov ecx, dword ptr ss:[ebp+0xC]
	movzx edx, byte ptr ds:[ecx+edx*1]
	shl edx, 0x8
	or eax, edx
	mov ecx, 0x1
	shl ecx, 0x3
	mov edx, dword ptr ss:[ebp+0xC]
	movzx ecx, byte ptr ds:[edx+ecx*1]
	or eax, ecx
	mov dword ptr ss:[ebp-0x14], eax
	mov edx, 0x1
	imul eax, edx, 0xF
	mov ecx, dword ptr ss:[ebp+0xC]
	movzx edx, byte ptr ds:[ecx+eax*1]
	shl edx, 0x18
	mov eax, 0x1
	imul ecx, eax, 0xE
	mov eax, dword ptr ss:[ebp+0xC]
	movzx ecx, byte ptr ds:[eax+ecx*1]
	shl ecx, 0x10
	or edx, ecx
	mov eax, 0x1
	imul ecx, eax, 0xD
	mov eax, dword ptr ss:[ebp+0xC]
	movzx ecx, byte ptr ds:[eax+ecx*1]
	shl ecx, 0x8
	or edx, ecx
	mov eax, 0x1
	imul ecx, eax, 0xC
	mov eax, dword ptr ss:[ebp+0xC]
	movzx ecx, byte ptr ds:[eax+ecx*1]
	or edx, ecx
	mov dword ptr ss:[ebp-0x18], edx
	mov edx, dword ptr ss:[ebp-0xC]
	rol edx, 0x8
	and edx, 0xFF00FF
	mov eax, dword ptr ss:[ebp-0xC]
	rol eax, 0x18
	and eax, 0xFF00FF00
	or edx, eax
	mov dword ptr ss:[ebp-0xC], edx
	mov ecx, dword ptr ss:[ebp-0x10]
	rol ecx, 0x8
	and ecx, 0xFF00FF
	mov edx, dword ptr ss:[ebp-0x10]
	rol edx, 0x18
	and edx, 0xFF00FF00
	or ecx, edx
	mov dword ptr ss:[ebp-0x10], ecx
	mov eax, dword ptr ss:[ebp-0x14]
	rol eax, 0x8
	and eax, 0xFF00FF
	mov ecx, dword ptr ss:[ebp-0x14]
	rol ecx, 0x18
	and ecx, 0xFF00FF00
	or eax, ecx
	mov dword ptr ss:[ebp-0x14], eax
	mov edx, dword ptr ss:[ebp-0x18]
	rol edx, 0x8
	and edx, 0xFF00FF
	mov eax, dword ptr ss:[ebp-0x18]
	rol eax, 0x18
	and eax, 0xFF00FF00
	or edx, eax
	mov dword ptr ss:[ebp-0x18], edx
	mov ecx, dword ptr ss:[ebp-0x14]
	mov edx, dword ptr ss:[ebp-0xC]
	lea eax, ds:[edx+ecx*1+0x61C88647]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	sub ecx, 0x61C88647
	sub ecx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+ecx*1], edx
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+edx*1], ecx
	mov ecx, dword ptr ss:[ebp-0xC]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0xC]
	shr edx, 0x8
	mov eax, dword ptr ss:[ebp-0x10]
	shl eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0xC], edx
	mov ecx, dword ptr ss:[ebp-0x10]
	shr ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x4]
	shl edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0x10], ecx
	mov eax, dword ptr ss:[ebp-0x14]
	mov ecx, dword ptr ss:[ebp-0xC]
	lea edx, ds:[ecx+eax*1-0x3C6EF373]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x10]
	add eax, 0x3C6EF373
	sub eax, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	imul eax, edx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+eax*1+0x8], ecx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+ecx*1+0x8], eax
	mov eax, dword ptr ss:[ebp-0x14]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x14]
	shl ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x18]
	shr edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0x14], ecx
	mov eax, dword ptr ss:[ebp-0x18]
	shl eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0x18], eax
	mov edx, dword ptr ss:[ebp-0x14]
	mov eax, dword ptr ss:[ebp-0xC]
	lea ecx, ds:[eax+edx*1-0x78DDE6E6]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x10]
	add edx, 0x78DDE6E6
	sub edx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+edx*1+0x10], eax
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+eax*1+0x10], edx
	mov edx, dword ptr ss:[ebp-0xC]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0xC]
	shr eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x10]
	shl ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0xC], eax
	mov edx, dword ptr ss:[ebp-0x10]
	shr edx, 0x8
	mov eax, dword ptr ss:[ebp-0x4]
	shl eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0x10], edx
	mov ecx, dword ptr ss:[ebp-0x14]
	mov edx, dword ptr ss:[ebp-0xC]
	lea eax, ds:[edx+ecx*1+0xE443234]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	sub ecx, 0xE443234
	sub ecx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x4]
)";
std::string szSEED_KeySchedKey_B = R"(
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+ecx*1+0x18], edx
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+edx*1+0x18], ecx
	mov ecx, dword ptr ss:[ebp-0x14]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x14]
	shl edx, 0x8
	mov eax, dword ptr ss:[ebp-0x18]
	shr eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0x14], edx
	mov ecx, dword ptr ss:[ebp-0x18]
	shl ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0x18], ecx
	mov eax, dword ptr ss:[ebp-0x14]
	mov ecx, dword ptr ss:[ebp-0xC]
	lea edx, ds:[ecx+eax*1+0x1C886467]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x10]
	sub eax, 0x1C886467
	sub eax, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	imul eax, edx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+eax*1+0x20], ecx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+ecx*1+0x20], eax
	mov eax, dword ptr ss:[ebp-0xC]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0xC]
	shr ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x10]
	shl edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0xC], ecx
	mov eax, dword ptr ss:[ebp-0x10]
	shr eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x4]
	shl ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0x10], eax
	mov edx, dword ptr ss:[ebp-0x14]
	mov eax, dword ptr ss:[ebp-0xC]
	lea ecx, ds:[eax+edx*1+0x3910C8CD]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x10]
	sub edx, 0x3910C8CD
	sub edx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+edx*1+0x28], eax
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+eax*1+0x28], edx
	mov edx, dword ptr ss:[ebp-0x14]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x14]
	shl eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x18]
	shr ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0x14], eax
	mov edx, dword ptr ss:[ebp-0x18]
	shl edx, 0x8
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0x18], edx
	mov ecx, dword ptr ss:[ebp-0x14]
	mov edx, dword ptr ss:[ebp-0xC]
	lea eax, ds:[edx+ecx*1+0x72219199]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	sub ecx, 0x72219199
	sub ecx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+ecx*1+0x30], edx
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+edx*1+0x30], ecx
	mov ecx, dword ptr ss:[ebp-0xC]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0xC]
	shr edx, 0x8
	mov eax, dword ptr ss:[ebp-0x10]
	shl eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0xC], edx
	mov ecx, dword ptr ss:[ebp-0x10]
	shr ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x4]
	shl edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0x10], ecx
	mov eax, dword ptr ss:[ebp-0x14]
	mov ecx, dword ptr ss:[ebp-0xC]
	lea edx, ds:[ecx+eax*1-0x1BBCDCCF]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x10]
	add eax, 0x1BBCDCCF
	sub eax, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	imul eax, edx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+eax*1+0x38], ecx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+ecx*1+0x38], eax
	mov eax, dword ptr ss:[ebp-0x14]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x14]
	shl ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x18]
	shr edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0x14], ecx
	mov eax, dword ptr ss:[ebp-0x18]
	shl eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0x18], eax
	mov edx, dword ptr ss:[ebp-0x14]
	mov eax, dword ptr ss:[ebp-0xC]
	lea ecx, ds:[eax+edx*1-0x3779B99E]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x10]
	add edx, 0x3779B99E
	sub edx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+edx*1+0x40], eax
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+eax*1+0x40], edx
	mov edx, dword ptr ss:[ebp-0xC]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0xC]
	shr eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x10]
	shl ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0xC], eax
	mov edx, dword ptr ss:[ebp-0x10]
	shr edx, 0x8
	mov eax, dword ptr ss:[ebp-0x4]
	shl eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0x10], edx
	mov ecx, dword ptr ss:[ebp-0x14]
	mov edx, dword ptr ss:[ebp-0xC]
	lea eax, ds:[edx+ecx*1-0x6EF3733C]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	add ecx, 0x6EF3733C
	sub ecx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+ecx*1+0x48], edx
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+edx*1+0x48], ecx
	mov ecx, dword ptr ss:[ebp-0x14]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x14]
	shl edx, 0x8
	mov eax, dword ptr ss:[ebp-0x18]
	shr eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0x14], edx
	mov ecx, dword ptr ss:[ebp-0x18]
	shl ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0x18], ecx
	mov eax, dword ptr ss:[ebp-0x14]
	mov ecx, dword ptr ss:[ebp-0xC]
	lea edx, ds:[ecx+eax*1+0x22191988]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x10]
	sub eax, 0x22191988
	sub eax, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	imul eax, edx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+eax*1+0x50], ecx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+ecx*1+0x50], eax
	mov eax, dword ptr ss:[ebp-0xC]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0xC]
	shr ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x10]
	shl edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0xC], ecx
	mov eax, dword ptr ss:[ebp-0x10]
	shr eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x4]
	shl ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0x10], eax
	mov edx, dword ptr ss:[ebp-0x14]
	mov eax, dword ptr ss:[ebp-0xC]
	lea ecx, ds:[eax+edx*1+0x4432330F]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x10]
	sub edx, 0x4432330F
	sub edx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+edx*1+0x58], eax
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+eax*1+0x58], edx
	mov edx, dword ptr ss:[ebp-0x14]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x14]
	shl eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x18]
	shr ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0x14], eax
	mov edx, dword ptr ss:[ebp-0x18]
	shl edx, 0x8
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0x18], edx
	mov ecx, dword ptr ss:[ebp-0x14]
	mov edx, dword ptr ss:[ebp-0xC]
	lea eax, ds:[edx+ecx*1-0x779B99E3]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	add ecx, 0x779B99E3
	sub ecx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+ecx*1+0x60], edx
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+edx*1+0x60], ecx
	mov ecx, dword ptr ss:[ebp-0xC]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0xC]
	shr edx, 0x8
	mov eax, dword ptr ss:[ebp-0x10]
	shl eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0xC], edx
	mov ecx, dword ptr ss:[ebp-0x10]
	shr ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x4]
	shl edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0x10], ecx
	mov eax, dword ptr ss:[ebp-0x14]
	mov ecx, dword ptr ss:[ebp-0xC]
	lea edx, ds:[ecx+eax*1+0x10C8CC3A]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x10]
	sub eax, 0x10C8CC3A
	sub eax, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	imul eax, edx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+eax*1+0x68], ecx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
)";
std::string szSEED_KeySchedKey_C = R"(
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+ecx*1+0x68], eax
	mov eax, dword ptr ss:[ebp-0x14]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x14]
	shl ecx, 0x8
	mov edx, dword ptr ss:[ebp-0x18]
	shr edx, 0x18
	xor ecx, edx
	mov dword ptr ss:[ebp-0x14], ecx
	mov eax, dword ptr ss:[ebp-0x18]
	shl eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0x18], eax
	mov edx, dword ptr ss:[ebp-0x14]
	mov eax, dword ptr ss:[ebp-0xC]
	lea ecx, ds:[eax+edx*1+0x21919873]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x10]
	sub edx, 0x21919873
	sub edx, dword ptr ss:[ebp-0x18]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+SS0]
	xor eax, dword ptr ds:[ebx+edx*4+SS1]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS2]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+SS3]
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+edx*1+0x70], eax
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[ecx+eax*1+0x70], edx
	mov edx, dword ptr ss:[ebp-0xC]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0xC]
	shr eax, 0x8
	mov ecx, dword ptr ss:[ebp-0x10]
	shl ecx, 0x18
	xor eax, ecx
	mov dword ptr ss:[ebp-0xC], eax
	mov edx, dword ptr ss:[ebp-0x10]
	shr edx, 0x8
	mov eax, dword ptr ss:[ebp-0x4]
	shl eax, 0x18
	xor edx, eax
	mov dword ptr ss:[ebp-0x10], edx
	mov ecx, dword ptr ss:[ebp-0x14]
	mov edx, dword ptr ss:[ebp-0xC]
	lea eax, ds:[edx+ecx*1+0x432330E5]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	sub ecx, dword ptr ss:[ebp-0x18]
	sub ecx, 0x432330E5
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+SS0]
	xor edx, dword ptr ds:[ebx+ecx*4+SS1]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS2]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+SS3]
	mov eax, 0x4
	imul ecx, eax, 0x1E
	mov eax, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[eax+ecx*1], edx
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
	xor ecx, dword ptr ds:[ebx+eax*4+SS1]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS2]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+SS3]
	mov edx, 0x4
	imul eax, edx, 0x1F
	mov edx, dword ptr ss:[ebp-0x1C]
	mov dword ptr ds:[edx+eax*1], ecx
	mov esp, ebp
	pop ebp
	ret 0x8
)";

std::string szSEED_KeySchedKey = szSEED_KeySchedKey_A + szSEED_KeySchedKey_B + szSEED_KeySchedKey_C;
