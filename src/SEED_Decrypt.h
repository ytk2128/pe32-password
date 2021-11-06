#pragma once
// SEED_Decrypt
#include <string>

std::string szSEED_Decrypt_A = R"(
	push ebp
	mov ebp, esp
	sub esp, 0x1C
	mov eax, dword ptr ss:[ebp+0xC]
	mov dword ptr ss:[ebp-0x1C], eax
	mov ecx, 0x1
	imul edx, ecx, 0x3
	mov eax, dword ptr ss:[ebp+0x8]
	movzx ecx, byte ptr ds:[eax+edx*1]
	shl ecx, 0x18
	mov edx, 0x1
	shl edx, 0x1
	mov eax, dword ptr ss:[ebp+0x8]
	movzx edx, byte ptr ds:[eax+edx*1]
	shl edx, 0x10
	or ecx, edx
	mov eax, 0x1
	shl eax, 0x0
	mov edx, dword ptr ss:[ebp+0x8]
	movzx eax, byte ptr ds:[edx+eax*1]
	shl eax, 0x8
	or ecx, eax
	mov edx, 0x1
	imul eax, edx, 0x0
	mov edx, dword ptr ss:[ebp+0x8]
	movzx eax, byte ptr ds:[edx+eax*1]
	or ecx, eax
	mov dword ptr ss:[ebp-0x14], ecx
	mov ecx, 0x1
	imul edx, ecx, 0x7
	mov eax, dword ptr ss:[ebp+0x8]
	movzx ecx, byte ptr ds:[eax+edx*1]
	shl ecx, 0x18
	mov edx, 0x1
	imul eax, edx, 0x6
	mov edx, dword ptr ss:[ebp+0x8]
	movzx eax, byte ptr ds:[edx+eax*1]
	shl eax, 0x10
	or ecx, eax
	mov edx, 0x1
	imul eax, edx, 0x5
	mov edx, dword ptr ss:[ebp+0x8]
	movzx eax, byte ptr ds:[edx+eax*1]
	shl eax, 0x8
	or ecx, eax
	mov edx, 0x1
	shl edx, 0x2
	mov eax, dword ptr ss:[ebp+0x8]
	movzx edx, byte ptr ds:[eax+edx*1]
	or ecx, edx
	mov dword ptr ss:[ebp-0x18], ecx
	mov eax, 0x1
	imul ecx, eax, 0xB
	mov edx, dword ptr ss:[ebp+0x8]
	movzx eax, byte ptr ds:[edx+ecx*1]
	shl eax, 0x18
	mov ecx, 0x1
	imul edx, ecx, 0xA
	mov ecx, dword ptr ss:[ebp+0x8]
	movzx edx, byte ptr ds:[ecx+edx*1]
	shl edx, 0x10
	or eax, edx
	mov ecx, 0x1
	imul edx, ecx, 0x9
	mov ecx, dword ptr ss:[ebp+0x8]
	movzx edx, byte ptr ds:[ecx+edx*1]
	shl edx, 0x8
	or eax, edx
	mov ecx, 0x1
	shl ecx, 0x3
	mov edx, dword ptr ss:[ebp+0x8]
	movzx ecx, byte ptr ds:[edx+ecx*1]
	or eax, ecx
	mov dword ptr ss:[ebp-0xC], eax
	mov edx, 0x1
	imul eax, edx, 0xF
	mov ecx, dword ptr ss:[ebp+0x8]
	movzx edx, byte ptr ds:[ecx+eax*1]
	shl edx, 0x18
	mov eax, 0x1
	imul ecx, eax, 0xE
	mov eax, dword ptr ss:[ebp+0x8]
	movzx ecx, byte ptr ds:[eax+ecx*1]
	shl ecx, 0x10
	or edx, ecx
	mov eax, 0x1
	imul ecx, eax, 0xD
	mov eax, dword ptr ss:[ebp+0x8]
	movzx ecx, byte ptr ds:[eax+ecx*1]
	shl ecx, 0x8
	or edx, ecx
	mov eax, 0x1
	imul ecx, eax, 0xC
	mov eax, dword ptr ss:[ebp+0x8]
	movzx ecx, byte ptr ds:[eax+ecx*1]
	or edx, ecx
	mov dword ptr ss:[ebp-0x10], edx
	mov edx, dword ptr ss:[ebp-0x14]
	rol edx, 0x8
	and edx, 0xFF00FF
	mov eax, dword ptr ss:[ebp-0x14]
	rol eax, 0x18
	and eax, 0xFF00FF00
	or edx, eax
	mov dword ptr ss:[ebp-0x14], edx
	mov ecx, dword ptr ss:[ebp-0x18]
	rol ecx, 0x8
	and ecx, 0xFF00FF
	mov edx, dword ptr ss:[ebp-0x18]
	rol edx, 0x18
	and edx, 0xFF00FF00
	or ecx, edx
	mov dword ptr ss:[ebp-0x18], ecx
	mov eax, dword ptr ss:[ebp-0xC]
	rol eax, 0x8
	and eax, 0xFF00FF
	mov ecx, dword ptr ss:[ebp-0xC]
	rol ecx, 0x18
	and ecx, 0xFF00FF00
	or eax, ecx
	mov dword ptr ss:[ebp-0xC], eax
	mov edx, dword ptr ss:[ebp-0x10]
	rol edx, 0x8
	and edx, 0xFF00FF
	mov eax, dword ptr ss:[ebp-0x10]
	rol eax, 0x18
	and eax, 0xFF00FF00
	or edx, eax
	mov dword ptr ss:[ebp-0x10], edx
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0xC]
	xor ecx, dword ptr ds:[eax+edx*1+0x78]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x10]
	xor ecx, dword ptr ds:[eax+edx*1+0x78]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x4]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], ecx
	mov ecx, dword ptr ss:[ebp-0x4]
	add ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, dword ptr ss:[ebp-0x14]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x14], eax
	mov ecx, dword ptr ss:[ebp-0x18]
	xor ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x18], ecx
	mov edx, 0x4
	imul eax, edx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0x14]
	xor edx, dword ptr ds:[ecx+eax*1+0x70]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0x18]
	xor edx, dword ptr ds:[ecx+eax*1+0x70]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x4]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], edx
	mov edx, dword ptr ss:[ebp-0x4]
	add edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, dword ptr ss:[ebp-0xC]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0xC], ecx
	mov edx, dword ptr ss:[ebp-0x10]
	xor edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x10], edx
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0xC]
	xor eax, dword ptr ds:[edx+ecx*1+0x68]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0x10]
	xor eax, dword ptr ds:[edx+ecx*1+0x68]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x4]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], eax
	mov eax, dword ptr ss:[ebp-0x4]
	add eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, dword ptr ss:[ebp-0x14]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x14], edx
	mov eax, dword ptr ss:[ebp-0x18]
	xor eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x18], eax
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x14]
	xor ecx, dword ptr ds:[eax+edx*1+0x60]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x18]
	xor ecx, dword ptr ds:[eax+edx*1+0x60]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x4]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], ecx
	mov ecx, dword ptr ss:[ebp-0x4]
	add ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, dword ptr ss:[ebp-0xC]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0xC], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	xor ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x10], ecx
	mov edx, 0x4
	imul eax, edx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0xC]
	xor edx, dword ptr ds:[ecx+eax*1+0x58]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0x10]
	xor edx, dword ptr ds:[ecx+eax*1+0x58]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x4]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], edx
	mov edx, dword ptr ss:[ebp-0x4]
	add edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, dword ptr ss:[ebp-0x14]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x14], ecx
	mov edx, dword ptr ss:[ebp-0x18]
	xor edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x18], edx
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0x14]
	xor eax, dword ptr ds:[edx+ecx*1+0x50]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0x18]
	xor eax, dword ptr ds:[edx+ecx*1+0x50]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x4]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
)";

std::string szSEED_Decrypt_B = R"(
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], eax
	mov eax, dword ptr ss:[ebp-0x4]
	add eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, dword ptr ss:[ebp-0xC]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0xC], edx
	mov eax, dword ptr ss:[ebp-0x10]
	xor eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x10], eax
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0xC]
	xor ecx, dword ptr ds:[eax+edx*1+0x48]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x10]
	xor ecx, dword ptr ds:[eax+edx*1+0x48]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x4]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], ecx
	mov ecx, dword ptr ss:[ebp-0x4]
	add ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, dword ptr ss:[ebp-0x14]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x14], eax
	mov ecx, dword ptr ss:[ebp-0x18]
	xor ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x18], ecx
	mov edx, 0x4
	imul eax, edx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0x14]
	xor edx, dword ptr ds:[ecx+eax*1+0x40]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0x18]
	xor edx, dword ptr ds:[ecx+eax*1+0x40]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x4]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], edx
	mov edx, dword ptr ss:[ebp-0x4]
	add edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, dword ptr ss:[ebp-0xC]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0xC], ecx
	mov edx, dword ptr ss:[ebp-0x10]
	xor edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x10], edx
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0xC]
	xor eax, dword ptr ds:[edx+ecx*1+0x38]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0x10]
	xor eax, dword ptr ds:[edx+ecx*1+0x38]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x4]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], eax
	mov eax, dword ptr ss:[ebp-0x4]
	add eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, dword ptr ss:[ebp-0x14]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x14], edx
	mov eax, dword ptr ss:[ebp-0x18]
	xor eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x18], eax
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x14]
	xor ecx, dword ptr ds:[eax+edx*1+0x30]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x18]
	xor ecx, dword ptr ds:[eax+edx*1+0x30]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x4]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], ecx
	mov ecx, dword ptr ss:[ebp-0x4]
	add ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, dword ptr ss:[ebp-0xC]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0xC], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	xor ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x10], ecx
	mov edx, 0x4
	imul eax, edx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0xC]
	xor edx, dword ptr ds:[ecx+eax*1+0x28]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0x10]
	xor edx, dword ptr ds:[ecx+eax*1+0x28]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x4]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], edx
	mov edx, dword ptr ss:[ebp-0x4]
	add edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, dword ptr ss:[ebp-0x14]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x14], ecx
	mov edx, dword ptr ss:[ebp-0x18]
	xor edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x18], edx
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0x14]
	xor eax, dword ptr ds:[edx+ecx*1+0x20]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0x18]
	xor eax, dword ptr ds:[edx+ecx*1+0x20]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x4]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], eax
	mov eax, dword ptr ss:[ebp-0x4]
	add eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, dword ptr ss:[ebp-0xC]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0xC], edx
	mov eax, dword ptr ss:[ebp-0x10]
	xor eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x10], eax
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0xC]
	xor ecx, dword ptr ds:[eax+edx*1+0x18]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x10]
	xor ecx, dword ptr ds:[eax+edx*1+0x18]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x4]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], ecx
	mov ecx, dword ptr ss:[ebp-0x4]
	add ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
)";
std::string szSEED_Decrypt_C = R"(
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, dword ptr ss:[ebp-0x14]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x14], eax
	mov ecx, dword ptr ss:[ebp-0x18]
	xor ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x18], ecx
	mov edx, 0x4
	imul eax, edx, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0x14]
	xor edx, dword ptr ds:[ecx+eax*1+0x10]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, 0x4
	shl eax, 0x0
	mov ecx, dword ptr ss:[ebp-0x1C]
	mov edx, dword ptr ss:[ebp-0x18]
	xor edx, dword ptr ds:[ecx+eax*1+0x10]
	mov dword ptr ss:[ebp-0x4], edx
	mov eax, dword ptr ss:[ebp-0x4]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	movzx edx, byte ptr ss:[ebp-0x8]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x8]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], edx
	mov edx, dword ptr ss:[ebp-0x4]
	add edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, dword ptr ss:[ebp-0xC]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0xC], ecx
	mov edx, dword ptr ss:[ebp-0x10]
	xor edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x10], edx
	mov eax, 0x4
	imul ecx, eax, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0xC]
	xor eax, dword ptr ds:[edx+ecx*1+0x8]
	mov dword ptr ss:[ebp-0x8], eax
	mov ecx, 0x4
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp-0x1C]
	mov eax, dword ptr ss:[ebp-0x10]
	xor eax, dword ptr ds:[edx+ecx*1+0x8]
	mov dword ptr ss:[ebp-0x4], eax
	mov ecx, dword ptr ss:[ebp-0x4]
	xor ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	movzx eax, byte ptr ss:[ebp-0x8]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x8]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], eax
	mov eax, dword ptr ss:[ebp-0x4]
	add eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], eax
	movzx ecx, byte ptr ss:[ebp-0x4]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x4]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], ecx
	mov ecx, dword ptr ss:[ebp-0x8]
	add ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, dword ptr ss:[ebp-0x14]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x14], edx
	mov eax, dword ptr ss:[ebp-0x18]
	xor eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x18], eax
	mov ecx, 0x4
	imul edx, ecx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x14]
	xor ecx, dword ptr ds:[eax+edx*1]
	mov dword ptr ss:[ebp-0x8], ecx
	mov edx, 0x4
	shl edx, 0x0
	mov eax, dword ptr ss:[ebp-0x1C]
	mov ecx, dword ptr ss:[ebp-0x18]
	xor ecx, dword ptr ds:[eax+edx*1]
	mov dword ptr ss:[ebp-0x4], ecx
	mov edx, dword ptr ss:[ebp-0x4]
	xor edx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], edx
	movzx eax, byte ptr ss:[ebp-0x4]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x8
	movzx edx, cl
	mov eax, dword ptr ds:[ebx+eax*4+S0.rva]
	xor eax, dword ptr ds:[ebx+edx*4+S1.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x10
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S2.rva]
	mov ecx, dword ptr ss:[ebp-0x4]
	shr ecx, 0x18
	movzx edx, cl
	xor eax, dword ptr ds:[ebx+edx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], eax
	mov eax, dword ptr ss:[ebp-0x8]
	add eax, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], eax
	movzx ecx, byte ptr ss:[ebp-0x8]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x8
	movzx eax, dl
	mov ecx, dword ptr ds:[ebx+ecx*4+S0.rva]
	xor ecx, dword ptr ds:[ebx+eax*4+S1.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x10
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S2.rva]
	mov edx, dword ptr ss:[ebp-0x8]
	shr edx, 0x18
	movzx eax, dl
	xor ecx, dword ptr ds:[ebx+eax*4+S3.rva]
	mov dword ptr ss:[ebp-0x8], ecx
	mov ecx, dword ptr ss:[ebp-0x4]
	add ecx, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0x4], ecx
	movzx edx, byte ptr ss:[ebp-0x4]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x8
	movzx ecx, al
	mov edx, dword ptr ds:[ebx+edx*4+S0.rva]
	xor edx, dword ptr ds:[ebx+ecx*4+S1.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x10
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S2.rva]
	mov eax, dword ptr ss:[ebp-0x4]
	shr eax, 0x18
	movzx ecx, al
	xor edx, dword ptr ds:[ebx+ecx*4+S3.rva]
	mov dword ptr ss:[ebp-0x4], edx
	mov edx, dword ptr ss:[ebp-0x8]
	add edx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x8], edx
	mov eax, dword ptr ss:[ebp-0xC]
	xor eax, dword ptr ss:[ebp-0x8]
	mov dword ptr ss:[ebp-0xC], eax
	mov ecx, dword ptr ss:[ebp-0x10]
	xor ecx, dword ptr ss:[ebp-0x4]
	mov dword ptr ss:[ebp-0x10], ecx
	mov edx, dword ptr ss:[ebp-0x14]
	rol edx, 0x8
	and edx, 0xFF00FF
	mov eax, dword ptr ss:[ebp-0x14]
	rol eax, 0x18
	and eax, 0xFF00FF00
	or edx, eax
	mov dword ptr ss:[ebp-0x14], edx
	mov ecx, dword ptr ss:[ebp-0x18]
	rol ecx, 0x8
	and ecx, 0xFF00FF
	mov edx, dword ptr ss:[ebp-0x18]
	rol edx, 0x18
	and edx, 0xFF00FF00
	or ecx, edx
	mov dword ptr ss:[ebp-0x18], ecx
	mov eax, dword ptr ss:[ebp-0xC]
	rol eax, 0x8
	and eax, 0xFF00FF
	mov ecx, dword ptr ss:[ebp-0xC]
	rol ecx, 0x18
	and ecx, 0xFF00FF00
	or eax, ecx
	mov dword ptr ss:[ebp-0xC], eax
	mov edx, dword ptr ss:[ebp-0x10]
	rol edx, 0x8
	and edx, 0xFF00FF
	mov eax, dword ptr ss:[ebp-0x10]
	rol eax, 0x18
	and eax, 0xFF00FF00
	or edx, eax
	mov dword ptr ss:[ebp-0x10], edx
	mov ecx, dword ptr ss:[ebp-0xC]
	and ecx, 0xFF
	mov edx, 0x1
	imul eax, edx, 0x0
	mov edx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[edx+eax*1], cl
	mov eax, dword ptr ss:[ebp-0xC]
	shr eax, 0x8
	and eax, 0xFF
	mov ecx, 0x1
	shl ecx, 0x0
	mov edx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[edx+ecx*1], al
	mov eax, dword ptr ss:[ebp-0xC]
	shr eax, 0x10
	and eax, 0xFF
	mov ecx, 0x1
	shl ecx, 0x1
	mov edx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[edx+ecx*1], al
	mov eax, dword ptr ss:[ebp-0xC]
	shr eax, 0x18
	and eax, 0xFF
	mov ecx, 0x1
	imul edx, ecx, 0x3
	mov ecx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[ecx+edx*1], al
	mov edx, dword ptr ss:[ebp-0x10]
	and edx, 0xFF
	mov eax, 0x1
	shl eax, 0x2
	mov ecx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[ecx+eax*1], dl
	mov edx, dword ptr ss:[ebp-0x10]
	shr edx, 0x8
	and edx, 0xFF
	mov eax, 0x1
	imul ecx, eax, 0x5
	mov eax, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[eax+ecx*1], dl
	mov ecx, dword ptr ss:[ebp-0x10]
	shr ecx, 0x10
	and ecx, 0xFF
	mov edx, 0x1
	imul eax, edx, 0x6
	mov edx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[edx+eax*1], cl
	mov eax, dword ptr ss:[ebp-0x10]
	shr eax, 0x18
	and eax, 0xFF
	mov ecx, 0x1
	imul edx, ecx, 0x7
	mov ecx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[ecx+edx*1], al
	mov edx, dword ptr ss:[ebp-0x14]
	and edx, 0xFF
	mov eax, 0x1
	shl eax, 0x3
	mov ecx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[ecx+eax*1], dl
	mov edx, dword ptr ss:[ebp-0x14]
	shr edx, 0x8
	and edx, 0xFF
	mov eax, 0x1
	imul ecx, eax, 0x9
	mov eax, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[eax+ecx*1], dl
	mov ecx, dword ptr ss:[ebp-0x14]
	shr ecx, 0x10
	and ecx, 0xFF
	mov edx, 0x1
	imul eax, edx, 0xA
	mov edx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[edx+eax*1], cl
	mov eax, dword ptr ss:[ebp-0x14]
	shr eax, 0x18
	and eax, 0xFF
	mov ecx, 0x1
	imul edx, ecx, 0xB
	mov ecx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[ecx+edx*1], al
	mov edx, dword ptr ss:[ebp-0x18]
	and edx, 0xFF
	mov eax, 0x1
	imul ecx, eax, 0xC
	mov eax, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[eax+ecx*1], dl
	mov ecx, dword ptr ss:[ebp-0x18]
	shr ecx, 0x8
	and ecx, 0xFF
	mov edx, 0x1
	imul eax, edx, 0xD
	mov edx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[edx+eax*1], cl
	mov eax, dword ptr ss:[ebp-0x18]
	shr eax, 0x10
	and eax, 0xFF
	mov ecx, 0x1
	imul edx, ecx, 0xE
	mov ecx, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[ecx+edx*1], al
	mov edx, dword ptr ss:[ebp-0x18]
	shr edx, 0x18
	and edx, 0xFF
	mov eax, 0x1
	imul ecx, eax, 0xF
	mov eax, dword ptr ss:[ebp+0x8]
	mov byte ptr ds:[eax+ecx*1], dl
	mov esp, ebp
	pop ebp
	ret 0x8
)";

std::string szSEED_Decrypt = szSEED_Decrypt_A + szSEED_Decrypt_B + szSEED_Decrypt_C;
