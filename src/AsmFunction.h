#pragma once
/*
	CheckPassword

*/


typedef std::string func;
#include <string>

#pragma region CheckPassword
func asmCheckPassword = R"(
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
#pragma endregion

#pragma region DialogProcedure

func asmDialogProcedure = R"(
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

#pragma endregion

#pragma region InitializeVariables
func asmInitializeVariables = R"(

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

	; Get DialogBoxIndirectParamA
	lea edx, ds:[ebx+szDialogBoxIndirectParamA.rva]
	push edx
	push dword ptr ds:[ebx+baseUser32.rva]
	call dword ptr ds:[ebx+funcGetProcAddress.rva]
	mov dword ptr ds:[ebx+funcDialogBoxIndirectParamA.rva], eax

	; Get GetDlgItemTextA
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

#pragma endregion

#pragma region Kernel32Function
func asmKernel32Function = R"(
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

#pragma endregion

#pragma region RtlCompareMemory

func asmRtlCompareMemory = R"(
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

#pragma endregion

#pragma region SEED_Decrypt

func asmSEED_Decrypt = R"(
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
	)"

	R"(
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
	)"
	R"(
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


#pragma endregion

#pragma region SEED_KeySchedKey
std::string asmSEED_KeySchedKey = R"(
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
)"
R"(
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
)"
R"(
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
#pragma endregion

#pragma region SHA256
func asmSHA256 = R"(
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

#pragma endregion

#pragma region TLSCallback
std::string asmTLSCallback = R"(
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

#pragma endregion

#pragma region ZeroMemory
func asmZeroMemory = R"(
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
#pragma endregion

