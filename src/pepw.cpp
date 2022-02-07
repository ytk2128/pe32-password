#include "pepw.h"
#include "PE/PEBase.h"
#include "PE/PEResource.h"
#include "PE/PERelocation.h"
#include "PE/Exception.h"
#include "Assembler.h"
#include "Functions.h"

using namespace pe32;

int main(int argc, char** argv) {
	if (argc < 2) {
		cout << "Usage: pepw [file name]\n\n";
		return 1;
	}

	try {
		string input(argv[1]);
		string output(input + "_out.exe");
		string password;

		cout << "PEPW x32 v1.0 by ytk2128\n\n";

	prompt:
		cout << "enter the password: ";
		cin >> password;
		if (password.size() > 16) {
			cout << "the password length must be less than 17\n\n";
			goto prompt;
		}

		BYTE bOrgHash[32];
		if (getSHA256(password, bOrgHash)) {
			throw Exception("main", "failed to generate SHA256 of password");
		}

		PEFile file(input);
		PERelocation reloc(file);

#pragma region Save old property
		auto oldTLSDirectory = *(IMAGE_TLS_DIRECTORY*)(file.data() + file.rvaToRaw(file.TLSDirectory->VirtualAddress));
		auto oldSizeOfImage = *file.SizeOfImage;
		auto oldRelocationDirectory = file.rvaToAddr(file.RelocationDirectory->VirtualAddress);
		auto oldRelocationDirectorySize = file.RelocationDirectory->Size;
		file.RelocationDirectory->VirtualAddress = 0;
		file.RelocationDirectory->Size = 0;
#pragma endregion

		file.createNewSection(".pepw", 0x7000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE);
		file.setPos(file.getLastSection().PointerToRawData);

#pragma region Global Variables
		// Dialog Template
		auto dialogTemplate = file.getPos();
		file.copyMemory(dialogTemplateRawData, sizeof(dialogTemplateRawData));

		// TLS Directory
		auto tlsDirectory = file.getPos();
		if (file.TLSDirectory->VirtualAddress) {
			file.TLSDirectory->VirtualAddress = tlsDirectory.rva;
			file.TLSDirectory->Size = sizeof(IMAGE_TLS_DIRECTORY);
			file.copyMemory(&oldTLSDirectory, sizeof(IMAGE_TLS_DIRECTORY));

			auto size = oldTLSDirectory.EndAddressOfRawData - oldTLSDirectory.StartAddressOfRawData;
			auto pTLSDirectory = (IMAGE_TLS_DIRECTORY*)(file.data() + tlsDirectory.raw);
			pTLSDirectory->AddressOfCallBacks = 0;
			pTLSDirectory->StartAddressOfRawData = file.getPos().va;
			pTLSDirectory->EndAddressOfRawData = pTLSDirectory->StartAddressOfRawData + size;
			file += size + 1;

			if (*file.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
				reloc.push_rva(tlsDirectory.rva);
				reloc.push_data(tlsDirectory.rva);
				reloc.push_data(tlsDirectory.rva + 4);
				reloc.push_data(tlsDirectory.rva + 8);
				reloc.build();
			}
		}

		// Strings
		auto szUser32 = file.getPos();
		file << "user32.dll";
		auto szAdvapi32 = file.getPos();
		file << "advapi32.dll";
		auto szDialogBoxIndirectParamA = file.getPos();
		file << "DialogBoxIndirectParamA";
		auto szGetDlgItemTextA = file.getPos();
		file << "GetDlgItemTextA";
		auto szEndDialog = file.getPos();
		file << "EndDialog";
		auto szCryptAcquireContextA = file.getPos();
		file << "CryptAcquireContextA";
		auto szCryptCreateHash = file.getPos();
		file << "CryptCreateHash";
		auto szCryptDestroyHash = file.getPos();
		file << "CryptDestroyHash";
		auto szCryptReleaseContext = file.getPos();
		file << "CryptReleaseContext";
		auto szCryptGetHashParam = file.getPos();
		file << "CryptGetHashParam";
		auto szCryptHashData = file.getPos();
		file << "CryptHashData";

		// Addresses
		auto baseUser32 = file.getPos(); file += 4;
		auto baseAdvapi32 = file.getPos(); file += 4;
		auto funcDialogBoxIndirectParamA = file.getPos(); file += 4;
		auto funcGetDlgItemTextA = file.getPos(); file += 4;
		auto funcEndDialog = file.getPos(); file += 4;
		auto funcLoadLibraryA = file.getPos(); file += 4;
		auto funcGetProcAddress = file.getPos(); file += 4;
		auto funclstrlenA = file.getPos(); file += 4;
		auto funclstrcmpA = file.getPos(); file += 4;
		auto funcCryptAcquireContextA = file.getPos(); file += 4;
		auto funcCryptCreateHash = file.getPos(); file += 4;
		auto funcCryptDestroyHash = file.getPos(); file += 4;
		auto funcCryptReleaseContext = file.getPos(); file += 4;
		auto funcCryptGetHashParam = file.getPos(); file += 4;
		auto funcCryptHashData = file.getPos(); file += 4;

		// Buffers
		auto dwordBuffer = file.getPos(); file += 4;
		auto orgHashBuffer = file.getPos();                 // hash value of correct password
		file.copyMemory((void*)bOrgHash, sizeof(bOrgHash));

		auto pwBuffer = file.getPos(); file += 256;         // typed password
		auto hashBuffer = file.getPos(); file += 32;        // hash value of typed password
		auto roundKeyBuffer = file.getPos(); file += (4 * 32);    // round key of typed password

		auto sectionAddrBuffer = file.getPos();
#pragma endregion

#pragma region Encrypt sections
		DWORD roundKey[32] = { 0 };
		BYTE userKey[16] = { 0 };
		memcpy(userKey, password.data(), password.size());
		SEED_KeySchedKey(roundKey, userKey);

		for (WORD i = 0; i < *file.NumberOfSections - 1; i++) {
			if (file.pSecHeader[i].VirtualAddress <= file.ResourceDirectory->VirtualAddress
				&& file.pSecHeader[i].VirtualAddress + file.pSecHeader[i].Misc.VirtualSize >= file.ResourceDirectory->VirtualAddress) {
				continue;
			}

			auto secSize = min(file.pSecHeader[i].SizeOfRawData, file.pSecHeader[i].Misc.VirtualSize);
			if (file.pSecHeader[i].PointerToRawData == 0 || secSize == 0) {
				continue;
			}

			encryptData(file.data() + file.pSecHeader[i].PointerToRawData, secSize, roundKey);
			file << (file.pSecHeader[i].VirtualAddress + secSize - 16) << file.pSecHeader[i].VirtualAddress;
		}
#pragma endregion

#pragma region Encrypt specific resource data
		auto resPtr = 0ul;
		auto baseAddr = file.rvaToRaw(file.ResourceDirectory->VirtualAddress);
		auto pResDir = (PIMAGE_RESOURCE_DIRECTORY)(file.data() + baseAddr);
		auto pResEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(file.data() + baseAddr + sizeof(IMAGE_RESOURCE_DIRECTORY));

		for (WORD i = 0; i < pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries; i++) {
			switch (pResEntry[i].Name) {
				case (DWORD)RT_ICON:
				case (DWORD)RT_GROUP_ICON:
				case (DWORD)RT_VERSION:
				case (DWORD)RT_MANIFEST:
					break;

				default:
				{
					resPtr = baseAddr + (pResEntry[i].OffsetToData ^ 0x80000000);

					auto pResDir2 = (PIMAGE_RESOURCE_DIRECTORY)(file.data() + resPtr);
					auto pResEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(file.data() + resPtr + sizeof(IMAGE_RESOURCE_DIRECTORY));

					for (WORD j = 0; j < pResDir2->NumberOfIdEntries + pResDir2->NumberOfNamedEntries; j++) {
						resPtr = baseAddr + (pResEntry2[j].OffsetToData ^ 0x80000000);
						auto pResEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(file.data() + resPtr + sizeof(IMAGE_RESOURCE_DIRECTORY));
						resPtr = baseAddr + pResEntry3->OffsetToData;
						auto pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(file.data() + resPtr);

						if (pResDataEntry->Size >= 16) {
							auto data = file.rvaToAddr(pResDataEntry->OffsetToData);
							encryptData(file.data() + data.raw, pResDataEntry->Size, roundKey);
							file << (data.rva + pResDataEntry->Size - 16) << data.rva;
						}
					}
				}
			}
		}
		file += 4;
#pragma endregion

#pragma region Functions

#pragma region SEED128 S-BOX
		auto S0 = file.getPos();
		file.copyMemory((void*)SS0, sizeof(SS0));
		auto S1 = file.getPos();
		file.copyMemory((void*)SS1, sizeof(SS1));
		auto S2 = file.getPos();
		file.copyMemory((void*)SS2, sizeof(SS2));
		auto S3 = file.getPos();
		file.copyMemory((void*)SS3, sizeof(SS3));
#pragma endregion

		Assembler assembler;

#pragma region SEED_KeySchedKey
		/*
		* push pbUserKey
		* push pdwRoundkey
		* call func
		*/
		assembler.setScript(asmSEED_KeySchedKey)
			.setSymbol("SS0", S0.rva)
			.setSymbol("SS1", S1.rva)
			.setSymbol("SS2", S2.rva)
			.setSymbol("SS3", S3.rva);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build SEED_KeySchedKey");
		}
		auto seedKeySched = file.getPos();
		file << assembler.getVector();
#pragma endregion

#pragma region SEED_Decrypt
		/*
		* push pdwRoundKey
		* push pbData
		* call func
		*/
		assembler.setScript(asmSEED_Decrypt)
			.setSymbol("S0.rva", S0.rva)
			.setSymbol("S1.rva", S1.rva)
			.setSymbol("S2.rva", S2.rva)
			.setSymbol("S3.rva", S3.rva);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build SEED_Decrypt");
		}
		auto seedDecrypt = file.getPos();
		file << assembler.getVector();
#pragma endregion

#pragma region Zero Memory
		/*
		* push size
		* push ptr
		* call func
		*/
		assembler.setScript(asmZeroMemory);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Zero Memory");
		}
		auto zeroMemory = file.getPos();
		file << assembler.getVector();
#pragma endregion

#pragma region SHA256
		/*
		* push output
		* push password
		* call func
		*/
		assembler.setScript(asmSHA256)
			.setSymbol("funcCryptAcquireContextA.rva", funcCryptAcquireContextA.rva)
			.setSymbol("funcCryptCreateHash.rva", funcCryptCreateHash.rva)
			.setSymbol("funcCryptHashData.rva", funcCryptHashData.rva)
			.setSymbol("funcCryptGetHashParam.rva", funcCryptGetHashParam.rva)
			.setSymbol("funcCryptDestroyHash.rva", funcCryptDestroyHash.rva)
			.setSymbol("funcCryptReleaseContext.rva", funcCryptReleaseContext.rva)
			.setSymbol("funclstrlenA.rva", funclstrlenA.rva);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build SHA256");
		}
		auto sha256 = file.getPos();
		file << assembler.getVector();
#pragma endregion

#pragma region RtlCompareMemory
		/*
		* push size
		* push buffer2
		* push buffer1
		* call func
		*/
		assembler.setScript(asmRtlCompareMemory);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build RtlCompareMemory");
		}
		auto rtlCompareMemory = file.getPos();
		file << assembler.getVector();
#pragma endregion

#pragma region Check Password
		assembler.setScript(asmCheckPassword)
			.setSymbol("hashBuffer.rva", hashBuffer.rva)
			.setSymbol("pwBuffer.rva", pwBuffer.rva)
			.setSymbol("sha256.rva", sha256.rva)
			.setSymbol("hashBuffer.rva", hashBuffer.rva)
			.setSymbol("orgHashBuffer.rva", orgHashBuffer.rva)
			.setSymbol("rtlCompareMemory.rva", rtlCompareMemory.rva)
			.setSymbol("pwBuffer.rva", pwBuffer.rva)
			.setSymbol("roundKeyBuffer.rva", roundKeyBuffer.rva)
			.setSymbol("seedKeySched.rva", seedKeySched.rva);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Check Password");
		}
		auto checkPassword = file.getPos();
		file << assembler.getVector();
#pragma endregion

#pragma region Dialog Procedure
		// if the password is correct, the return value of EndDialog will be 0, otherwise 1.
		assembler.setScript(asmDialogProcedure)
			.setSymbol("pwBuffer.rva", pwBuffer.rva)
			.setSymbol("zeroMemory.rva", zeroMemory.rva)
			.setSymbol("funcGetDlgItemTextA.rva", funcGetDlgItemTextA.rva)
			.setSymbol("funclstrlenA.rva", funclstrlenA.rva)
			.setSymbol("checkPassword.rva", checkPassword.rva)
			.setSymbol("funcEndDialog.rva", funcEndDialog.rva);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Dialog Procedure");
		}
		auto dialogProc = file.getPos();
		file << assembler.getVector();
#pragma endregion

#pragma region Kernel32 Parser
		assembler.setScript(asmKernel32Parser);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Kernel32 Parser");
		}
		auto kernel32Parser = file.getPos();
		file << assembler.getVector();
#pragma endregion

#pragma region TLS Callback
		auto tlsCallback = file.getPos();
		if (file.TLSDirectory->VirtualAddress) {
			assembler.setScript(asmTLSCallback)
				.setSymbol("AddressOfCallBacks", oldTLSDirectory.AddressOfCallBacks - *file.ImageBase);
			if (assembler.build() == false) {
				throw Exception("main", "failed to build TLS Callback");
			}
			file << assembler.getVector();
		}
#pragma endregion

#pragma endregion

#pragma region Entry Point
		auto entryPoint = file.getPos();

#pragma region Prologue
		assembler.setScript(R"(
			pushad
			mov ebx, dword ptr fs:[0x00000030]
			mov ebx, dword ptr ds:[ebx+0x8]
			lea ebp, ds:[ebx+kernel32Parser.rva]
			push hVirtualProtect
			call ebp
			lea edx, ds:[ebx+dwordBuffer.rva]
			push edx
			push PAGE_EXECUTE_READWRITE
			push oldSizeOfImage
			push ebx
			call eax
		)")
			.setSymbol("kernel32Parser.rva", kernel32Parser.rva)
			.setSymbol("dwordBuffer.rva", dwordBuffer.rva)
			.setSymbol("PAGE_EXECUTE_READWRITE", PAGE_EXECUTE_READWRITE)
			.setSymbol("oldSizeOfImage", oldSizeOfImage)
			.setSymbol("hVirtualProtect", hashGenerate("VirtualProtect"));
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Prologue");
		}
		file << assembler.getVector();
#pragma endregion

#pragma region Initialize variables
		assembler.setScript(asmInitializeVariables)
			.setSymbol("funcLoadLibraryA.rva", funcLoadLibraryA.rva)
			.setSymbol("szUser32.rva", szUser32.rva)
			.setSymbol("baseUser32.rva", baseUser32.rva)
			.setSymbol("szAdvapi32.rva", szAdvapi32.rva)
			.setSymbol("baseAdvapi32.rva", baseAdvapi32.rva)
			.setSymbol("funcGetProcAddress.rva", funcGetProcAddress.rva)
			.setSymbol("szDialogBoxIndirectParamA.rva", szDialogBoxIndirectParamA.rva)
			.setSymbol("funcDialogBoxIndirectParamA.rva", funcDialogBoxIndirectParamA.rva)
			.setSymbol("szGetDlgItemTextA.rva", szGetDlgItemTextA.rva)
			.setSymbol("funcGetDlgItemTextA.rva", funcGetDlgItemTextA.rva)
			.setSymbol("szEndDialog.rva", szEndDialog.rva)
			.setSymbol("funcEndDialog.rva", funcEndDialog.rva)
			.setSymbol("funclstrlenA.rva", funclstrlenA.rva)
			.setSymbol("funclstrcmpA.rva", funclstrcmpA.rva)
			.setSymbol("szCryptAcquireContextA.rva", szCryptAcquireContextA.rva)
			.setSymbol("funcCryptAcquireContextA.rva", funcCryptAcquireContextA.rva)
			.setSymbol("szCryptCreateHash.rva", szCryptCreateHash.rva)
			.setSymbol("funcCryptCreateHash.rva", funcCryptCreateHash.rva)
			.setSymbol("szCryptDestroyHash.rva", szCryptDestroyHash.rva)
			.setSymbol("funcCryptDestroyHash.rva", funcCryptDestroyHash.rva)
			.setSymbol("szCryptReleaseContext.rva", szCryptReleaseContext.rva)
			.setSymbol("funcCryptReleaseContext.rva", funcCryptReleaseContext.rva)
			.setSymbol("szCryptGetHashParam.rva", szCryptGetHashParam.rva)
			.setSymbol("funcCryptGetHashParam.rva", funcCryptGetHashParam.rva)
			.setSymbol("szCryptHashData.rva", szCryptHashData.rva)
			.setSymbol("funcCryptHashData.rva", funcCryptHashData.rva)
			.setSymbol("hLoadLibraryA", hashGenerate("LoadLibraryA"))
			.setSymbol("hGetProcAddress", hashGenerate("GetProcAddress"))
			.setSymbol("hlstrlenA", hashGenerate("lstrlenA"))
			.setSymbol("hlstrcmpA", hashGenerate("lstrcmpA"));
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Initialize variables");
		}
		file << assembler.getVector();
#pragma endregion

#pragma region Show password dialog
		// Show dialog
		assembler.setScript(R"(
			push 0x0
			lea edx, ds:[ebx+dialogProc.rva]
			push edx
			push 0x0
			lea edx, ds:[ebx+dialogTemplate.rva]
			push edx
			push ebx
			call dword ptr ds:[ebx+funcDialogBoxIndirectParamA.rva]
		)")
			.setSymbol("dialogProc.rva", dialogProc.rva)
			.setSymbol("dialogTemplate.rva", dialogTemplate.rva)
			.setSymbol("funcDialogBoxIndirectParamA.rva", funcDialogBoxIndirectParamA.rva);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Show password dialog");
		}
		file << assembler.getVector();
#pragma endregion

#pragma region Decrypt sections
		// check eax. if eax is 1, dialog was closed by the user so exit process.
		// if eax is 0, the password is correct so decrypt binary using generated round key.

		assembler.setScript(R"(
			test eax, eax
			je label_decrypt
			push hExitProcess
			call ebp
			push 0x0
			call eax
			label_decrypt:
			lea ecx, ds:[ebx+sectionAddrBuffer.rva]
		loop:
			mov esi, dword ptr ds:[ecx]
			test esi, esi
			je end
			mov edi, dword ptr ds:[ecx+0x4]
			add esi, ebx
			add edi, ebx
		loop2:
			cmp esi, edi
			jl next
			push ecx
			lea edx, ds:[ebx+roundKeyBuffer.rva]
			push edx
			push esi
			lea edx, ds:[ebx+seedDecrypt.rva]
			call edx
			pop ecx
			dec esi
			jmp loop2
		next:
			add ecx, 0x8
			jmp loop
		end:
		)")
			.setSymbol("hExitProcess", hashGenerate("ExitProcess"))
			.setSymbol("sectionAddrBuffer.rva", sectionAddrBuffer.rva)
			.setSymbol("roundKeyBuffer.rva", roundKeyBuffer.rva)
			.setSymbol("seedDecrypt.rva", seedDecrypt.rva);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Decrypt sections");
		}
		file << assembler.getVector();
#pragma endregion

#pragma region Recover PE Header
		// Recover import directory
		if (file.ImportDirectory->VirtualAddress) {
			assembler.setScript(R"(
				lea esi, ds:[ebx+ImportDirectoryRVA]
			loop1:
				mov eax, dword ptr ds:[esi+0xC]
				test eax, eax
				je end
				add eax, ebx
				push eax
				call dword ptr ds:[ebx+funcLoadLibraryA.rva]
				mov edi, eax
				mov ecx, dword ptr ds:[esi+0x10]
				add ecx, ebx
			loop2:
				mov edx, dword ptr ds:[ecx]
				test edx, edx
				je next
				mov eax, edx
				test eax, 0x80000000
				jne ordinal
				add edx, ebx
				add edx, 0x2
				jmp get_addr
			ordinal:
				xor edx, 0x80000000
			get_addr:
				push ecx
				push edx
				push edi
				call dword ptr ds:[ebx+funcGetProcAddress.rva]
				pop ecx
				mov dword ptr ds:[ecx], eax
				add ecx, 0x4
				jmp loop2
			next:
				add esi, 0x14
				jmp loop1
			end:
				mov dword ptr ds:[ebx+ImportDirectoryRVA.Offset], ImportDirectoryRVA
				mov dword ptr ds:[ebx+ImportDirectorySize.Offset], ImportDirectorySize
			)")
				.setSymbol("funcLoadLibraryA.rva", funcLoadLibraryA.rva)
				.setSymbol("funcGetProcAddress.rva", funcGetProcAddress.rva)
				.setSymbol("ImportDirectoryRVA.Offset", (DWORD)((BYTE*)file.ImportDirectory - file.data()))
				.setSymbol("ImportDirectorySize.Offset", (DWORD)((BYTE*)file.ImportDirectory - file.data()) + 4)
				.setSymbol("ImportDirectorySize", file.ImportDirectory->Size)
				.setSymbol("ImportDirectoryRVA", file.ImportDirectory->VirtualAddress);
			if (assembler.build() == false) {
				throw Exception("main", "failed to build Recover import directory");
			}
			file << assembler.getVector();
		}

		// Recover relocation directory
		if (*file.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE && oldRelocationDirectory.rva) {
			assembler.setScript(R"(
				mov edi, ImageBase
				lea esi, ds:[ebx+oldRelocationDirectory.rva]
			loop1:
				 mov edx, dword ptr ds:[esi]
				 test edx, edx
				 je end
				 mov ecx, dword ptr ds:[esi+0x4]
				 sub ecx, 0x8
				 add esi, 0x8
			loop2:
				test ecx, ecx
				je loop1
				xor eax, eax
				mov ax, word ptr ds:[esi]
				test ax, ax
				je next
				and ax, 0xFFF
				add eax, edx
				add eax, ebx
				sub dword ptr ds:[eax], edi
				add dword ptr ds:[eax], ebx
			next:
				add esi, 0x2
				sub ecx, 0x2
				jmp loop2
			end:
			)")
				.setSymbol("ImageBase", *file.ImageBase)
				.setSymbol("oldRelocationDirectory.rva", oldRelocationDirectory.rva);
			if (assembler.build() == false) {
				throw Exception("main", "failed to build Recover relocation directory");
			}
			file << assembler.getVector();
		}

		// Call TLS callbacks
		if (file.TLSDirectory->VirtualAddress) {
			assembler.setScript(R"(
				push 0
				push 1
				push ebx
				lea edx, ds:[ebx+tlsCallback.rva]
				call edx
			)")
				.setSymbol("tlsCallback.rva", tlsCallback.rva);
			if (assembler.build() == false) {
				throw Exception("main", "failed to build Call TLS callbacks");
			}
			file << assembler.getVector();
		}
#pragma endregion

#pragma region Epilogue
		assembler.setScript(R"(
			lea edx, ds:[ebx+OEP.rva]
			mov dword ptr ss:[esp+0x1C], edx
			popad
			jmp dword ptr ss:[esp-0x4]
		)")
			.setSymbol("OEP.rva", *file.AddressOfEntryPoint);
		if (assembler.build() == false) {
			throw Exception("main", "failed to build Epilogue");
		}
		file << assembler.getVector();
#pragma endregion

#pragma endregion

#pragma region Configure PE Header and Save as executable file
		file.ExportDirectory->VirtualAddress = 0;
		file.ExportDirectory->Size = 0;
		file.ImportDirectory->VirtualAddress = 0;
		file.ImportDirectory->Size = 0;
		file.ImportAddressTableDirectory->VirtualAddress = 0;
		file.ImportAddressTableDirectory->Size = 0;
		file.DelayImportDirectory->VirtualAddress = 0;
		file.DelayImportDirectory->Size = 0;
		file.SecurityDirectory->VirtualAddress = 0;
		file.SecurityDirectory->Size = 0;
		file.DebugDirectory->VirtualAddress = 0;
		file.DebugDirectory->Size = 0;
		file.ConfigurationDirectory->VirtualAddress = 0;
		file.ConfigurationDirectory->Size = 0;

		*file.AddressOfEntryPoint = entryPoint.rva;
		file.save(output);
#pragma endregion

		cout << "the file is successfully encrypted.\n\n";
	}
	catch (Exception& ex) {
		cerr << ex.get() << "\n";
		return 1;
	}

	return 0;
}