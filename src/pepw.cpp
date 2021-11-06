#include "pepw.h"
#include "PE/PEBase.h"
#include "PE/PEResource.h"
#include "PE/PERelocation.h"
#include "PE/Exception.h"

#include "Assembler1.h"
#include "SEED_KeySchedKey.h"
#include "SEED_Decrypt.h"
#include "ZeroMemory.h"
#include "SHA256.h"
#include "RtlCompareMemory.h"
#include "CheckPassword.h"
#include "DialogProcedure.h"
#include "Kernel32Function.h"
#include "TLSCallback.h"
#include "InitializeVariables.h"

int main(int argc, char** argv) {

	if (argc < 2) {
		std::cout << "Usage: pepw [file name]\n\n";
		return 1;
	}

	try {
		std::string input(argv[1]);
		std::string output(input + "_out.exe");
		std::string password;

		std::cout << "PEPW x32 v1.0 by ytk2128\n\n";

	prompt:
		std::cout << "enter the password: ";
		std::cin >> password;
		if (password.size() > 16) {
			std::cout << "the password length must be less than 17\n\n";
			goto prompt;
		}

		BYTE bOrgHash[32];
		if (getSHA256(password, bOrgHash)) {
			throw pe32::Exception("main", "failed to generate SHA256 of password");
		}

		pe32::PEFile file(input);
		pe32::PERelocation reloc(file);

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

			default: {
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


#pragma region SEED_KeySchedKey
		/*
		* push pbUserKey
		* push pdwRoundkey
		* call func
		*/
		auto seedKeySched = file.getPos();

		Assembler1 SEED_KeySchedKey(szSEED_KeySchedKey);
		SEED_KeySchedKey
			.setSymbol("SS0", S0.rva)
			.setSymbol("SS1", S1.rva)
			.setSymbol("SS2", S2.rva)
			.setSymbol("SS3", S3.rva)
			.build();

		if (SEED_KeySchedKey.error()) {
			std::cerr << "SEED_KeySchedKey Error\n\n";
			return 1;
		}

		file << SEED_KeySchedKey.getVector();
#pragma endregion

#pragma region SEED_Decrypt
		/*
		* push pdwRoundKey
		* push pbData
		* call func
		*/
		auto seedDecrypt = file.getPos();

		Assembler1 SEED_Decrypt(szSEED_Decrypt);
		SEED_Decrypt
			.setSymbol("S0.rva", S0.rva)
			.setSymbol("S1.rva", S1.rva)
			.setSymbol("S2.rva", S2.rva)
			.setSymbol("S3.rva", S3.rva)
			.build();

		if (SEED_Decrypt.error()) {
			std::cerr << "SEED_Decrypt Error\n\n";
			return 1;
		}

		file << SEED_Decrypt.getVector();
#pragma endregion


#pragma region Zero Memory

		/*
		* push size
		* push ptr
		* call func
		*/

		auto zeroMemory = file.getPos();

		Assembler1 vZeroMemory(szZeroMemory);
		vZeroMemory.build();
		if (vZeroMemory.error()) {
			std::cerr << "ZeroMemory Error\n\n";
			return 1;
		}

		file << vZeroMemory.getVector();
#pragma endregion

#pragma region SHA256
		auto sha256 = file.getPos();
		/*
		* push output
		* push password
		* call func
		*/

		Assembler1 vSHAA256(szSHA256);
		vSHAA256
			.setSymbol("funcCryptAcquireContextA.rva", funcCryptAcquireContextA.rva)
			.setSymbol("funcCryptCreateHash.rva", funcCryptCreateHash.rva)
			.setSymbol("funcCryptHashData.rva", funcCryptHashData.rva)
			.setSymbol("funcCryptGetHashParam.rva", funcCryptGetHashParam.rva)
			.setSymbol("funcCryptDestroyHash.rva", funcCryptDestroyHash.rva)
			.setSymbol("funcCryptReleaseContext.rva", funcCryptReleaseContext.rva)
			.setSymbol("funclstrlenA.rva", funclstrlenA.rva)
			.build();

		if (vSHAA256.error()) {
			std::cerr << "SHAA256 Error\n\n";
			return 1;
		}

		file << vSHAA256.getVector();

#pragma endregion

#pragma region RtlCompareMemory
		auto rtlCompareMemory = file.getPos();
		/*
		* push size
		* push buffer2
		* push buffer1
		* call func
		*/

		Assembler1 vRtlCompareMemory(szRtlCompareMemory);
		vRtlCompareMemory.build();
		if (vRtlCompareMemory.error()) {
			std::cerr << "RtlCompareMemory Error\n\n";
			return 1;
		}

		file << vRtlCompareMemory.getVector();

#pragma endregion

#pragma region Check Password
		auto checkPassword = file.getPos();

		Assembler1 vCheckPassword(szCheckPassword);
		vCheckPassword
			.setSymbol("hashBuffer.rva", hashBuffer.rva)
			.setSymbol("pwBuffer.rva", pwBuffer.rva)
			.setSymbol("sha256.rva", sha256.rva)
			.setSymbol("hashBuffer.rva", hashBuffer.rva)
			.setSymbol("orgHashBuffer.rva", orgHashBuffer.rva)
			.setSymbol("rtlCompareMemory.rva", rtlCompareMemory.rva)
			.setSymbol("pwBuffer.rva", pwBuffer.rva)
			.setSymbol("roundKeyBuffer.rva", roundKeyBuffer.rva)
			.setSymbol("seedKeySched.rva", seedKeySched.rva)
			.build();

		if (vCheckPassword.error()) {
			std::cerr << "checkPassword Error\n\n";
			return 1;
		}


		file << vCheckPassword.getVector();
#pragma endregion

#pragma region Dialog Procedure
		// if the password is correct, the return value of EndDialog will be 0, otherwise 1.
		auto dialogProc = file.getPos();

		Assembler1 vDialogProcedure(szDialogProcedure);
		vDialogProcedure
			.setSymbol("pwBuffer.rva", pwBuffer.rva)
			.setSymbol("zeroMemory.rva", zeroMemory.rva)
			.setSymbol("funcGetDlgItemTextA.rva", funcGetDlgItemTextA.rva)
			.setSymbol("funclstrlenA.rva", funclstrlenA.rva)
			.setSymbol("checkPassword.rva", checkPassword.rva)
			.setSymbol("funcEndDialog.rva", funcEndDialog.rva)
			.build();

		if (vDialogProcedure.error()) {
			std::cerr << "DialogProcedure Error\n\n";
			return 1;
		}


		file << vDialogProcedure.getVector();
#pragma endregion

#pragma region Kernel32 Function
		auto kernel32Function = file.getPos();
		Assembler1 vKernel32Function(szKernel32Function);
		vKernel32Function.build();
		if (vKernel32Function.error()) {
			std::cerr << "Kernel32Function Error\n\n";
			return 1;
		}
		file << vKernel32Function.getVector();
#pragma endregion

#pragma region TLS Callback
		auto tlsCallback = file.getPos();
		if (file.TLSDirectory->VirtualAddress) {

			Assembler1 vTLSCallback(szTLSCallback);
			vTLSCallback.setSymbol("AddressOfCallBacks.RVA", oldTLSDirectory.AddressOfCallBacks - *file.ImageBase);
			vTLSCallback.build();
			if (vTLSCallback.error()) {
				std::cerr << "TLSCallback Error\n\n";
				return 1;
			}
			file << vTLSCallback.getVector();
		}
#pragma endregion

#pragma endregion

#pragma region Entry Point
		auto entryPoint = file.getPos();

#pragma region Prologue

		Assembler1 Prologue(
			R"(
				pushad
				mov ebx, dword ptr fs:[0x00000030]
				mov ebx, dword ptr ds:[ebx+0x8]
				lea ebp, ds:[ebx+kernel32Function.rva]
				push hashGenerate("VirtualProtect")
				call ebp
				lea edx, ds:[ebx+dwordBuffer.rva]
				push edx
				push PAGE_EXECUTE_READWRITE
				push oldSizeOfImage
				push ebx
				call eax
			)"
		);
		Prologue
			.setSymbol("kernel32Function.rva", kernel32Function.rva)
			.setSymbol("dwordBuffer.rva", dwordBuffer.rva)
			.setSymbol("PAGE_EXECUTE_READWRITE", PAGE_EXECUTE_READWRITE)
			.setSymbol("oldSizeOfImage", oldSizeOfImage)
			.setFunction("hashGenerate", [](std::string arg)->uint32_t { return hashGenerate(arg); })
			.build();

		if (Prologue.error()) {
			std::cerr << "Prologue Error\n\n";
			return 1;
		}
		file << Prologue.getVector();
#pragma endregion

#pragma region Initialize variables
		Assembler1 InitializeVariables(szInitializeVariables);
		InitializeVariables
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
			.setFunction("hashGenerate", [](std::string arg)->uint32_t { return hashGenerate(arg); })
			.build();

		if (InitializeVariables.error()) {
			std::cerr << "InitializeVariables Error\n\n";
			return 1;
		}
		file << InitializeVariables.getVector();

#pragma endregion

#pragma region Show password dialog
		// Show dialog
		Assembler1 ShowPasswordDialog(R"(
			push 0x0
			lea edx, ds:[ebx+dialogProc.rva]
			push edx
			push 0x0
			lea edx, ds:[ebx+dialogTemplate.rva]
			push edx
			push ebx
			call dword ptr ds:[ebx+funcDialogBoxIndirectParamA.rva]
		)");
		ShowPasswordDialog
			.setSymbol("dialogProc.rva", dialogProc.rva)
			.setSymbol("dialogTemplate.rva", dialogTemplate.rva)
			.setSymbol("funcDialogBoxIndirectParamA.rva", funcDialogBoxIndirectParamA.rva)
			.build();

		if (ShowPasswordDialog.error()) {
			std::cerr << "ShowPasswordDialog Error\n\n";
			return 1;
		}
		file << ShowPasswordDialog.getVector();
#pragma endregion

#pragma region Decrypt sections
		// check eax. if eax is 1, dialog was closed by the user so exit process.
		// if eax is 0, the password is correct so decrypt binary using generated round key.

		Assembler1 DecryptSections(R"(
			test eax, eax
			je label_decrypt
			push hashGenerate("ExitProcess")
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
		)");
		DecryptSections
			.setSymbol("sectionAddrBuffer.rva", sectionAddrBuffer.rva)
			.setSymbol("roundKeyBuffer.rva", roundKeyBuffer.rva)
			.setSymbol("seedDecrypt.rva", seedDecrypt.rva)
			.setFunction("hashGenerate", [](std::string arg)->uint32_t { return hashGenerate(arg); })
			.build();
		if (DecryptSections.error()) {
			std::cerr << "ShowPasswordDialog Error\n\n";
			return 1;
		}
		file << DecryptSections.getVector();
#pragma endregion

#pragma region Recover PE Header
		// Recover import directory
		if (file.ImportDirectory->VirtualAddress) {
			Assembler1 RecoverImportDirectory(R"(
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
		)");
			RecoverImportDirectory
				.setSymbol("funcLoadLibraryA.rva", funcLoadLibraryA.rva)
				.setSymbol("funcGetProcAddress.rva", funcGetProcAddress.rva)
				.setSymbol("ImportDirectoryRVA.Offset", (DWORD)((BYTE*)file.ImportDirectory - file.data()))
				.setSymbol("ImportDirectorySize.Offset", (DWORD)((BYTE*)file.ImportDirectory - file.data()) + 4)
				.setSymbol("ImportDirectorySize", file.ImportDirectory->Size)
				.setSymbol("ImportDirectoryRVA", file.ImportDirectory->VirtualAddress)
				.build();

			if (RecoverImportDirectory.error()) {
				std::cerr << "RecoverImportDirectory Error\n\n";
				return 1;
			}
			file << RecoverImportDirectory.getVector();
		}

		// Recover relocation directory
		if (*file.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE && oldRelocationDirectory.rva) {

			Assembler1 RecoverRelocationDirectory(R"(
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
)");

			RecoverRelocationDirectory
				.setSymbol("ImageBase", *file.ImageBase)
				.setSymbol("oldRelocationDirectory.rva", oldRelocationDirectory.rva)
				.build();
			if (RecoverRelocationDirectory.error()) {
				std::cerr << "RecoverRelocationDirectory Error\n\n";
				return 1;
			}
			file << RecoverRelocationDirectory.getVector();

		}

		// Recover TLS directory
		if (file.TLSDirectory->VirtualAddress) {

			Assembler1 RecoverTLSDirectory(R"(
				push 0
				push 1
				push ebx
				lea edx, ds:[ebx+tlsCallback.rva]
				call edx
			)");
			RecoverTLSDirectory
				.setSymbol("tlsCallback.rva", tlsCallback.rva)
				.build();

			if (RecoverTLSDirectory.error()) {
				std::cerr << "RecoverTLSDirectory Error\n\n";
				return 1;
			}
			file << RecoverTLSDirectory.getVector();
		}
#pragma endregion

#pragma region Epilogue

		Assembler1 Epilogue(R"(
			lea edx, ds:[ebx+OEP.rva]
			mov dword ptr ss:[esp+0x1C], edx
			popad
			jmp dword ptr ss:[esp-0x4]
		)");
		Epilogue
			.setSymbol("OEP.rva", *file.AddressOfEntryPoint)
			.build();

		if (Epilogue.error()) {
			std::cerr << "RecoverTLSDirectory Error\n\n";
			return 1;
		}
		file << Epilogue.getVector();

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

		std::cout << "the file is successfully encrypted.\n\n";

	}
	catch (pe32::Exception& ex) {
		std::cout << ex.get() << "\n";
		return 1;
	}

	return 0;
}