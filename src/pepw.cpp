#include <iostream>
#include "pepw.h"
#include "PE/PEBase.h"
#include "PE/PEResource.h"
#include "PE/PERelocation.h"
#include "PE/Exception.h"

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
		auto seedKeySched = file.getPos();
		/*
		* push pbUserKey
		* push pdwRoundkey
		* call func
		*/
		file << VECTOR(0x55);                                                                                             // push ebp
		file << VECTOR(0x8B, 0xEC);                                                                                       // mov ebp, esp
		file << VECTOR(0x83, 0xEC, 0x1C);                                                                                 // sub esp, 0x1C
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x89, 0x45, 0xE4);                                                                                 // mov dword ptr ss:[ebp-0x1C], eax
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x03);                                                                                 // imul edx, ecx, 0x3
		file << VECTOR(0x8B, 0x45, 0x0C);                                                                                 // mov eax, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x10);                                                                           // movzx ecx, byte ptr ds:[eax+edx*1]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0xD1, 0xE2);                                                                                       // shl edx, 0x1
		file << VECTOR(0x8B, 0x45, 0x0C);                                                                                 // mov eax, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x10);                                                                           // movzx edx, byte ptr ds:[eax+edx*1]
		file << VECTOR(0xC1, 0xE2, 0x10);                                                                                 // shl edx, 0x10
		file << VECTOR(0x0B, 0xCA);                                                                                       // or ecx, edx
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x55, 0x0C);                                                                                 // mov edx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x02);                                                                           // movzx eax, byte ptr ds:[edx+eax*1]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x0B, 0xC8);                                                                                       // or ecx, eax
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x55, 0x0C);                                                                                 // mov edx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x02);                                                                           // movzx eax, byte ptr ds:[edx+eax*1]
		file << VECTOR(0x0B, 0xC8);                                                                                       // or ecx, eax
		file << VECTOR(0x89, 0x4D, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], ecx
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x07);                                                                                 // imul edx, ecx, 0x7
		file << VECTOR(0x8B, 0x45, 0x0C);                                                                                 // mov eax, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x10);                                                                           // movzx ecx, byte ptr ds:[eax+edx*1]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x06);                                                                                 // imul eax, edx, 0x6
		file << VECTOR(0x8B, 0x55, 0x0C);                                                                                 // mov edx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x02);                                                                           // movzx eax, byte ptr ds:[edx+eax*1]
		file << VECTOR(0xC1, 0xE0, 0x10);                                                                                 // shl eax, 0x10
		file << VECTOR(0x0B, 0xC8);                                                                                       // or ecx, eax
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x05);                                                                                 // imul eax, edx, 0x5
		file << VECTOR(0x8B, 0x55, 0x0C);                                                                                 // mov edx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x02);                                                                           // movzx eax, byte ptr ds:[edx+eax*1]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x0B, 0xC8);                                                                                       // or ecx, eax
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0xC1, 0xE2, 0x02);                                                                                 // shl edx, 0x2
		file << VECTOR(0x8B, 0x45, 0x0C);                                                                                 // mov eax, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x10);                                                                           // movzx edx, byte ptr ds:[eax+edx*1]
		file << VECTOR(0x0B, 0xCA);                                                                                       // or ecx, edx
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0B);                                                                                 // imul ecx, eax, 0xB
		file << VECTOR(0x8B, 0x55, 0x0C);                                                                                 // mov edx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x0A);                                                                           // movzx eax, byte ptr ds:[edx+ecx*1]
		file << VECTOR(0xC1, 0xE0, 0x18);                                                                                 // shl eax, 0x18
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x0A);                                                                                 // imul edx, ecx, 0xA
		file << VECTOR(0x8B, 0x4D, 0x0C);                                                                                 // mov ecx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x11);                                                                           // movzx edx, byte ptr ds:[ecx+edx*1]
		file << VECTOR(0xC1, 0xE2, 0x10);                                                                                 // shl edx, 0x10
		file << VECTOR(0x0B, 0xC2);                                                                                       // or eax, edx
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x09);                                                                                 // imul edx, ecx, 0x9
		file << VECTOR(0x8B, 0x4D, 0x0C);                                                                                 // mov ecx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x11);                                                                           // movzx edx, byte ptr ds:[ecx+edx*1]
		file << VECTOR(0xC1, 0xE2, 0x08);                                                                                 // shl edx, 0x8
		file << VECTOR(0x0B, 0xC2);                                                                                       // or eax, edx
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0xC1, 0xE1, 0x03);                                                                                 // shl ecx, 0x3
		file << VECTOR(0x8B, 0x55, 0x0C);                                                                                 // mov edx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x0A);                                                                           // movzx ecx, byte ptr ds:[edx+ecx*1]
		file << VECTOR(0x0B, 0xC1);                                                                                       // or eax, ecx
		file << VECTOR(0x89, 0x45, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], eax
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x0F);                                                                                 // imul eax, edx, 0xF
		file << VECTOR(0x8B, 0x4D, 0x0C);                                                                                 // mov ecx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x01);                                                                           // movzx edx, byte ptr ds:[ecx+eax*1]
		file << VECTOR(0xC1, 0xE2, 0x18);                                                                                 // shl edx, 0x18
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0E);                                                                                 // imul ecx, eax, 0xE
		file << VECTOR(0x8B, 0x45, 0x0C);                                                                                 // mov eax, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x08);                                                                           // movzx ecx, byte ptr ds:[eax+ecx*1]
		file << VECTOR(0xC1, 0xE1, 0x10);                                                                                 // shl ecx, 0x10
		file << VECTOR(0x0B, 0xD1);                                                                                       // or edx, ecx
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0D);                                                                                 // imul ecx, eax, 0xD
		file << VECTOR(0x8B, 0x45, 0x0C);                                                                                 // mov eax, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x08);                                                                           // movzx ecx, byte ptr ds:[eax+ecx*1]
		file << VECTOR(0xC1, 0xE1, 0x08);                                                                                 // shl ecx, 0x8
		file << VECTOR(0x0B, 0xD1);                                                                                       // or edx, ecx
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0C);                                                                                 // imul ecx, eax, 0xC
		file << VECTOR(0x8B, 0x45, 0x0C);                                                                                 // mov eax, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x08);                                                                           // movzx ecx, byte ptr ds:[eax+ecx*1]
		file << VECTOR(0x0B, 0xD1);                                                                                       // or edx, ecx
		file << VECTOR(0x89, 0x55, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], edx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xC2, 0x08);                                                                                 // rol edx, 0x8
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0xFF, 0x00);                                                               // and edx, 0xFF00FF
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xC0, 0x18);                                                                                 // rol eax, 0x18
		file << VECTOR(0x25, 0x00, 0xFF, 0x00, 0xFF);                                                                     // and eax, 0xFF00FF00
		file << VECTOR(0x0B, 0xD0);                                                                                       // or edx, eax
		file << VECTOR(0x89, 0x55, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], edx
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xC1, 0x08);                                                                                 // rol ecx, 0x8
		file << VECTOR(0x81, 0xE1, 0xFF, 0x00, 0xFF, 0x00);                                                               // and ecx, 0xFF00FF
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xC2, 0x18);                                                                                 // rol edx, 0x18
		file << VECTOR(0x81, 0xE2, 0x00, 0xFF, 0x00, 0xFF);                                                               // and edx, 0xFF00FF00
		file << VECTOR(0x0B, 0xCA);                                                                                       // or ecx, edx
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xC0, 0x08);                                                                                 // rol eax, 0x8
		file << VECTOR(0x25, 0xFF, 0x00, 0xFF, 0x00);                                                                     // and eax, 0xFF00FF
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xC1, 0x18);                                                                                 // rol ecx, 0x18
		file << VECTOR(0x81, 0xE1, 0x00, 0xFF, 0x00, 0xFF);                                                               // and ecx, 0xFF00FF00
		file << VECTOR(0x0B, 0xC1);                                                                                       // or eax, ecx
		file << VECTOR(0x89, 0x45, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], eax
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xC2, 0x08);                                                                                 // rol edx, 0x8
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0xFF, 0x00);                                                               // and edx, 0xFF00FF
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xC0, 0x18);                                                                                 // rol eax, 0x18
		file << VECTOR(0x25, 0x00, 0xFF, 0x00, 0xFF);                                                                     // and eax, 0xFF00FF00
		file << VECTOR(0x0B, 0xD0);                                                                                       // or edx, eax
		file << VECTOR(0x89, 0x55, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], edx
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x84, 0x0A, 0x47, 0x86, 0xC8, 0x61);                                                         // lea eax, ds:[edx+ecx*1+0x61C88647]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xE9, 0x47, 0x86, 0xC8, 0x61);                                                               // sub ecx, 0x61C88647
		file << VECTOR(0x2B, 0x4D, 0xE8);                                                                                 // sub ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x14, 0x08);                                                                                 // mov dword ptr ds:[eax+ecx*1], edx
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x0C, 0x10);                                                                                 // mov dword ptr ds:[eax+edx*1], ecx
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE0, 0x18);                                                                                 // shl eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], edx
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE2, 0x18);                                                                                 // shl edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x94, 0x01, 0x8D, 0x0C, 0x91, 0xC3);                                                         // lea edx, ds:[ecx+eax*1-0x3C6EF373]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x05, 0x73, 0xF3, 0x6E, 0x3C);                                                                     // add eax, 0x3C6EF373
		file << VECTOR(0x2B, 0x45, 0xE8);                                                                                 // sub eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x02, 0x08);                                                                           // mov dword ptr ds:[edx+eax*1+0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x0A, 0x08);                                                                           // mov dword ptr ds:[edx+ecx*1+0x8], eax
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE1, 0x08);                                                                                 // shl ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], ecx
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], eax
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x8C, 0x10, 0x1A, 0x19, 0x22, 0x87);                                                         // lea ecx, ds:[eax+edx*1-0x78DDE6E6]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xC2, 0xE6, 0xE6, 0xDD, 0x78);                                                               // add edx, 0x78DDE6E6
		file << VECTOR(0x2B, 0x55, 0xE8);                                                                                 // sub edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x11, 0x10);                                                                           // mov dword ptr ds:[ecx+edx*1+0x10], eax
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x01, 0x10);                                                                           // mov dword ptr ds:[ecx+eax*1+0x10], edx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE0, 0x18);                                                                                 // shl eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x84, 0x0A, 0x34, 0x32, 0x44, 0x0E);                                                         // lea eax, ds:[edx+ecx*1+0xE443234]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xE9, 0x34, 0x32, 0x44, 0x0E);                                                               // sub ecx, 0xE443234
		file << VECTOR(0x2B, 0x4D, 0xE8);                                                                                 // sub ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x08, 0x18);                                                                           // mov dword ptr ds:[eax+ecx*1+0x18], edx
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x10, 0x18);                                                                           // mov dword ptr ds:[eax+edx*1+0x18], ecx
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE2, 0x08);                                                                                 // shl edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], edx
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE1, 0x08);                                                                                 // shl ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], ecx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x94, 0x01, 0x67, 0x64, 0x88, 0x1C);                                                         // lea edx, ds:[ecx+eax*1+0x1C886467]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x2D, 0x67, 0x64, 0x88, 0x1C);                                                                     // sub eax, 0x1C886467
		file << VECTOR(0x2B, 0x45, 0xE8);                                                                                 // sub eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x02, 0x20);                                                                           // mov dword ptr ds:[edx+eax*1+0x20], ecx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x0A, 0x20);                                                                           // mov dword ptr ds:[edx+ecx*1+0x20], eax
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE2, 0x18);                                                                                 // shl edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], ecx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], eax
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x8C, 0x10, 0xCD, 0xC8, 0x10, 0x39);                                                         // lea ecx, ds:[eax+edx*1+0x3910C8CD]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xEA, 0xCD, 0xC8, 0x10, 0x39);                                                               // sub edx, 0x3910C8CD
		file << VECTOR(0x2B, 0x55, 0xE8);                                                                                 // sub edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x11, 0x28);                                                                           // mov dword ptr ds:[ecx+edx*1+0x28], eax
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x01, 0x28);                                                                           // mov dword ptr ds:[ecx+eax*1+0x28], edx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], eax
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE2, 0x08);                                                                                 // shl edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], edx
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x84, 0x0A, 0x99, 0x91, 0x21, 0x72);                                                         // lea eax, ds:[edx+ecx*1+0x72219199]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xE9, 0x99, 0x91, 0x21, 0x72);                                                               // sub ecx, 0x72219199
		file << VECTOR(0x2B, 0x4D, 0xE8);                                                                                 // sub ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x08, 0x30);                                                                           // mov dword ptr ds:[eax+ecx*1+0x30], edx
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x10, 0x30);                                                                           // mov dword ptr ds:[eax+edx*1+0x30], ecx
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE0, 0x18);                                                                                 // shl eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], edx
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE2, 0x18);                                                                                 // shl edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x94, 0x01, 0x31, 0x23, 0x43, 0xE4);                                                         // lea edx, ds:[ecx+eax*1-0x1BBCDCCF]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x05, 0xCF, 0xDC, 0xBC, 0x1B);                                                                     // add eax, 0x1BBCDCCF
		file << VECTOR(0x2B, 0x45, 0xE8);                                                                                 // sub eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x02, 0x38);                                                                           // mov dword ptr ds:[edx+eax*1+0x38], ecx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x0A, 0x38);                                                                           // mov dword ptr ds:[edx+ecx*1+0x38], eax
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE1, 0x08);                                                                                 // shl ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], ecx
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], eax
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x8C, 0x10, 0x62, 0x46, 0x86, 0xC8);                                                         // lea ecx, ds:[eax+edx*1-0x3779B99E]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xC2, 0x9E, 0xB9, 0x79, 0x37);                                                               // add edx, 0x3779B99E
		file << VECTOR(0x2B, 0x55, 0xE8);                                                                                 // sub edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x11, 0x40);                                                                           // mov dword ptr ds:[ecx+edx*1+0x40], eax
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x01, 0x40);                                                                           // mov dword ptr ds:[ecx+eax*1+0x40], edx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE0, 0x18);                                                                                 // shl eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x84, 0x0A, 0xC4, 0x8C, 0x0C, 0x91);                                                         // lea eax, ds:[edx+ecx*1-0x6EF3733C]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xC1, 0x3C, 0x73, 0xF3, 0x6E);                                                               // add ecx, 0x6EF3733C
		file << VECTOR(0x2B, 0x4D, 0xE8);                                                                                 // sub ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x08, 0x48);                                                                           // mov dword ptr ds:[eax+ecx*1+0x48], edx
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x10, 0x48);                                                                           // mov dword ptr ds:[eax+edx*1+0x48], ecx
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE2, 0x08);                                                                                 // shl edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], edx
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE1, 0x08);                                                                                 // shl ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], ecx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x94, 0x01, 0x88, 0x19, 0x19, 0x22);                                                         // lea edx, ds:[ecx+eax*1+0x22191988]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x2D, 0x88, 0x19, 0x19, 0x22);                                                                     // sub eax, 0x22191988
		file << VECTOR(0x2B, 0x45, 0xE8);                                                                                 // sub eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x02, 0x50);                                                                           // mov dword ptr ds:[edx+eax*1+0x50], ecx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x0A, 0x50);                                                                           // mov dword ptr ds:[edx+ecx*1+0x50], eax
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE2, 0x18);                                                                                 // shl edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], ecx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], eax
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x8C, 0x10, 0x0F, 0x33, 0x32, 0x44);                                                         // lea ecx, ds:[eax+edx*1+0x4432330F]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xEA, 0x0F, 0x33, 0x32, 0x44);                                                               // sub edx, 0x4432330F
		file << VECTOR(0x2B, 0x55, 0xE8);                                                                                 // sub edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x11, 0x58);                                                                           // mov dword ptr ds:[ecx+edx*1+0x58], eax
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x01, 0x58);                                                                           // mov dword ptr ds:[ecx+eax*1+0x58], edx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], eax
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE2, 0x08);                                                                                 // shl edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], edx
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x84, 0x0A, 0x1D, 0x66, 0x64, 0x88);                                                         // lea eax, ds:[edx+ecx*1-0x779B99E3]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xC1, 0xE3, 0x99, 0x9B, 0x77);                                                               // add ecx, 0x779B99E3
		file << VECTOR(0x2B, 0x4D, 0xE8);                                                                                 // sub ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x08, 0x60);                                                                           // mov dword ptr ds:[eax+ecx*1+0x60], edx
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x10, 0x60);                                                                           // mov dword ptr ds:[eax+edx*1+0x60], ecx
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE0, 0x18);                                                                                 // shl eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], edx
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE2, 0x18);                                                                                 // shl edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x94, 0x01, 0x3A, 0xCC, 0xC8, 0x10);                                                         // lea edx, ds:[ecx+eax*1+0x10C8CC3A]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x2D, 0x3A, 0xCC, 0xC8, 0x10);                                                                     // sub eax, 0x10C8CC3A
		file << VECTOR(0x2B, 0x45, 0xE8);                                                                                 // sub eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x4C, 0x02, 0x68);                                                                           // mov dword ptr ds:[edx+eax*1+0x68], ecx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x0A, 0x68);                                                                           // mov dword ptr ds:[edx+ecx*1+0x68], eax
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE1, 0x08);                                                                                 // shl ecx, 0x8
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x33, 0xCA);                                                                                       // xor ecx, edx
		file << VECTOR(0x89, 0x4D, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], ecx
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], eax
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x8C, 0x10, 0x73, 0x98, 0x91, 0x21);                                                         // lea ecx, ds:[eax+edx*1+0x21919873]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xEA, 0x73, 0x98, 0x91, 0x21);                                                               // sub edx, 0x21919873
		file << VECTOR(0x2B, 0x55, 0xE8);                                                                                 // sub edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[ebx+eax*4+SS0]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS1]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS2]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[ebx+edx*4+SS3]
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x44, 0x11, 0x70);                                                                           // mov dword ptr ds:[ecx+edx*1+0x70], eax
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x54, 0x01, 0x70);                                                                           // mov dword ptr ds:[ecx+eax*1+0x70], edx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0x33, 0xC1);                                                                                       // xor eax, ecx
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE0, 0x18);                                                                                 // shl eax, 0x18
		file << VECTOR(0x33, 0xD0);                                                                                       // xor edx, eax
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x8D, 0x84, 0x0A, 0xE5, 0x30, 0x23, 0x43);                                                         // lea eax, ds:[edx+ecx*1+0x432330E5]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x2B, 0x4D, 0xE8);                                                                                 // sub ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x81, 0xE9, 0xE5, 0x30, 0x23, 0x43);                                                               // sub ecx, 0x432330E5
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[ebx+edx*4+SS0]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS1]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS2]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ebx+ecx*4+SS3]
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x1E);                                                                                 // imul ecx, eax, 0x1E
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x14, 0x08);                                                                                 // mov dword ptr ds:[eax+ecx*1], edx
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ebx+ecx*4+SS0]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS1]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS2]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[ebx+eax*4+SS3]
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x1F);                                                                                 // imul eax, edx, 0x1F
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x89, 0x0C, 0x02);                                                                                 // mov dword ptr ds:[edx+eax*1], ecx
		file << VECTOR(0x8B, 0xE5);                                                                                       // mov esp, ebp
		file << VECTOR(0x5D);                                                                                             // pop ebp
		file << VECTOR(0xC2, 0x08, 0x00);                                                                                 // ret 0x8

#pragma endregion

#pragma region SEED_Decrypt
		auto seedDecrypt = file.getPos();
		/*
		* push pdwRoundKey
		* push pbData
		* call func
		*/
		file << VECTOR(0x55);                                                                                             // push ebp
		file << VECTOR(0x8B, 0xEC);                                                                                       // mov ebp, esp
		file << VECTOR(0x83, 0xEC, 0x1C);                                                                                 // sub esp, 0x1C
		file << VECTOR(0x8B, 0x45, 0x0C);                                                                                 // mov eax, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x89, 0x45, 0xE4);                                                                                 // mov dword ptr ss:[ebp-0x1C], eax
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x03);                                                                                 // imul edx, ecx, 0x3
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x10);                                                                           // movzx ecx, byte ptr ds:[eax+edx*1]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0xD1, 0xE2);                                                                                       // shl edx, 0x1
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x10);                                                                           // movzx edx, byte ptr ds:[eax+edx*1]
		file << VECTOR(0xC1, 0xE2, 0x10);                                                                                 // shl edx, 0x10
		file << VECTOR(0x0B, 0xCA);                                                                                       // or ecx, edx
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x02);                                                                           // movzx eax, byte ptr ds:[edx+eax*1]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x0B, 0xC8);                                                                                       // or ecx, eax
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x02);                                                                           // movzx eax, byte ptr ds:[edx+eax*1]
		file << VECTOR(0x0B, 0xC8);                                                                                       // or ecx, eax
		file << VECTOR(0x89, 0x4D, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], ecx
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x07);                                                                                 // imul edx, ecx, 0x7
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x10);                                                                           // movzx ecx, byte ptr ds:[eax+edx*1]
		file << VECTOR(0xC1, 0xE1, 0x18);                                                                                 // shl ecx, 0x18
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x06);                                                                                 // imul eax, edx, 0x6
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x02);                                                                           // movzx eax, byte ptr ds:[edx+eax*1]
		file << VECTOR(0xC1, 0xE0, 0x10);                                                                                 // shl eax, 0x10
		file << VECTOR(0x0B, 0xC8);                                                                                       // or ecx, eax
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x05);                                                                                 // imul eax, edx, 0x5
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x02);                                                                           // movzx eax, byte ptr ds:[edx+eax*1]
		file << VECTOR(0xC1, 0xE0, 0x08);                                                                                 // shl eax, 0x8
		file << VECTOR(0x0B, 0xC8);                                                                                       // or ecx, eax
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0xC1, 0xE2, 0x02);                                                                                 // shl edx, 0x2
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x10);                                                                           // movzx edx, byte ptr ds:[eax+edx*1]
		file << VECTOR(0x0B, 0xCA);                                                                                       // or ecx, edx
		file << VECTOR(0x89, 0x4D, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], ecx
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0B);                                                                                 // imul ecx, eax, 0xB
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x04, 0x0A);                                                                           // movzx eax, byte ptr ds:[edx+ecx*1]
		file << VECTOR(0xC1, 0xE0, 0x18);                                                                                 // shl eax, 0x18
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x0A);                                                                                 // imul edx, ecx, 0xA
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x11);                                                                           // movzx edx, byte ptr ds:[ecx+edx*1]
		file << VECTOR(0xC1, 0xE2, 0x10);                                                                                 // shl edx, 0x10
		file << VECTOR(0x0B, 0xC2);                                                                                       // or eax, edx
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x09);                                                                                 // imul edx, ecx, 0x9
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x11);                                                                           // movzx edx, byte ptr ds:[ecx+edx*1]
		file << VECTOR(0xC1, 0xE2, 0x08);                                                                                 // shl edx, 0x8
		file << VECTOR(0x0B, 0xC2);                                                                                       // or eax, edx
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0xC1, 0xE1, 0x03);                                                                                 // shl ecx, 0x3
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x0A);                                                                           // movzx ecx, byte ptr ds:[edx+ecx*1]
		file << VECTOR(0x0B, 0xC1);                                                                                       // or eax, ecx
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x0F);                                                                                 // imul eax, edx, 0xF
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x14, 0x01);                                                                           // movzx edx, byte ptr ds:[ecx+eax*1]
		file << VECTOR(0xC1, 0xE2, 0x18);                                                                                 // shl edx, 0x18
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0E);                                                                                 // imul ecx, eax, 0xE
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x08);                                                                           // movzx ecx, byte ptr ds:[eax+ecx*1]
		file << VECTOR(0xC1, 0xE1, 0x10);                                                                                 // shl ecx, 0x10
		file << VECTOR(0x0B, 0xD1);                                                                                       // or edx, ecx
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0D);                                                                                 // imul ecx, eax, 0xD
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x08);                                                                           // movzx ecx, byte ptr ds:[eax+ecx*1]
		file << VECTOR(0xC1, 0xE1, 0x08);                                                                                 // shl ecx, 0x8
		file << VECTOR(0x0B, 0xD1);                                                                                       // or edx, ecx
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0C);                                                                                 // imul ecx, eax, 0xC
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x0F, 0xB6, 0x0C, 0x08);                                                                           // movzx ecx, byte ptr ds:[eax+ecx*1]
		file << VECTOR(0x0B, 0xD1);                                                                                       // or edx, ecx
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xC2, 0x08);                                                                                 // rol edx, 0x8
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0xFF, 0x00);                                                               // and edx, 0xFF00FF
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xC0, 0x18);                                                                                 // rol eax, 0x18
		file << VECTOR(0x25, 0x00, 0xFF, 0x00, 0xFF);                                                                     // and eax, 0xFF00FF00
		file << VECTOR(0x0B, 0xD0);                                                                                       // or edx, eax
		file << VECTOR(0x89, 0x55, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], edx
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xC1, 0x08);                                                                                 // rol ecx, 0x8
		file << VECTOR(0x81, 0xE1, 0xFF, 0x00, 0xFF, 0x00);                                                               // and ecx, 0xFF00FF
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xC2, 0x18);                                                                                 // rol edx, 0x18
		file << VECTOR(0x81, 0xE2, 0x00, 0xFF, 0x00, 0xFF);                                                               // and edx, 0xFF00FF00
		file << VECTOR(0x0B, 0xCA);                                                                                       // or ecx, edx
		file << VECTOR(0x89, 0x4D, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], ecx
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xC0, 0x08);                                                                                 // rol eax, 0x8
		file << VECTOR(0x25, 0xFF, 0x00, 0xFF, 0x00);                                                                     // and eax, 0xFF00FF
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xC1, 0x18);                                                                                 // rol ecx, 0x18
		file << VECTOR(0x81, 0xE1, 0x00, 0xFF, 0x00, 0xFF);                                                               // and ecx, 0xFF00FF00
		file << VECTOR(0x0B, 0xC1);                                                                                       // or eax, ecx
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xC2, 0x08);                                                                                 // rol edx, 0x8
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0xFF, 0x00);                                                               // and edx, 0xFF00FF
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xC0, 0x18);                                                                                 // rol eax, 0x18
		file << VECTOR(0x25, 0x00, 0xFF, 0x00, 0xFF);                                                                     // and eax, 0xFF00FF00
		file << VECTOR(0x0B, 0xD0);                                                                                       // or edx, eax
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x4C, 0x10, 0x78);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x78]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x4C, 0x10, 0x78);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x78]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x4D, 0xF8);                                                                                 // add ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], eax
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x4D, 0xFC);                                                                                 // xor ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x54, 0x01, 0x70);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x70]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x54, 0x01, 0x70);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x70]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x55, 0xF8);                                                                                 // add edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], ecx
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x55, 0xFC);                                                                                 // xor edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x44, 0x0A, 0x68);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x68]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x44, 0x0A, 0x68);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x68]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x45, 0xF8);                                                                                 // add eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], edx
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x45, 0xFC);                                                                                 // xor eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x4C, 0x10, 0x60);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x60]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x4C, 0x10, 0x60);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x60]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x4D, 0xF8);                                                                                 // add ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x4D, 0xFC);                                                                                 // xor ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x54, 0x01, 0x58);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x58]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x54, 0x01, 0x58);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x58]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x55, 0xF8);                                                                                 // add edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], ecx
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x55, 0xFC);                                                                                 // xor edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x44, 0x0A, 0x50);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x50]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x44, 0x0A, 0x50);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x50]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x45, 0xF8);                                                                                 // add eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], edx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x45, 0xFC);                                                                                 // xor eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x4C, 0x10, 0x48);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x48]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x4C, 0x10, 0x48);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x48]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x4D, 0xF8);                                                                                 // add ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], eax
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x4D, 0xFC);                                                                                 // xor ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x54, 0x01, 0x40);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x40]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x54, 0x01, 0x40);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x40]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x55, 0xF8);                                                                                 // add edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], ecx
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x55, 0xFC);                                                                                 // xor edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x44, 0x0A, 0x38);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x38]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x44, 0x0A, 0x38);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x38]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x45, 0xF8);                                                                                 // add eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], edx
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x45, 0xFC);                                                                                 // xor eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x4C, 0x10, 0x30);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x30]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x4C, 0x10, 0x30);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x30]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x4D, 0xF8);                                                                                 // add ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x4D, 0xFC);                                                                                 // xor ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x54, 0x01, 0x28);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x28]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x54, 0x01, 0x28);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x28]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x55, 0xF8);                                                                                 // add edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], ecx
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x55, 0xFC);                                                                                 // xor edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x44, 0x0A, 0x20);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x20]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x44, 0x0A, 0x20);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x20]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x45, 0xF8);                                                                                 // add eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x55, 0xF4);                                                                                 // mov edx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], edx
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x45, 0xFC);                                                                                 // xor eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x4C, 0x10, 0x18);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x18]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x4C, 0x10, 0x18);                                                                           // xor ecx, dword ptr ds:[eax+edx*1+0x18]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x4D, 0xF8);                                                                                 // add ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], eax
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x4D, 0xFC);                                                                                 // xor ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x54, 0x01, 0x10);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x10]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xC1, 0xE0, 0x00);                                                                                 // shl eax, 0x0
		file << VECTOR(0x8B, 0x4D, 0xE4);                                                                                 // mov ecx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x54, 0x01, 0x10);                                                                           // xor edx, dword ptr ds:[ecx+eax*1+0x10]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xF8);                                                                           // movzx edx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x55, 0xF8);                                                                                 // add edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], ecx
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x55, 0xFC);                                                                                 // xor edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0x6B, 0xC8, 0x00);                                                                                 // imul ecx, eax, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x44, 0x0A, 0x08);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x8]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0xE4);                                                                                 // mov edx, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x44, 0x0A, 0x08);                                                                           // xor eax, dword ptr ds:[edx+ecx*1+0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x4D, 0xF8);                                                                                 // xor ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xF8);                                                                           // movzx eax, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x45, 0xF8);                                                                                 // add eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xFC);                                                                           // movzx ecx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x4D, 0xFC);                                                                                 // add ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], edx
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x45, 0xFC);                                                                                 // xor eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], eax
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0x6B, 0xD1, 0x00);                                                                                 // imul edx, ecx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x33, 0x0C, 0x10);                                                                                 // xor ecx, dword ptr ds:[eax+edx*1]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0xBA, 0x04, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x4
		file << VECTOR(0xC1, 0xE2, 0x00);                                                                                 // shl edx, 0x0
		file << VECTOR(0x8B, 0x45, 0xE4);                                                                                 // mov eax, dword ptr ss:[ebp-0x1C]
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x33, 0x0C, 0x10);                                                                                 // xor ecx, dword ptr ds:[eax+edx*1]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x33, 0x55, 0xF8);                                                                                 // xor edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x0F, 0xB6, 0x45, 0xFC);                                                                           // movzx eax, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x8B, 0x84, 0x83) << S0.rva;                                                                       // mov eax, dword ptr ds:[eax*4+S0.rva]
		file << VECTOR(0x33, 0x84, 0x93) << S1.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S1.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S2.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S2.rva]
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE9, 0x18);                                                                                 // shr ecx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xD1);                                                                                 // movzx edx, cl
		file << VECTOR(0x33, 0x84, 0x93) << S3.rva;                                                                       // xor eax, dword ptr ds:[edx*4+S3.rva]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x45, 0xFC);                                                                                 // add eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x0F, 0xB6, 0x4D, 0xF8);                                                                           // movzx ecx, byte ptr ss:[ebp-0x8]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x8B, 0x8C, 0x8B) << S0.rva;                                                                       // mov ecx, dword ptr ds:[ecx*4+S0.rva]
		file << VECTOR(0x33, 0x8C, 0x83) << S1.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S1.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S2.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S2.rva]
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC2);                                                                                 // movzx eax, dl
		file << VECTOR(0x33, 0x8C, 0x83) << S3.rva;                                                                       // xor ecx, dword ptr ds:[eax*4+S3.rva]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x4D, 0xFC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x03, 0x4D, 0xF8);                                                                                 // add ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x4D, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], ecx
		file << VECTOR(0x0F, 0xB6, 0x55, 0xFC);                                                                           // movzx edx, byte ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x8B, 0x94, 0x93) << S0.rva;                                                                       // mov edx, dword ptr ds:[edx*4+S0.rva]
		file << VECTOR(0x33, 0x94, 0x8B) << S1.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S1.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S2.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S2.rva]
		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x0F, 0xB6, 0xC8);                                                                                 // movzx ecx, al
		file << VECTOR(0x33, 0x94, 0x8B) << S3.rva;                                                                       // xor edx, dword ptr ds:[ecx*4+S3.rva]
		file << VECTOR(0x89, 0x55, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], edx
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x03, 0x55, 0xFC);                                                                                 // add edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x55, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], edx
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x33, 0x45, 0xF8);                                                                                 // xor eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x33, 0x4D, 0xFC);                                                                                 // xor ecx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xC2, 0x08);                                                                                 // rol edx, 0x8
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0xFF, 0x00);                                                               // and edx, 0xFF00FF
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xC0, 0x18);                                                                                 // rol eax, 0x18
		file << VECTOR(0x25, 0x00, 0xFF, 0x00, 0xFF);                                                                     // and eax, 0xFF00FF00
		file << VECTOR(0x0B, 0xD0);                                                                                       // or edx, eax
		file << VECTOR(0x89, 0x55, 0xEC);                                                                                 // mov dword ptr ss:[ebp-0x14], edx
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xC1, 0x08);                                                                                 // rol ecx, 0x8
		file << VECTOR(0x81, 0xE1, 0xFF, 0x00, 0xFF, 0x00);                                                               // and ecx, 0xFF00FF
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xC2, 0x18);                                                                                 // rol edx, 0x18
		file << VECTOR(0x81, 0xE2, 0x00, 0xFF, 0x00, 0xFF);                                                               // and edx, 0xFF00FF00
		file << VECTOR(0x0B, 0xCA);                                                                                       // or ecx, edx
		file << VECTOR(0x89, 0x4D, 0xE8);                                                                                 // mov dword ptr ss:[ebp-0x18], ecx
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xC0, 0x08);                                                                                 // rol eax, 0x8
		file << VECTOR(0x25, 0xFF, 0x00, 0xFF, 0x00);                                                                     // and eax, 0xFF00FF
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xC1, 0x18);                                                                                 // rol ecx, 0x18
		file << VECTOR(0x81, 0xE1, 0x00, 0xFF, 0x00, 0xFF);                                                               // and ecx, 0xFF00FF00
		file << VECTOR(0x0B, 0xC1);                                                                                       // or eax, ecx
		file << VECTOR(0x89, 0x45, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], eax
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xC2, 0x08);                                                                                 // rol edx, 0x8
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0xFF, 0x00);                                                               // and edx, 0xFF00FF
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xC0, 0x18);                                                                                 // rol eax, 0x18
		file << VECTOR(0x25, 0x00, 0xFF, 0x00, 0xFF);                                                                     // and eax, 0xFF00FF00
		file << VECTOR(0x0B, 0xD0);                                                                                       // or edx, eax
		file << VECTOR(0x89, 0x55, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], edx
		file << VECTOR(0x8B, 0x4D, 0xF4);                                                                                 // mov ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x81, 0xE1, 0xFF, 0x00, 0x00, 0x00);                                                               // and ecx, 0xFF
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x00);                                                                                 // imul eax, edx, 0x0
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x0C, 0x02);                                                                                 // mov byte ptr ds:[edx+eax*1], cl
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xE8, 0x08);                                                                                 // shr eax, 0x8
		file << VECTOR(0x25, 0xFF, 0x00, 0x00, 0x00);                                                                     // and eax, 0xFF
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0xC1, 0xE1, 0x00);                                                                                 // shl ecx, 0x0
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x04, 0x0A);                                                                                 // mov byte ptr ds:[edx+ecx*1], al
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x25, 0xFF, 0x00, 0x00, 0x00);                                                                     // and eax, 0xFF
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0xD1, 0xE1);                                                                                       // shl ecx, 0x1
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x04, 0x0A);                                                                                 // mov byte ptr ds:[edx+ecx*1], al
		file << VECTOR(0x8B, 0x45, 0xF4);                                                                                 // mov eax, dword ptr ss:[ebp-0xC]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x25, 0xFF, 0x00, 0x00, 0x00);                                                                     // and eax, 0xFF
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x03);                                                                                 // imul edx, ecx, 0x3
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x04, 0x11);                                                                                 // mov byte ptr ds:[ecx+edx*1], al
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00);                                                               // and edx, 0xFF
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0xC1, 0xE0, 0x02);                                                                                 // shl eax, 0x2
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x14, 0x01);                                                                                 // mov byte ptr ds:[ecx+eax*1], dl
		file << VECTOR(0x8B, 0x55, 0xF0);                                                                                 // mov edx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00);                                                               // and edx, 0xFF
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x05);                                                                                 // imul ecx, eax, 0x5
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x14, 0x08);                                                                                 // mov byte ptr ds:[eax+ecx*1], dl
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x81, 0xE1, 0xFF, 0x00, 0x00, 0x00);                                                               // and ecx, 0xFF
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x06);                                                                                 // imul eax, edx, 0x6
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x0C, 0x02);                                                                                 // mov byte ptr ds:[edx+eax*1], cl
		file << VECTOR(0x8B, 0x45, 0xF0);                                                                                 // mov eax, dword ptr ss:[ebp-0x10]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x25, 0xFF, 0x00, 0x00, 0x00);                                                                     // and eax, 0xFF
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x07);                                                                                 // imul edx, ecx, 0x7
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x04, 0x11);                                                                                 // mov byte ptr ds:[ecx+edx*1], al
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00);                                                               // and edx, 0xFF
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0xC1, 0xE0, 0x03);                                                                                 // shl eax, 0x3
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x14, 0x01);                                                                                 // mov byte ptr ds:[ecx+eax*1], dl
		file << VECTOR(0x8B, 0x55, 0xEC);                                                                                 // mov edx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xEA, 0x08);                                                                                 // shr edx, 0x8
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00);                                                               // and edx, 0xFF
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x09);                                                                                 // imul ecx, eax, 0x9
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x14, 0x08);                                                                                 // mov byte ptr ds:[eax+ecx*1], dl
		file << VECTOR(0x8B, 0x4D, 0xEC);                                                                                 // mov ecx, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE9, 0x10);                                                                                 // shr ecx, 0x10
		file << VECTOR(0x81, 0xE1, 0xFF, 0x00, 0x00, 0x00);                                                               // and ecx, 0xFF
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x0A);                                                                                 // imul eax, edx, 0xA
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x0C, 0x02);                                                                                 // mov byte ptr ds:[edx+eax*1], cl
		file << VECTOR(0x8B, 0x45, 0xEC);                                                                                 // mov eax, dword ptr ss:[ebp-0x14]
		file << VECTOR(0xC1, 0xE8, 0x18);                                                                                 // shr eax, 0x18
		file << VECTOR(0x25, 0xFF, 0x00, 0x00, 0x00);                                                                     // and eax, 0xFF
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x0B);                                                                                 // imul edx, ecx, 0xB
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x04, 0x11);                                                                                 // mov byte ptr ds:[ecx+edx*1], al
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00);                                                               // and edx, 0xFF
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0C);                                                                                 // imul ecx, eax, 0xC
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x14, 0x08);                                                                                 // mov byte ptr ds:[eax+ecx*1], dl
		file << VECTOR(0x8B, 0x4D, 0xE8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE9, 0x08);                                                                                 // shr ecx, 0x8
		file << VECTOR(0x81, 0xE1, 0xFF, 0x00, 0x00, 0x00);                                                               // and ecx, 0xFF
		file << VECTOR(0xBA, 0x01, 0x00, 0x00, 0x00);                                                                     // mov edx, 0x1
		file << VECTOR(0x6B, 0xC2, 0x0D);                                                                                 // imul eax, edx, 0xD
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x0C, 0x02);                                                                                 // mov byte ptr ds:[edx+eax*1], cl
		file << VECTOR(0x8B, 0x45, 0xE8);                                                                                 // mov eax, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xE8, 0x10);                                                                                 // shr eax, 0x10
		file << VECTOR(0x25, 0xFF, 0x00, 0x00, 0x00);                                                                     // and eax, 0xFF
		file << VECTOR(0xB9, 0x01, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x1
		file << VECTOR(0x6B, 0xD1, 0x0E);                                                                                 // imul edx, ecx, 0xE
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x04, 0x11);                                                                                 // mov byte ptr ds:[ecx+edx*1], al
		file << VECTOR(0x8B, 0x55, 0xE8);                                                                                 // mov edx, dword ptr ss:[ebp-0x18]
		file << VECTOR(0xC1, 0xEA, 0x18);                                                                                 // shr edx, 0x18
		file << VECTOR(0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00);                                                               // and edx, 0xFF
		file << VECTOR(0xB8, 0x01, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x1
		file << VECTOR(0x6B, 0xC8, 0x0F);                                                                                 // imul ecx, eax, 0xF
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x88, 0x14, 0x08);                                                                                 // mov byte ptr ds:[eax+ecx*1], dl
		file << VECTOR(0x8B, 0xE5);                                                                                       // mov esp, ebp
		file << VECTOR(0x5D);                                                                                             // pop ebp
		file << VECTOR(0xC2, 0x08, 0x00);                                                                                 // ret 0x8
#pragma endregion

#pragma region Zero Memory
		auto zeroMemory = file.getPos();
		/*
		* push size
		* push ptr
		* call func
		*/
		file << VECTOR(0x55);                                                                                             // push ebp
		file << VECTOR(0x8B, 0xEC);                                                                                       // mov ebp, esp
		file << VECTOR(0x57);                                                                                             // push edi
		file << VECTOR(0x51);                                                                                             // push ecx
		file << VECTOR(0x8B, 0x7D, 0x08);                                                                                 // mov edi, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x8B, 0x4D, 0x0C);                                                                                 // mov ecx, dword ptr ss:[ebp+0xC]
		// label_loop:
		file << VECTOR(0xC6, 0x07, 0x00);                                                                                 // mov byte ptr ds:[edi], 0x0
		file << VECTOR(0x47);                                                                                             // inc edi
		file << VECTOR(0xE2, 0xFA);                                                                                       // loop label_loop
		file << VECTOR(0x59);                                                                                             // pop ecx
		file << VECTOR(0x5F);                                                                                             // pop edi
		file << VECTOR(0x8B, 0xE5);                                                                                       // mov esp, ebp
		file << VECTOR(0x5D);                                                                                             // pop ebp
		file << VECTOR(0xC2, 0x08, 0x00);                                                                                 // ret 0x8
#pragma endregion

#pragma region SHA256
		auto sha256 = file.getPos();
		/*
		* push output
		* push password
		* call func
		*/
		file << VECTOR(0x55);                                                                                             // push ebp
		file << VECTOR(0x8B, 0xEC);                                                                                       // mov ebp, esp
		file << VECTOR(0x83, 0xEC, 0x0C);                                                                                 // sub esp, 0xC
		file << VECTOR(0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00);                                                         // mov dword ptr ss:[ebp-0x8], 0x0
		file << VECTOR(0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00);                                                         // mov dword ptr ss:[ebp-0x4], 0x0
		file << VECTOR(0x64, 0x8B, 0x1D, 0x30, 0x00, 0x00, 0x00);                                                         // mov ebx, dword ptr fs:[0x00000030]
		file << VECTOR(0x8B, 0x5B, 0x08);                                                                                 // mov ebx, dword ptr ds:[ebx+0x8]

		file << VECTOR(0x68, 0x00, 0x00, 0x00, 0xF0);                                                                     // push 0xF0000000
		file << VECTOR(0x6A, 0x18);                                                                                       // push 0x18
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x8D, 0x45, 0xF8);                                                                                 // lea eax, ss:[ebp-0x8]
		file << VECTOR(0x50);                                                                                             // push eax
		file << VECTOR(0xFF, 0x93) << funcCryptAcquireContextA.rva;                                                       // call dword ptr ds:[ebx+funcCryptAcquireContextA.rva]

		file << VECTOR(0x8D, 0x4D, 0xFC);                                                                                 // lea ecx, ss:[ebp-0x4]
		file << VECTOR(0x51);                                                                                             // push ecx
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x68, 0x0C, 0x80, 0x00, 0x00);                                                                     // push 0x800C
		file << VECTOR(0x8B, 0x55, 0xF8);                                                                                 // mov edx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0x93) << funcCryptCreateHash.rva;                                                            // call dword ptr ds:[ebx+funcCryptCreateHash.rva]

		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x50);                                                                                             // push eax
		file << VECTOR(0xFF, 0x93) << funclstrlenA.rva;                                                                   // call dword ptr ds:[ebx+funclstrlenA.rva]

		file << VECTOR(0x50);                                                                                             // push eax
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x51);                                                                                             // push ecx
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0x93) << funcCryptHashData.rva;                                                              // call dword ptr ds:[ebx+funcCryptHashData.rva]

		file << VECTOR(0xC7, 0x45, 0xF4, 0x20, 0x00, 0x00, 0x00);                                                         // mov dword ptr ss:[ebp-0xC], 0x20
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x8D, 0x45, 0xF4);                                                                                 // lea eax, ss:[ebp-0xC]
		file << VECTOR(0x50);                                                                                             // push eax
		file << VECTOR(0x8B, 0x4D, 0x0C);                                                                                 // mov ecx, dword ptr ss:[ebp+0xC]
		file << VECTOR(0x51);                                                                                             // push ecx
		file << VECTOR(0x6A, 0x02);                                                                                       // push 0x2
		file << VECTOR(0x8B, 0x55, 0xFC);                                                                                 // mov edx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0x93) << funcCryptGetHashParam.rva;                                                          // call dword ptr ds:[ebx+funcCryptGetHashParam.rva]

		file << VECTOR(0x8B, 0x45, 0xFC);                                                                                 // mov eax, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x50);                                                                                             // push eax
		file << VECTOR(0xFF, 0x93) << funcCryptDestroyHash.rva;                                                           // call dword ptr ds:[ebx+funcCryptDestroyHash.rva]

		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0x51);                                                                                             // push ecx
		file << VECTOR(0xFF, 0x93) << funcCryptReleaseContext.rva;                                                        // call dword ptr ds:[ebx+funcCryptReleaseContext.rva]

		file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
		file << VECTOR(0x8B, 0xE5);                                                                                       // mov esp, ebp
		file << VECTOR(0x5D);                                                                                             // pop ebp
		file << VECTOR(0xC3);                                                                                             // ret
#pragma endregion

#pragma region RtlCompareMemory
		auto rtlCompareMemory = file.getPos();
		/*
		* push size
		* push buffer2
		* push buffer1
		* call func
		*/
		file << VECTOR(0x56);                                                                                             // push esi
		file << VECTOR(0x57);                                                                                             // push edi
		file << VECTOR(0xFC);                                                                                             // cld
		file << VECTOR(0x8B, 0x74, 0x24, 0x0C);                                                                           // mov esi, dword ptr ss:[esp+0xC]
		file << VECTOR(0x8B, 0x7C, 0x24, 0x10);                                                                           // mov edi, dword ptr ss:[esp+0x10]
		file << VECTOR(0x8B, 0x4C, 0x24, 0x14);                                                                           // mov ecx, dword ptr ss:[esp+0x14]
		file << VECTOR(0xC1, 0xE9, 0x02);                                                                                 // shr ecx, 0x2
		file << VECTOR(0x74, 0x04);                                                                                       // je 0x77248068
		file << VECTOR(0xF3, 0xA7);                                                                                       // repe cmpsd
		file << VECTOR(0x75, 0x16);                                                                                       // jne 0x7724807E
		file << VECTOR(0x8B, 0x4C, 0x24, 0x14);                                                                           // mov ecx, dword ptr ss:[esp+0x14]
		file << VECTOR(0x83, 0xE1, 0x03);                                                                                 // and ecx, 0x3
		file << VECTOR(0x74, 0x04);                                                                                       // je 0x77248075
		file << VECTOR(0xF3, 0xA6);                                                                                       // repe cmpsb
		file << VECTOR(0x75, 0x16);                                                                                       // jne 0x7724808B
		file << VECTOR(0x8B, 0x44, 0x24, 0x14);                                                                           // mov eax, dword ptr ss:[esp+0x14]
		file << VECTOR(0x5F);                                                                                             // pop edi
		file << VECTOR(0x5E);                                                                                             // pop esi
		file << VECTOR(0xC2, 0x0C, 0x00);                                                                                 // ret 0xC
		file << VECTOR(0x83, 0xEE, 0x04);                                                                                 // sub esi, 0x4
		file << VECTOR(0x83, 0xEF, 0x04);                                                                                 // sub edi, 0x4
		file << VECTOR(0xB9, 0x04, 0x00, 0x00, 0x00);                                                                     // mov ecx, 0x4
		file << VECTOR(0xF3, 0xA6);                                                                                       // repe cmpsb
		file << VECTOR(0x4E);                                                                                             // dec esi
		file << VECTOR(0x2B, 0x74, 0x24, 0x0C);                                                                           // sub esi, dword ptr ss:[esp+0xC]
		file << VECTOR(0x8B, 0xC6);                                                                                       // mov eax, esi
		file << VECTOR(0x5F);                                                                                             // pop edi
		file << VECTOR(0x5E);                                                                                             // pop esi
		file << VECTOR(0xC2, 0x0C, 0x00);                                                                                 // ret 0xC
#pragma endregion

#pragma region Check Password
		auto checkPassword = file.getPos();
		file << VECTOR(0x55);                                                                                             // push ebp
		file << VECTOR(0x8B, 0xEC);                                                                                       // mov ebp, esp
		file << VECTOR(0x8D, 0x93) << hashBuffer.rva;                                                                     // lea edx, ds:[ebx+hashBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x8D, 0x93) << pwBuffer.rva;                                                                       // lea edx, ds:[ebx+pwBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x8D, 0x93) << sha256.rva;                                                                         // lea edx, ds:[ebx+sha256.rva]
		file << VECTOR(0xFF, 0xD2);                                                                                       // call edx
		file << VECTOR(0x6A, 0x20);                                                                                       // push 0x20
		file << VECTOR(0x8D, 0x93) << hashBuffer.rva;                                                                     // lea edx, ds:[ebx+hashBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x8D, 0x93) << orgHashBuffer.rva;                                                                  // lea edx, ds:[ebx+orgHashBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x8D, 0x93) << rtlCompareMemory.rva;                                                               // lea edx, ds:[ebx+rtlCompareMemory.rva]
		file << VECTOR(0xFF, 0xD2);                                                                                       // call edx
		file << VECTOR(0x83, 0xF8, 0x20);                                                                                 // cmp eax, 0x20
		file << VECTOR(0x74, 0x06);                                                                                       // je label_true
		file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
		file << VECTOR(0x8B, 0xE5);                                                                                       // mov esp, ebp
		file << VECTOR(0x5D);                                                                                             // pop ebp
		file << VECTOR(0xC3);                                                                                             // ret
		// label_true:
		file << VECTOR(0x8D, 0x93) << pwBuffer.rva;                                                                       // lea edx, ds:[ebx+pwBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x8D, 0x93) << roundKeyBuffer.rva;                                                                 // lea edx, ds:[ebx+roundKeyBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x8D, 0x93) << seedKeySched.rva;                                                                   // lea edx, ds:[ebx+seedKeySched.rva]
		file << VECTOR(0xFF, 0xD2);                                                                                       // call edx
		file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
		file << VECTOR(0x40);                                                                                             // inc eax
		file << VECTOR(0x8B, 0xE5);                                                                                       // mov esp, ebp
		file << VECTOR(0x5D);                                                                                             // pop ebp
		file << VECTOR(0xC3);                                                                                             // ret
#pragma endregion

#pragma region Dialog Procedure
		// if the password is correct, the return value of EndDialog will be 0, otherwise 1.
		auto dialogProc = file.getPos();
		file << VECTOR(0x55);                                                                                             // push ebp
		file << VECTOR(0x8B, 0xEC);                                                                                       // mov ebp, esp
		file << VECTOR(0x64, 0x8B, 0x1D, 0x30, 0x00, 0x00, 0x00);                                                         // mov ebx, dword ptr fs:[0x00000030]
		file << VECTOR(0x8B, 0x5B, 0x08);                                                                                 // mov ebx, dword ptr ds:[ebx+0x8]
		file << VECTOR(0x81, 0x7D, 0x0C, 0x11, 0x01, 0x00, 0x00);                                                         // cmp dword ptr ss:[ebp+0xC], 0x111
		file << VECTOR(0x0F, 0x85, 0x81, 0x00, 0x00, 0x00);                                                               // jne label_else
		file << VECTOR(0x8B, 0x45, 0x10);                                                                                 // mov eax, dword ptr ss:[ebp+0x10]
		file << VECTOR(0x25, 0xFF, 0xFF, 0x00, 0x00);                                                                     // and eax, 0xFFFF
		file << VECTOR(0x0F, 0xB7, 0xC8);                                                                                 // movzx ecx, ax
		file << VECTOR(0x81, 0xF9, 0xE9, 0x03, 0x00, 0x00);                                                               // cmp ecx, 0x3E9
		file << VECTOR(0x75, 0x6C);                                                                                       // jne label_retn
		file << VECTOR(0x8B, 0x55, 0x10);                                                                                 // mov edx, dword ptr ss:[ebp+0x10]
		file << VECTOR(0xC1, 0xEA, 0x10);                                                                                 // shr edx, 0x10
		file << VECTOR(0x81, 0xE2, 0xFF, 0xFF, 0x00, 0x00);                                                               // and edx, 0xFFFF
		file << VECTOR(0x0F, 0xB7, 0xC2);                                                                                 // movzx eax, dx
		file << VECTOR(0x3D, 0x00, 0x03, 0x00, 0x00);                                                                     // cmp eax, 0x300
		file << VECTOR(0x75, 0x56);                                                                                       // jne label_retn
		file << VECTOR(0x6A, 0x10);                                                                                       // push 0x10
		file << VECTOR(0x8D, 0x93) << pwBuffer.rva;                                                                       // lea edx, ds:[ebx+pwBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x8D, 0x93) << zeroMemory.rva;                                                                     // lea edx, ds:[ebx+zeroMemory.rva]
		file << VECTOR(0xFF, 0xD2);                                                                                       // call edx
		file << VECTOR(0x68, 0x00, 0x01, 0x00, 0x00);                                                                     // push 0x100
		file << VECTOR(0x8D, 0x93) << pwBuffer.rva;                                                                       // lea edx, ds:[ebx+pwBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x68, 0xE9, 0x03, 0x00, 0x00);                                                                     // push 0x3E9
		file << VECTOR(0x8B, 0x4D, 0x08);                                                                                 // mov ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x51);                                                                                             // push ecx
		file << VECTOR(0xFF, 0x93) << funcGetDlgItemTextA.rva;                                                            // call dword ptr ds:[ebx+funcGetDlgItemTextA.rva]
		file << VECTOR(0x8D, 0x93) << pwBuffer.rva;                                                                       // lea edx, ds:[ebx+pwBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0x93) << funclstrlenA.rva;                                                                   // call dword ptr ds:[ebx+funclstrlenA.rva]
		file << VECTOR(0x83, 0xF8, 0x10);                                                                                 // cmp eax, 0x10
		file << VECTOR(0x7F, 0x18);                                                                                       // jg label_retn
		file << VECTOR(0x8D, 0x93) << checkPassword.rva;                                                                  // lea edx, ds:[ebx+checkPassword.rva]
		file << VECTOR(0xFF, 0xD2);                                                                                       // call edx
		file << VECTOR(0x85, 0xC0);                                                                                       // test eax, eax
		file << VECTOR(0x74, 0x0C);                                                                                       // je label_retn
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x8B, 0x55, 0x08);                                                                                 // mov edx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0x93) << funcEndDialog.rva;                                                                  // call dword ptr ds:[ebx+funcEndDialog.rva]
		// label_retn:
		file << VECTOR(0xEB, 0x12);                                                                                       // jmp label_exit
		// label_else:
		file << VECTOR(0x83, 0x7D, 0x0C, 0x10);                                                                           // cmp dword ptr ss:[ebp+0xC], 0x10
		file << VECTOR(0x75, 0x0C);                                                                                       // jne label_exit
		file << VECTOR(0x6A, 0x01);                                                                                       // push 0x1
		file << VECTOR(0x8B, 0x45, 0x08);                                                                                 // mov eax, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x50);                                                                                             // push eax
		file << VECTOR(0xFF, 0x93) << funcEndDialog.rva;                                                                  // call dword ptr ds:[ebx+funcEndDialog.rva]
		// label_exit:
		file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
		file << VECTOR(0x5D);                                                                                             // pop ebp
		file << VECTOR(0xC2, 0x10, 0x00);                                                                                 // ret 0x10
#pragma endregion

#pragma region Kernel32 Function
		auto kernel32Function = file.getPos();
		file << VECTOR(0x55);                                                                                             // push ebp
		file << VECTOR(0x8B, 0xEC);                                                                                       // mov ebp, esp
		file << VECTOR(0x83, 0xEC, 0x10);                                                                                 // sub esp, 0x10
		file << VECTOR(0x51);                                                                                             // push ecx
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x53);                                                                                             // push ebx
		file << VECTOR(0x56);                                                                                             // push esi
		file << VECTOR(0x57);                                                                                             // push edi
		file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x64, 0xA1, 0x30, 0x00, 0x00, 0x00);                                                               // mov eax, dword ptr fs:[0x00000030]
		file << VECTOR(0x8B, 0x40, 0x0C);                                                                                 // mov eax, dword ptr ds:[eax+0xC]
		file << VECTOR(0x8B, 0x40, 0x0C);                                                                                 // mov eax, dword ptr ds:[eax+0xC]
		file << VECTOR(0x8B, 0x00);                                                                                       // mov eax, dword ptr ds:[eax]
		file << VECTOR(0x8B, 0x00);                                                                                       // mov eax, dword ptr ds:[eax]
		file << VECTOR(0x8B, 0x40, 0x18);                                                                                 // mov eax, dword ptr ds:[eax+0x18]
		file << VECTOR(0x8B, 0x48, 0x3C);                                                                                 // mov ecx, dword ptr ds:[eax+0x3C]
		file << VECTOR(0x83, 0xC1, 0x78);                                                                                 // add ecx, 0x78
		file << VECTOR(0x8B, 0x14, 0x08);                                                                                 // mov edx, dword ptr ds:[eax+ecx*1]
		file << VECTOR(0x03, 0xD0);                                                                                       // add edx, eax
		file << VECTOR(0x33, 0xDB);                                                                                       // xor ebx, ebx
		file << VECTOR(0x83, 0xC2, 0x20);                                                                                 // add edx, 0x20
		file << VECTOR(0x8B, 0x1A);                                                                                       // mov ebx, dword ptr ds:[edx]
		file << VECTOR(0x03, 0xD8);                                                                                       // add ebx, eax
		file << VECTOR(0x8B, 0xF8);                                                                                       // mov edi, eax
		file << VECTOR(0x83, 0xC3, 0x04);                                                                                 // add ebx, 0x4
		file << VECTOR(0xFF, 0x45, 0xFC);                                                                                 // inc dword ptr ss:[ebp-0x4]
		file << VECTOR(0x8B, 0x33);                                                                                       // mov esi, dword ptr ds:[ebx]
		file << VECTOR(0x03, 0xF7);                                                                                       // add esi, edi
		file << VECTOR(0x33, 0xC9);                                                                                       // xor ecx, ecx
		file << VECTOR(0xB8, 0x20, 0x83, 0xB8, 0xED);                                                                     // mov eax, 0xEDB88320
		file << VECTOR(0x89, 0x45, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], eax
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
		file << VECTOR(0xAC);                                                                                             // lodsb
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xD1, 0xE1);                                                                                       // shl ecx, 0x1
		file << VECTOR(0x89, 0x4D, 0xF4);                                                                                 // mov dword ptr ss:[ebp-0xC], ecx
		file << VECTOR(0x8B, 0x4D, 0xF8);                                                                                 // mov ecx, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xC1, 0xE9, 0x1F);                                                                                 // shr ecx, 0x1F
		file << VECTOR(0x0B, 0x4D, 0xF4);                                                                                 // or ecx, dword ptr ss:[ebp-0xC]
		file << VECTOR(0x89, 0x4D, 0xF8);                                                                                 // mov dword ptr ss:[ebp-0x8], ecx
		file << VECTOR(0x8B, 0x4D, 0xF0);                                                                                 // mov ecx, dword ptr ss:[ebp-0x10]
		file << VECTOR(0x50);                                                                                             // push eax
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x8B, 0x45, 0xF8);                                                                                 // mov eax, dword ptr ss:[ebp-0x8]
		file << VECTOR(0xF7, 0xE1);                                                                                       // mul ecx
		file << VECTOR(0x8B, 0xC8);                                                                                       // mov ecx, eax
		file << VECTOR(0x5A);                                                                                             // pop edx
		file << VECTOR(0x58);                                                                                             // pop eax
		file << VECTOR(0x03, 0xC8);                                                                                       // add ecx, eax
		file << VECTOR(0x89, 0x4D, 0xF0);                                                                                 // mov dword ptr ss:[ebp-0x10], ecx
		file << VECTOR(0x84, 0xC0);                                                                                       // test al, al
		file << VECTOR(0x75, 0xD4);                                                                                       // jne 0x00E813AB
		file << VECTOR(0x3B, 0x4D, 0x08);                                                                                 // cmp ecx, dword ptr ss:[ebp+0x8]
		file << VECTOR(0x75, 0xB6);                                                                                       // jne 0x00E81392
		file << VECTOR(0x33, 0xDB);                                                                                       // xor ebx, ebx
		file << VECTOR(0x83, 0xC2, 0x04);                                                                                 // add edx, 0x4
		file << VECTOR(0x8B, 0x1A);                                                                                       // mov ebx, dword ptr ds:[edx]
		file << VECTOR(0x03, 0xDF);                                                                                       // add ebx, edi
		file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
		file << VECTOR(0xB0, 0x02);                                                                                       // mov al, 0x2
		file << VECTOR(0x8B, 0xF2);                                                                                       // mov esi, edx
		file << VECTOR(0x3E, 0x66, 0xF7, 0x65, 0xFC);                                                                     // mul word ptr ds:[ebp-0x4]
		file << VECTOR(0x89, 0x45, 0xFC);                                                                                 // mov dword ptr ss:[ebp-0x4], eax
		file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
		file << VECTOR(0x03, 0x5D, 0xFC);                                                                                 // add ebx, dword ptr ss:[ebp-0x4]
		file << VECTOR(0x66, 0x8B, 0x03);                                                                                 // mov ax, word ptr ds:[ebx]
		file << VECTOR(0x83, 0xEE, 0x08);                                                                                 // sub esi, 0x8
		file << VECTOR(0x8B, 0x0E);                                                                                       // mov ecx, dword ptr ds:[esi]
		file << VECTOR(0x03, 0xCF);                                                                                       // add ecx, edi
		file << VECTOR(0x33, 0xDB);                                                                                       // xor ebx, ebx
		file << VECTOR(0x8B, 0xD8);                                                                                       // mov ebx, eax
		file << VECTOR(0xB8, 0x04, 0x00, 0x00, 0x00);                                                                     // mov eax, 0x4
		file << VECTOR(0xF7, 0xE3);                                                                                       // mul ebx
		file << VECTOR(0x03, 0xC8);                                                                                       // add ecx, eax
		file << VECTOR(0x8B, 0x09);                                                                                       // mov ecx, dword ptr ds:[ecx]
		file << VECTOR(0x03, 0xCF);                                                                                       // add ecx, edi
		file << VECTOR(0x8B, 0xC1);                                                                                       // mov eax, ecx
		file << VECTOR(0x5F);                                                                                             // pop edi
		file << VECTOR(0x5E);                                                                                             // pop esi
		file << VECTOR(0x5B);                                                                                             // pop ebx
		file << VECTOR(0x5A);                                                                                             // pop edx
		file << VECTOR(0x59);                                                                                             // pop ecx
		file << VECTOR(0x8B, 0xE5);                                                                                       // mov esp, ebp
		file << VECTOR(0x5D);                                                                                             // pop ebp
		file << VECTOR(0xC2, 0x04, 0x00);                                                                                 // ret 0x4
#pragma endregion

#pragma region TLS Callback
		auto tlsCallback = file.getPos();
		if (file.TLSDirectory->VirtualAddress) {
			file << VECTOR(0x56);                                                                                             // push esi
			file << VECTOR(0x8D, 0xB3) << oldTLSDirectory.AddressOfCallBacks - *file.ImageBase;                               // lea esi, ds:[ebx+AddressOfCallBacks RVA]
			file << VECTOR(0xFC);                                                                                             // cld
			// label_get:
			file << VECTOR(0xAD);                                                                                             // lodsd
			file << VECTOR(0x85, 0xC0);                                                                                       // test eax, eax
			file << VECTOR(0x74, 0x0D);                                                                                       // je exit
			file << VECTOR(0x6A, 0x03);                                                                                       // push 0x3
			file << VECTOR(0x59);                                                                                             // pop ecx
			// label_loop:
			file << VECTOR(0xFF, 0x74, 0x24, 0x10);                                                                           // push dword ptr ss:[esp+0x10]
			file << VECTOR(0xE2, 0xFA);                                                                                       // loop label_loop
			file << VECTOR(0xFF, 0xD0);                                                                                       // call eax
			file << VECTOR(0xEB, 0xEE);                                                                                       // jmp label_get
			// exit:
			file << VECTOR(0x5E);                                                                                             // pop esi
			file << VECTOR(0xC2, 0x0C, 0x00);                                                                                 // ret 0xC
		}
#pragma endregion

#pragma endregion

#pragma region Entry Point
		auto entryPoint = file.getPos();

#pragma region Prologue
		file << VECTOR(0x60);                                                                                             // pushad
		file << VECTOR(0x64, 0x8B, 0x1D, 0x30, 0x00, 0x00, 0x00);                                                         // mov ebx, dword ptr fs:[0x00000030]
		file << VECTOR(0x8B, 0x5B, 0x08);                                                                                 // mov ebx, dword ptr ds:[ebx+0x8]
		file << VECTOR(0x8D, 0xAB) << kernel32Function.rva;                                                               // lea ebp, ds:[ebx+kernel32Function.rva]

		// To modify pe header
		file << VECTOR(0x68) << hashGenerate("VirtualProtect");                                                           // push "VirtualProtect" hash
		file << VECTOR(0xFF, 0xD5);                                                                                       // call ebp
		file << VECTOR(0x8D, 0x93) << dwordBuffer.rva;                                                                    // lea edx, ds:[ebx+dwordBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x6A, PAGE_EXECUTE_READWRITE);                                                                     // push PAGE_EXECUTE_READWRITE
		file << VECTOR(0x68) << oldSizeOfImage;                                                                           // push oldSizeOfImage
		file << VECTOR(0x53);                                                                                             // push ebx
		file << VECTOR(0xFF, 0xD0);                                                                                       // call eax
#pragma endregion

#pragma region Initialize variables
		// Get LoadLibraryA
		file << VECTOR(0x68) << hashGenerate("LoadLibraryA");                                                             // push "LoadLibraryA" hash
		file << VECTOR(0xFF, 0xD5);                                                                                       // call ebp
		file << VECTOR(0x89, 0x83) << funcLoadLibraryA.rva;                                                               // mov dword ptr ds:[ebx+funcLoadLibraryA.rva], eax

		// Get base address of user32.dll
		file << VECTOR(0x8D, 0x93) << szUser32.rva;                                                                       // lea edx, ds:[ebx+szUser32.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0x93) << funcLoadLibraryA.rva;                                                               // call dword ptr ds:[ebx+funcLoadLibraryA.rva]
		file << VECTOR(0x89, 0x83) << baseUser32.rva;                                                                     // mov dword ptr ds:[ebx+baseUser32.rva], eax

		// Get base address of advapi32.dll
		file << VECTOR(0x8D, 0x93) << szAdvapi32.rva;                                                                     // lea edx, ds:[ebx+szAdvapi32.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0x93) << funcLoadLibraryA.rva;                                                               // call dword ptr ds:[ebx+funcLoadLibraryA.rva]
		file << VECTOR(0x89, 0x83) << baseAdvapi32.rva;                                                                   // mov dword ptr ds:[ebx+baseAdvapi32.rva], eax

		// Get GetProcAddress
		file << VECTOR(0x68) << hashGenerate("GetProcAddress");                                                           // push "GetProcAddress" hash
		file << VECTOR(0xFF, 0xD5);                                                                                       // call ebp
		file << VECTOR(0x89, 0x83) << funcGetProcAddress.rva;                                                             // mov dword ptr ds:[ebx+funcGetProcAddress.rva], eax

		// Get DialogBoxIndirectParamA
		file << VECTOR(0x8D, 0x93) << szDialogBoxIndirectParamA.rva;                                                      // lea edx, ds:[ebx+szDialogBoxIndirectParamA.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseUser32.rva;                                                                     // push dword ptr ds:[ebx+baseUser32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcDialogBoxIndirectParamA.rva;                                                    // mov dword ptr ds:[ebx+funcDialogBoxIndirectParamA.rva], eax

		// Get GetDlgItemTextA
		file << VECTOR(0x8D, 0x93) << szGetDlgItemTextA.rva;                                                              // lea edx, ds:[ebx+szGetDlgItemTextA.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseUser32.rva;                                                                     // push dword ptr ds:[ebx+baseUser32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcGetDlgItemTextA.rva;                                                            // mov dword ptr ds:[ebx+funcGetDlgItemTextA.rva], eax

		// Get EndDialog
		file << VECTOR(0x8D, 0x93) << szEndDialog.rva;                                                                    // lea edx, ds:[ebx+szEndDialog.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseUser32.rva;                                                                     // push dword ptr ds:[ebx+baseUser32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcEndDialog.rva;                                                                  // mov dword ptr ds:[ebx+funcEndDialog.rva], eax

		// Get lstrlenA
		file << VECTOR(0x68) << hashGenerate("lstrlenA");                                                                 // push "lstrlenA" hash
		file << VECTOR(0xFF, 0xD5);                                                                                       // call ebp
		file << VECTOR(0x89, 0x83) << funclstrlenA.rva;                                                                   // mov dword ptr ds:[ebx+funclstrlenA.rva], eax

		// Get lstrcmpA
		file << VECTOR(0x68) << hashGenerate("lstrcmpA");                                                                 // push "lstrcmpA" hash
		file << VECTOR(0xFF, 0xD5);                                                                                       // call ebp
		file << VECTOR(0x89, 0x83) << funclstrcmpA.rva;                                                                   // mov dword ptr ds:[ebx+funclstrcmpA.rva], eax

		// Get CryptAcquireContextA
		file << VECTOR(0x8D, 0x93) << szCryptAcquireContextA.rva;                                                         // lea edx, ds:[ebx+szCryptAcquireContextA.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseAdvapi32.rva;                                                                   // push dword ptr ds:[ebx+baseAdvapi32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcCryptAcquireContextA.rva;                                                       // mov dword ptr ds:[ebx+funcCryptAcquireContextA.rva], eax

		// Get CryptCreateHash
		file << VECTOR(0x8D, 0x93) << szCryptCreateHash.rva;                                                              // lea edx, ds:[ebx+szCryptCreateHash.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseAdvapi32.rva;                                                                   // push dword ptr ds:[ebx+baseAdvapi32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcCryptCreateHash.rva;                                                            // mov dword ptr ds:[ebx+funcCryptCreateHash.rva], eax

		// Get CryptDestroyHash
		file << VECTOR(0x8D, 0x93) << szCryptDestroyHash.rva;                                                             // lea edx, ds:[ebx+szCryptDestroyHash.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseAdvapi32.rva;                                                                   // push dword ptr ds:[ebx+baseAdvapi32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcCryptDestroyHash.rva;                                                           // mov dword ptr ds:[ebx+funcCryptDestroyHash.rva], eax

		// Get CryptReleaseContext
		file << VECTOR(0x8D, 0x93) << szCryptReleaseContext.rva;                                                          // lea edx, ds:[ebx+szCryptReleaseContext.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseAdvapi32.rva;                                                                   // push dword ptr ds:[ebx+baseAdvapi32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcCryptReleaseContext.rva;                                                        // mov dword ptr ds:[ebx+funcCryptReleaseContext.rva], eax

		// Get CryptGetHashParam
		file << VECTOR(0x8D, 0x93) << szCryptGetHashParam.rva;                                                            // lea edx, ds:[ebx+szCryptGetHashParam.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseAdvapi32.rva;                                                                   // push dword ptr ds:[ebx+baseAdvapi32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcCryptGetHashParam.rva;                                                          // mov dword ptr ds:[ebx+funcCryptGetHashParam.rva], eax

		// Get CryptHashData
		file << VECTOR(0x8D, 0x93) << szCryptHashData.rva;                                                                // lea edx, ds:[ebx+szCryptHashData.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0xFF, 0xB3) << baseAdvapi32.rva;                                                                   // push dword ptr ds:[ebx+baseAdvapi32.rva]
		file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
		file << VECTOR(0x89, 0x83) << funcCryptHashData.rva;                                                              // mov dword ptr ds:[ebx+funcCryptHashData.rva], eax

#pragma endregion

#pragma region Show password dialog
		// Show dialog
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x8D, 0x93) << dialogProc.rva;                                                                     // lea edx, ds:[ebx+dialogProc.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0x8D, 0x93) << dialogTemplate.rva;                                                                 // lea edx, ds:[ebx+dialogTemplate.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x53);                                                                                             // push ebx
		file << VECTOR(0xFF, 0x93) << funcDialogBoxIndirectParamA.rva;                                                    // call dword ptr ds:[ebx+funcDialogBoxIndirectParamA.rva]
#pragma endregion

#pragma region Decrypt sections
		// check eax. if eax is 1, dialog was closed by the user so exit process.
		// if eax is 0, the password is correct so decrypt binary using generated round key.

		file << VECTOR(0x85, 0xC0);                                                                                       // test eax, eax
		file << VECTOR(0x74, 0x0B);                                                                                       // je label_decrypt
		file << VECTOR(0x68) << hashGenerate("ExitProcess");                                                              // push "ExitProcess" hash
		file << VECTOR(0xFF, 0xD5);                                                                                       // call ebp
		file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
		file << VECTOR(0xFF, 0xD0);                                                                                       // call eax
		// label_decrypt:
		file << VECTOR(0x8D, 0x8B) << sectionAddrBuffer.rva;                                                              // lea ecx, ds:[ebx+sectionAddrBuffer.rva]
		// loop:
		file << VECTOR(0x8B, 0x31);                                                                                       // mov esi, dword ptr ds:[ecx]
		file << VECTOR(0x85, 0xF6);                                                                                       // test esi, esi
		file << VECTOR(0x74, 0x25);                                                                                       // je end
		file << VECTOR(0x8B, 0x79, 0x04);                                                                                 // mov edi, dword ptr ds:[ecx+0x4]
		file << VECTOR(0x03, 0xF3);                                                                                       // add esi, ebx
		file << VECTOR(0x03, 0xFB);                                                                                       // add edi, ebx
		// loop2:
		file << VECTOR(0x3B, 0xF7);                                                                                       // cmp esi, edi
		file << VECTOR(0x7C, 0x15);                                                                                       // jl next
		file << VECTOR(0x51);                                                                                             // push ecx
		file << VECTOR(0x8D, 0x93) << roundKeyBuffer.rva;                                                                 // lea edx, ds:[ebx+roundKeyBuffer.rva]
		file << VECTOR(0x52);                                                                                             // push edx
		file << VECTOR(0x56);                                                                                             // push esi
		file << VECTOR(0x8D, 0x93) << seedDecrypt.rva;                                                                    // lea edx, ds:[ebx+seedDecrypt.rva]
		file << VECTOR(0xFF, 0xD2);                                                                                       // call edx
		file << VECTOR(0x59);                                                                                             // pop ecx
		file << VECTOR(0x4E);                                                                                             // dec esi
		file << VECTOR(0xEB, 0xE7);                                                                                       // jmp loop2
		// next:
		file << VECTOR(0x83, 0xC1, 0x08);                                                                                 // add ecx, 0x8
		file << VECTOR(0xEB, 0xD5);                                                                                       // jmp loop
		// end:
#pragma endregion

#pragma region Recover PE Header
		// Recover import directory
		if (file.ImportDirectory->VirtualAddress) {
			file << VECTOR(0x8D, 0xB3) << file.ImportDirectory->VirtualAddress;                                               // lea esi, ds:[ebx+ImportDirectoryRVA]
			// loop1:
			file << VECTOR(0x8B, 0x46, 0x0C);                                                                                 // mov eax, dword ptr ds:[esi+0xC]
			file << VECTOR(0x85, 0xC0);                                                                                       // test eax, eax
			file << VECTOR(0x74, 0x42);                                                                                       // je end
			file << VECTOR(0x03, 0xC3);                                                                                       // add eax, ebx
			file << VECTOR(0x50);                                                                                             // push eax
			file << VECTOR(0xFF, 0x93) << funcLoadLibraryA.rva;                                                               // call dword ptr ds:[ebx+funcLoadLibraryA.rva]
			file << VECTOR(0x8B, 0xF8);                                                                                       // mov edi, eax
			file << VECTOR(0x8B, 0x4E, 0x10);                                                                                 // mov ecx, dword ptr ds:[esi+0x10]
			file << VECTOR(0x03, 0xCB);                                                                                       // add ecx, ebx
			// loop2:
			file << VECTOR(0x8B, 0x11);                                                                                       // mov edx, dword ptr ds:[ecx]
			file << VECTOR(0x85, 0xD2);                                                                                       // test edx, edx
			file << VECTOR(0x74, 0x27);                                                                                       // je next
			file << VECTOR(0x8B, 0xC2);                                                                                       // mov eax, edx
			file << VECTOR(0xA9, 0x00, 0x00, 0x00, 0x80);                                                                     // test eax, 0x80000000
			file << VECTOR(0x75, 0x07);                                                                                       // jne ordinal
			file << VECTOR(0x03, 0xD3);                                                                                       // add edx, ebx
			file << VECTOR(0x83, 0xC2, 0x02);                                                                                 // add edx, 0x2
			file << VECTOR(0xEB, 0x06);                                                                                       // jmp get_addr
			// ordinal:
			file << VECTOR(0x81, 0xF2, 0x00, 0x00, 0x00, 0x80);                                                               // xor edx, 0x80000000
			//get_addr:
			file << VECTOR(0x51);                                                                                             // push ecx
			file << VECTOR(0x52);                                                                                             // push edx
			file << VECTOR(0x57);                                                                                             // push edi
			file << VECTOR(0xFF, 0x93) << funcGetProcAddress.rva;                                                             // call dword ptr ds:[ebx+funcGetProcAddress.rva]
			file << VECTOR(0x59);                                                                                             // pop ecx
			file << VECTOR(0x89, 0x01);                                                                                       // mov dword ptr ds:[ecx], eax
			file << VECTOR(0x83, 0xC1, 0x04);                                                                                 // add ecx, 0x4
			file << VECTOR(0xEB, 0xD3);                                                                                       // jmp loop2
			// next:
			file << VECTOR(0x83, 0xC6, 0x14);                                                                                 // add esi, 0x14
			file << VECTOR(0xEB, 0xB7);                                                                                       // jmp loop1
			// end:
			file << VECTOR(0xC7, 0x83) << (DWORD)((BYTE*)file.ImportDirectory - file.data()) << file.ImportDirectory->VirtualAddress;  // mov dword ptr ds:[ebx+ImportDirectoryRVA offset], ImportDirectoryRVA
			file << VECTOR(0xC7, 0x83) << (DWORD)((BYTE*)file.ImportDirectory - file.data()) + 4 << file.ImportDirectory->Size;        // mov dword ptr ds:[ebx+ImportDirectorySize offset], ImportDirectorySize
		}

		// Recover relocation directory
		if (*file.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE && oldRelocationDirectory.rva) {
			file << VECTOR(0xBF) << *file.ImageBase;                                                                          // mov edi, ImageBase
			file << VECTOR(0x8D, 0xB3) << oldRelocationDirectory.rva;                                                         // lea esi, ds:[ebx+oldRelocationDirectory.rva]
			// loop1:
			file << VECTOR(0x8B, 0x16);                                                                                       // mov edx, dword ptr ds:[esi]
			file << VECTOR(0x85, 0xD2);                                                                                       // test edx, edx
			file << VECTOR(0x74, 0x2B);                                                                                       // je end
			file << VECTOR(0x8B, 0x4E, 0x04);                                                                                 // mov ecx, dword ptr ds:[esi+0x4]
			file << VECTOR(0x83, 0xE9, 0x08);                                                                                 // sub ecx, 0x8
			file << VECTOR(0x83, 0xC6, 0x08);                                                                                 // add esi, 0x8
			// loop2:
			file << VECTOR(0x85, 0xC9);                                                                                       // test ecx, ecx
			file << VECTOR(0x74, 0xED);                                                                                       // je loop1
			file << VECTOR(0x33, 0xC0);                                                                                       // xor eax, eax
			file << VECTOR(0x66, 0x8B, 0x06);                                                                                 // mov ax, word ptr ds:[esi]
			file << VECTOR(0x66, 0x85, 0xC0);                                                                                 // test ax, ax
			file << VECTOR(0x74, 0x0C);                                                                                       // je next
			file << VECTOR(0x66, 0x25, 0xFF, 0x0F);                                                                           // and ax, 0xFFF
			file << VECTOR(0x03, 0xC2);                                                                                       // add eax, edx
			file << VECTOR(0x03, 0xC3);                                                                                       // add eax, ebx
			file << VECTOR(0x29, 0x38);                                                                                       // sub dword ptr ds:[eax], edi
			file << VECTOR(0x01, 0x18);                                                                                       // add dword ptr ds:[eax], ebx
			// next:
			file << VECTOR(0x83, 0xC6, 0x02);                                                                                 // add esi, 0x2
			file << VECTOR(0x83, 0xE9, 0x02);                                                                                 // sub ecx, 0x2
			file << VECTOR(0xEB, 0xDE);                                                                                       // jmp 0x004F1D40
			// end:
		}

		// Recover TLS directory
		if (file.TLSDirectory->VirtualAddress) {
			file << VECTOR(0x6A, 0x00);                                                                                       // push 0x0
			file << VECTOR(0x6A, 0x01);                                                                                       // push 0x1
			file << VECTOR(0x53);                                                                                             // push ebx
			file << VECTOR(0x8D, 0x93) << tlsCallback.rva;                                                                    // lea edx, ds:[ebx+tlsCallback.rva]
			file << VECTOR(0xFF, 0xD2);                                                                                       // call edx
		}
#pragma endregion

#pragma region Epilogue
		file << VECTOR(0x8D, 0x93) << *file.AddressOfEntryPoint;                                                          // lea edx, ds:[ebx+OEP.rva]
		file << VECTOR(0x89, 0x54, 0x24, 0x1C);                                                                           // mov dword ptr ss:[esp+0x1C], edx
		file << VECTOR(0x61);                                                                                             // popad
		file << VECTOR(0xFF, 0x64, 0x24, 0xFC);                                                                           // jmp dword ptr ss:[esp-0x4]
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
