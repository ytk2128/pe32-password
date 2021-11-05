#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <Windows.h>

#define VECTOR(...) std::vector<BYTE>({__VA_ARGS__})

namespace pe32 {
	class addr {
	public:
		DWORD raw;
		DWORD rva;
		DWORD va;

		addr() = default;
		addr(DWORD _raw, DWORD _rva, DWORD _va);

		void reset();
		void reset(addr& address);
		void reset(DWORD _raw, DWORD _rva, DWORD _va);

		addr operator+(std::size_t rhs);
		addr operator-(std::size_t rhs);
		addr& operator+=(std::size_t rhs);
		addr& operator-=(std::size_t rhs);
		bool operator==(addr& rhs) const;
		bool operator!=(addr& rhs) const;
	};

	class PEHeader {
	public:
		PIMAGE_DOS_HEADER pDosHeader;
		PIMAGE_NT_HEADERS pNtHeader;
		PIMAGE_SECTION_HEADER pSecHeader;

		PIMAGE_DATA_DIRECTORY ExportDirectory;
		PIMAGE_DATA_DIRECTORY ImportDirectory;
		PIMAGE_DATA_DIRECTORY ResourceDirectory;
		PIMAGE_DATA_DIRECTORY SecurityDirectory;
		PIMAGE_DATA_DIRECTORY RelocationDirectory;
		PIMAGE_DATA_DIRECTORY DebugDirectory;
		PIMAGE_DATA_DIRECTORY TLSDirectory;
		PIMAGE_DATA_DIRECTORY ConfigurationDirectory;
		PIMAGE_DATA_DIRECTORY BoundImportDirectory;
		PIMAGE_DATA_DIRECTORY ImportAddressTableDirectory;
		PIMAGE_DATA_DIRECTORY DelayImportDirectory;
		PIMAGE_DATA_DIRECTORY NetMetaDataDirectory;

		PWORD NumberOfSections;
		PDWORD ImageBase;
		PDWORD SizeOfImage;
		PDWORD SizeOfHeaders;
		PDWORD FileAlignment;
		PDWORD SectionAlignment;
		PDWORD AddressOfEntryPoint;
		PWORD DllCharacteristics;

		//PEHeader() = default;
		virtual ~PEHeader();
		bool isValidHeader() const;
	};

	class PEFile : public PEHeader {
	public:
		PEFile();
		explicit PEFile(const std::string& fileName);
		explicit PEFile(const std::size_t fileSize);
		~PEFile();

		bool open(const std::string& fileName);
		bool create(const std::size_t fileSize);
		bool save(const std::string& fileName);

		BYTE* data();
		void resize(const std::size_t newSize);
		std::size_t getFileSize() const;
		void setFileSize(const std::size_t fileSize);
		std::string getFileName() const;

		/* Converting Addresses */
		DWORD rvaToRaw(DWORD rva) const;
		DWORD rawToRva(DWORD raw) const;
		DWORD rvaToSectionIdx(DWORD rva) const;
		DWORD rawToSectionIdx(DWORD raw) const;
		addr rvaToAddr(DWORD rva) const;
		addr rawToAddr(DWORD raw) const;
		addr vaToAddr(DWORD va) const;

		std::size_t getVirtualImageSize() const;
		std::size_t getRawImageSize() const;

		IMAGE_SECTION_HEADER& getFirstSection() const;
		IMAGE_SECTION_HEADER& getLastSection() const;
		IMAGE_SECTION_HEADER& createNewSection(const std::string& name, const std::size_t size, DWORD chr);

		void setPos(DWORD raw);
		addr getPos();

	private:
		void setPEHeaders();

	public:
		DWORD align(DWORD x, DWORD align) const;

	public:
		PEFile& operator<<(const std::vector<BYTE>& bytes);
		PEFile& operator<<(const std::string& str);
		PEFile& operator<<(const WORD w);
		PEFile& operator<<(const DWORD dw);
		PEFile& operator+=(const std::size_t size);

		void copyMemory(const void* src, std::size_t size);

	private:
		std::vector<BYTE> _mem;
		std::size_t _ptr;
		std::string _fileName;
		std::size_t _fileSize;
		mutable addr _retn;
	};
}