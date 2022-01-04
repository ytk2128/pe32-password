#pragma once
#include <tuple>
#include "PEBase.h"

namespace pe32 {
	class PEResource {
	public:
		PEResource(PEFile& file);
		void push_entry(DWORD name);
		void push_data(DWORD id, DWORD name, BYTE* data, std::size_t size);
		void build();
		std::size_t size() const;

	private:


	private:
		using ResourceEntry = std::vector<std::tuple<DWORD, DWORD, std::vector<BYTE>>>;
		using ResourceData = std::pair<DWORD, ResourceEntry>;
		PEFile& _file;
		std::vector<ResourceData> _rData;
		std::size_t _baseDirSize;
		std::size_t _subDirSize;
		std::size_t _finalDirSize;
		std::size_t _dataEntrySize;
		std::size_t _dataSize;
	};
}