#pragma once
#include "PEBase.h"

namespace pe32 {
	class PERelocation {
	public:
		PERelocation(PEFile& file);
		void push_rva(DWORD rva);
		void push_data(DWORD rva);
		void build();

	private:
		PEFile& _file;
		std::vector<std::pair<DWORD, std::vector<WORD>>> _data;
	};
}