#pragma once

#define ASMJIT_EMBED
#include <asmjit/asmjit.h>
#include <asmtk/asmtk.h>
using namespace asmjit;
using namespace asmtk;

#include <string>
#include <vector>
#include <Windows.h>
#include <algorithm>
#include <map>
#include <regex>

class Assembler1
{
public:
	Assembler1(std::string asmScript);

	template <typename T>
	Assembler1& setSymbol(std::string name, T value) {
		script = ReplaceAll(script, name, std::to_string(value));
		return *this;
	}

	typedef uint32_t (*fun)(std::string);
	Assembler1& setFunction(std::string name, fun value) {
		functionMap.insert(std::pair<std::string, fun>(name, value));
		//script = ReplaceAll(script, name, std::to_string(value));
		return *this;
	}

	std::string getBuildScript();
	std::vector<uint8_t> getVector();
	
	bool build();
	bool error();

private:
	std::string ReplaceAll(std::string str, const std::string& from, const std::string& to);
	std::map<std::string, fun> functionMap;
	std::vector<uint8_t> binary;
	Error buildError;
	std::string script;
};
