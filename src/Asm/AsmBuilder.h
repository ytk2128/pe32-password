#pragma once

#include <asmjit/asmjit.h>
#include <asmtk/asmtk.h>

#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <regex>

class AsmBuilder {
public:
	AsmBuilder(std::string asmScript);

	template <typename T>
	AsmBuilder& setSymbol(std::string name, T value) {
		script = ReplaceAll(script, name, std::to_string(value));
		return *this;
	}

	typedef uint32_t(*fun)(std::string);
	AsmBuilder& setFunction(std::string name, fun value) {
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
	asmtk::Error buildError;
	std::string script;
};
