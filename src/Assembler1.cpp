#include "Assembler1.h"

Assembler1::Assembler1(std::string asmScript)
{
	script = asmScript;
}


std::string Assembler1::ReplaceAll(std::string str, const std::string& from, const std::string& to) {
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
	return str;
}

bool Assembler1::build() {
	std::map<std::string, fun>::iterator iter;
	for (iter = functionMap.begin(); iter != functionMap.end(); iter++) {
	
		std::regex re(iter->first + R"(.*\))");
		std::smatch match;
		while (std::regex_search(script, match, re)) {
			std::string funName(match.str());
			std::smatch match2;

			std::regex re(R"(("+).*")");
			std::regex_search(funName, match2, re);

			std::string ar(
				funName.begin() + match2.position() + 1,
				funName.begin() + match2.position() + match2.length() - 1);

			uint32_t val = iter->second(ar);
			script.erase(
				script.begin() + match.position(),
				script.begin() + match.position() + match.length());
			script.insert(match.position(), std::to_string(val));
		}
	}

	Environment environment;
	environment.init(Environment::kArchX86);

	CodeHolder code;
	Error error = code.init(environment, 0);
	if (error) {
		buildError = error;
		return false;
	}

	x86::Assembler a(&code);
	AsmParser p(&a);

	error = p.parse(script.c_str());
	if (error) {
		buildError = error;
		return false;
	}

	CodeBuffer& buffer = code.sectionById(0)->buffer();
	binary = std::vector<uint8_t>(buffer.data(), buffer.data() + buffer.size());
	return true;
}

std::vector<uint8_t> Assembler1::getVector() {
	return binary;
}

bool Assembler1::error() {
	return buildError;
}

std::string Assembler1::getBuildScript() {
	std::map<std::string, fun>::iterator iter;

	for (iter = functionMap.begin(); iter != functionMap.end(); iter++) {
		std::regex re(iter->first + R"(.*\))");
		std::smatch match;
		while (std::regex_search(script, match, re)) {
			std::string funName(match.str());
			std::smatch match2;

			std::regex re(R"(("+).*")");
			std::regex_search(funName, match2, re);

			std::string ar(
				funName.begin() + match2.position() + 1,
				funName.begin() + match2.position() + match2.length() - 1);

			uint32_t val = iter->second(ar);
			script.erase(
				script.begin() + match.position(),
				script.begin() + match.position() + match.length());
			script.insert(match.position(), std::to_string(val));
		}

	}
	return script;
}