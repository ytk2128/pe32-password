#pragma once
#include <iostream>
#include <string>

namespace pe32 {
	class Exception {
	public:
		explicit Exception(const std::string& cls, const std::string& con)
			: _class(cls.c_str())
			, _content(con.c_str())
		{}

		std::string get() const {
			return "<Exception occurred   " + _class + " - " + _content + ">";
		}

	private:
		std::string _class;
		std::string _content;
	};
}