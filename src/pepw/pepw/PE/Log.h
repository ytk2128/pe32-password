#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <ctime>
#include <cstdarg>

namespace pe32 {
	class Log {
	public:
		Log()
			: _logs()
		{}

		void add(const char* format, ...) {
			time_t t;
			struct tm lt;
			time(&t);
			localtime_s(&lt, &t);

			char time[80] = {};
			std::strftime(time, 80, "%m/%d/%Y %H:%M:%S", &lt);

			char log[1024] = {};
			va_list aptr;
			va_start(aptr, format);
			vsnprintf(log, 1024, format, aptr);
			va_end(aptr);

			std::ostringstream line;
			line << "[" << time << "] " << log;
			_logs.push_back(line.str().c_str());
		}

		std::string getLogs() const {
			std::ostringstream logs;
			for (auto& i : _logs) {
				logs << i << std::endl;
			}
			return logs.str();
		}

		void print(bool all = false) {
			if (all) {
				std::cout << getLogs() << std::endl;
			}
			else {
				std::cout << _logs.back() << std::endl;
			}
		}

	private:
		std::vector<std::string> _logs;
	};
}