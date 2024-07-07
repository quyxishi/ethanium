#pragma once

#include <global.h>

namespace cli {
	extern const char* notice_prefix;
	extern const char* warn_prefix;
	extern const char* error_prefix;

	void notice(const char* msg, const char* add = "", char end = '\n', char sep = ' ');
	void notice(std::string msg, std::string add = "", char end = '\n', char sep = ' ');

	void warn(const char* msg, const char* add = "", char end = '\n', char sep = ' ');
	void warn(std::string msg, std::string add = "", char end = '\n', char sep = ' ');

	void error(const char* msg, const char* add = "", char end = '\n', char sep = ' ');
	void error(std::string msg, std::string add = "", char end = '\n', char sep = ' ');
}
