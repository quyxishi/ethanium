#include <global.h>

#include <cli.h>

namespace cli {
#ifndef LOG_PREFIXES
#define LOG_PREFIXES

	const char* notice_prefix = "[*] ";
	const char* warn_prefix = "[!] warning: ";
	const char* error_prefix = "[x] error: ";

#endif

	void notice(const char* msg, const char* add, char end, char sep) {
		std::cout << notice_prefix << msg << (strlen(add) ? sep : '\0') << add << end << std::flush;
	}

	void notice(std::string msg, std::string add, char end, char sep) {
		std::cout << notice_prefix << msg << (strlen(add.c_str()) ? sep : '\0') << add << end << std::flush;
	}

	void warn(const char* msg, const char* add, char end, char sep) {
		std::cout << warn_prefix << msg << (strlen(add) ? sep : '\0') << add << end << std::flush;
	}

	void warn(std::string msg, std::string add, char end, char sep) {
		std::cout << warn_prefix << msg << (strlen(add.c_str()) ? sep : '\0') << add << end << std::flush;
	}

	void error(const char* msg, const char* add, char end, char sep) {
		std::cout << error_prefix << msg << (strlen(add) ? sep : '\0') << add << end << std::flush;
	}

	void error(std::string msg, std::string add, char end, char sep) {
		std::cout << error_prefix << msg << (strlen(add.c_str()) ? sep : '\0') << add << end << std::flush;
	}
}