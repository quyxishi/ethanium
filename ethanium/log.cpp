#include <global.h>

#include <log.h>


namespace logc {
#ifndef LOG_PREFIXES
#define LOG_PREFIXES

	const char* noticeprefix = "[*] ";
	const char* warnprefix = "[!] warning: ";
	const char* errorprefix = "[x] error: ";

#endif

	void notice(const char* msg, const char* add, char end, char sep) {
		std::cout << noticeprefix << msg << (strlen(add) ? sep : '\0') << add << end << std::flush;
	}

	void notice(std::string msg, std::string add, char end, char sep) {
		std::cout << noticeprefix << msg << (strlen(add.c_str()) ? sep : '\0') << add << end << std::flush;
	}


	void warn(const char* msg, const char* add, char end, char sep) {
		std::cout << warnprefix << msg << (strlen(add) ? sep : '\0') << add << end << std::flush;
	}

	void warn(std::string msg, std::string add, char end, char sep) {
		std::cout << warnprefix << msg << (strlen(add.c_str()) ? sep : '\0') << add << end << std::flush;
	}


	void error(const char* msg, const char* add, char end, char sep) {
		std::cout << errorprefix << msg << (strlen(add) ? sep : '\0') << add << end << std::flush;
	}

	void error(std::string msg, std::string add, char end, char sep) {
		std::cout << errorprefix << msg << (strlen(add.c_str()) ? sep : '\0') << add << end << std::flush;
	}
}