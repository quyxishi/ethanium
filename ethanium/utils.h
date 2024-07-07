#pragma once

#include <global.h>

namespace Utils {
	bool IsFileExists(const char* abs_file_path);
	std::string SplitDot(size_t n);
	std::string PasswordPrompt();
}