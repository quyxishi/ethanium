#pragma once

#include <global.h>


namespace Utils {
    bool IsFileExists(const char* absfilepath);
    std::string SplitDot(size_t n);
}