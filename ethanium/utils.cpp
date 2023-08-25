#include <global.h>


namespace Utils {
    bool IsFileExists(const char* absfilepath) {
        struct stat sbuff {};
        int i = stat(absfilepath, &sbuff);
        return (!i || errno == EOVERFLOW);
    }

    std::string SplitDot(size_t n) {
        std::string sn = std::to_string(n);
        size_t stsn = sn.length();

        for (int i = (int)stsn - 3; i > 0; i -= 3) {
            sn.insert(i, ".");
        }

        return sn;
    }
}