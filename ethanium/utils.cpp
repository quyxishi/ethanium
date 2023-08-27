#include <global.h>


constexpr auto CONTROLC_ASCII = 3;
constexpr auto BACKSPACE_ASCII = 8;
constexpr auto RETURN_ASCII = 13;

namespace Utils {
    bool IsFileExists(const char* absfilepath) {
        struct stat sbuff {};
        return (!stat(absfilepath, &sbuff) || errno == EOVERFLOW);
    }

    std::string SplitDot(size_t n) {
        std::string sn = std::to_string(n);
        size_t stsn = sn.length();

        for (int i = (int)stsn - 3; i > 0; i -= 3) {
            sn.insert(i, ".");
        }

        return sn;
    }

    std::string PasswordPrompt() {
        std::string passwd = "";
        int cpasswd;

        while (true) {
            cpasswd = _getch();

            if (cpasswd == RETURN_ASCII) {
                break;
            }

            if (cpasswd == CONTROLC_ASCII) {
                passwd = "";
                break;
            }

            if (cpasswd == BACKSPACE_ASCII) {
                if (passwd.length())
                    passwd.pop_back();

                continue;
            }

            if (cpasswd < 32 || cpasswd > 126)
                continue;

            passwd.push_back((char)cpasswd);
        }

        std::cout << std::endl;

        return passwd;
    }
}