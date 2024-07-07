#include <global.h>

constexpr auto CONTROLC_ASCII = 3;
constexpr auto BACKSPACE_ASCII = 8;
constexpr auto RETURN_ASCII = 13;

namespace Utils {
	bool IsFileExists(const char* file_path) {
		struct stat sbuff {};
		return (!stat(file_path, &sbuff) || errno == EOVERFLOW);
	}

	std::string SplitDot(size_t n) {
		std::string str_n = std::to_string(n);

		for (int i = (int)str_n.length() - 3; i > 0; i -= 3) {
			str_n.insert(i, ".");
		}

		return str_n;
	}

	std::string PasswordPrompt() {
		std::string password = "";
		int password_char;

		while (true) {
			password_char = _getch();

			if (password_char < 32 || password_char > 126) {
				if (password_char == BACKSPACE_ASCII && password.length())
					password.pop_back();

				if (password_char == RETURN_ASCII) {
					break;
				}

				if (password_char == CONTROLC_ASCII) {
					password = "";
					break;
				}

				continue;
			}

			password.push_back((char)password_char);
		}

		std::cout << std::endl;

		return password;
	}
}