#include <global.h>

#include <args.h>
#include <utils.h>
#include <ciphers/xchachapoly.h>

int main(int argc, char* argv[]) {
	ArgsParser args_parser;

	if (!args_parser.StructArgs(argc, argv)) {
		return -1;
	}

	ETHANIUM_ARGS args = args_parser.GetArgs();

	if (args.help) {
		std::cout << ETHANIUM_HELP << std::endl;
		return 0;
	}

	cli::notice(std::string("@ ethanium ") + ETHANIUM_VERSION);

	// *

	std::vector<std::string> files;

	const char* file_path;
	char abs_file_path[MAX_PATH]{};

	for (size_t i = 0; i < args.files_count; i++) {
		file_path = args.files[i];

		if (!Utils::IsFileExists(file_path)) {
			cli::warn("system cannot find file specified:", file_path);
		}
		else {
			if (!GetFullPathNameA(file_path, MAX_PATH, abs_file_path, NULL)) {
				cli::error("failed to get absolute path for:", file_path);
				return -2;
			}

			files.push_back(abs_file_path);
		}
	}

	if (!files.size()) {
		cli::notice("nothing to do");
		return 0;
	}

	// *

	cli::notice(std::string("password for ") + (args.mode ? "de" : "en") + "cryption: ", "", '\0');

	std::string _password = Utils::PasswordPrompt();
	size_t _password_len = _password.length();

	if (_password_len <= crypto_pwhash_PASSWD_MIN || _password_len >= crypto_pwhash_PASSWD_MAX) {
		cli::error("password length must be between: " + std::to_string(crypto_pwhash_PASSWD_MIN) + ".." + std::to_string(crypto_pwhash_PASSWD_MAX));
		return -2;
	}

	CryptoPP::SecByteBlock password((unsigned char*)_password.c_str(), _password.size());

	sodium_memzero(&_password, _password.size());

	if (sodium_mlock(password.data(), password.size())) {
		cli::error("failed to mlock password");
		return -3;
	}

	// *

	MEMORYSTATUSEX memory_status{};
	memory_status.dwLength = sizeof(memory_status);

	if (!GlobalMemoryStatusEx(&memory_status)) {
		cli::error("failed to retrieve available memory");
		return -5;
	}

	// *

	CryptoPP::SecByteBlock key(32), salt(16);

	if (!args.mode) {
		if (sodium_mlock(key.data(), key.size())) {
			cli::error("failed to mlock key");
			return -3;
		}

		// *

		if (memory_status.ullAvailPhys <= Crypto::pw_mem_limit[args.security]) {
			cli::error("not enough memory for key derivation");
			return -5;
		}

		if (!args.mesh_key) {
			cli::notice("deriving key from password ... ", "", '\0');

			if (Crypto::DeriveKeyAndSalt(key, salt, password, args.security)) {
				std::cout << "failed" << std::endl;
				return -4;
			}

			std::cout << "ok" << std::endl;

			sodium_munlock(password.data(), password.size());
		}
	}

	// *

	cli::notice(((args.mode) ? "# decrypting " : "# encrypting ") + std::to_string(files.size()) + " file(s) \\ " + std::to_string(args.files_count - files.size()) + " file(s) skipped");

	XChaChaPoly1305::result status;
	auto entry_time = high_resolution_clock::now();

	for (auto file_iter = files.begin(); file_iter != files.end(); ++file_iter) {
		std::string file = *file_iter;

		if (!args.mode && args.mesh_key) {
			cli::notice("deriving key from password ... ", "", '\0');

			if (Crypto::DeriveKeyAndSalt(key, salt, password, args.security)) {
				std::cout << "failed" << std::endl;
				continue;
			}

			std::cout << "ok" << std::endl;
		}

		status = (args.mode) ? XChaChaPoly1305::_DecryptFile(file.c_str(), password, memory_status.ullAvailPhys) : XChaChaPoly1305::_EncryptFile(file.c_str(), key, salt, args.security, memory_status.ullAvailPhys);
		std::cout << ((args.mode) ? "[d] " : "[e] ") << Crypto::errors[status.code] << " :: " << Utils::SplitDot(status.file_size) << " bytes, " << Utils::SplitDot(status.elapsed_ms.count()) << " ms :: " << *file_iter << std::endl;
	}

	if (args.mesh_key) {
		sodium_munlock(password.data(), password.size());
	}

	if (!args.mode) {
		sodium_munlock(key.data(), key.size());
	}

	cli::notice("# elapsed: " + Utils::SplitDot(Crypto::FetchRuntime(entry_time).count()) + " ms");
}