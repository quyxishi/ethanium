#include <global.h>

#include <args.h>
#include <utils.h>
#include <ciphers/xchachapoly.h>


int main(int argc, char* argv[]) {
    ArgsParser argsparser;

    bool argstat = argsparser.StructArgs(argc, argv);

    if (!argstat)
        return -1;

    ETHANIUM_ARGS args = argsparser.GetArgs();
    
    if (args.help) {
        std::cout << ETHANIUM_HELP << std::endl;
        return 0;
    }

    logc::notice(std::string("@ ethanium ") + ETHANIUM_VERSION);

    // *

    std::vector<std::string> files;

    const char* fpath;
    char absfpath[MAX_PATH]{};

    for (size_t i = 0; i < args.filescount; i++) {
        fpath = args.filesv[i];

        if (!Utils::IsFileExists(fpath)) {
            logc::warn("system cannot find file specified:", fpath);
        } else {
            if (!GetFullPathNameA(fpath, MAX_PATH, absfpath, NULL)) {
                logc::error("failed to get absolute path for:", fpath);
                return -2;
            }

            files.push_back(absfpath);
        }
    }

    size_t filescount = files.size();

    if (!filescount) {
        logc::notice("nothing to do");
        return 0;
    }

    // *

    logc::notice(std::string("password for ") + (args.mode ? "de" : "en") + "cryption: ", "", '\0');

    std::string _password = Utils::PasswordPrompt();
    size_t _stpassword = _password.length();

    if (_stpassword <= crypto_pwhash_PASSWD_MIN || _stpassword >= crypto_pwhash_PASSWD_MAX) {
        logc::error("password length must be between: " + std::to_string(crypto_pwhash_PASSWD_MIN) + " ... " + std::to_string(crypto_pwhash_PASSWD_MAX));
        return -2;
    }
    
    CryptoPP::SecByteBlock password((unsigned char*)_password.c_str(), _password.size());

    sodium_memzero(&_password, _password.size());

    if (sodium_mlock(password.data(), password.size())) {
        logc::error("failed to mlock password");
        return -3;
    }

    // *

    MEMORYSTATUSEX memstatus{};
    memstatus.dwLength = sizeof(memstatus);

    if (!GlobalMemoryStatusEx(&memstatus)) {
        logc::error("failed to retrieve available memory");
        return -5;
    }

    // *

    CryptoPP::SecByteBlock key(32), salt(16);

    if (!args.mode) {
        if (sodium_mlock(key.data(), key.size())) {
            logc::error("failed to mlock key");
            return -3;
        }

        // *

        if (memstatus.ullAvailPhys <= Crypto::pwmemlimit[args.security]) {
            logc::error("not enough memory for key derivation");
            return -5;
        }

        if (!args.meshkey) {
            logc::notice("deriving key from password ... ", "", '\0');

            int argonidstat = Crypto::DeriveKeyAndSalt(key, salt, password, args.security);

            if (argonidstat) {
                std::cout << "failed" << std::endl;
                return -4;
            }

            std::cout << "ok" << std::endl;

            sodium_munlock(password.data(), password.size());
        }
    }

    // *

    logc::notice(((args.mode) ? "# decrypting " : "# encrypting ") + std::to_string(filescount) + " file(s) \\ " + std::to_string(args.filescount - filescount) + " file(s) skipped");

    XChaChaPoly1305::result status;
    auto runtimestart = high_resolution_clock::now();

    for (auto it = files.begin(); it != files.end(); ++it) {
        std::string sit = *it;

        if (!args.mode && args.meshkey) {
            logc::notice("deriving key from password ... ", "", '\0');

            int argonidstat = Crypto::DeriveKeyAndSalt(key, salt, password, args.security);

            if (argonidstat) {
                std::cout << "failed" << std::endl;
                continue;
            }

            std::cout << "ok" << std::endl;
        }

        status = (args.mode) ? XChaChaPoly1305::_DecryptFile(sit.c_str(), password, memstatus.ullAvailPhys) : XChaChaPoly1305::_EncryptFile(sit.c_str(), key, salt, args.security, memstatus.ullAvailPhys);
        std::cout << ((args.mode) ? "[d] " : "[e] ") << Crypto::errorslist[status.statuscode] << " :: " << Utils::SplitDot(status.fsize) << " bytes, " << Utils::SplitDot(status.runtimems.count()) << " ms :: " << *it << std::endl;
    }

    if (args.meshkey)
        sodium_munlock(password.data(), password.size());

    if (!args.mode)
        sodium_munlock(key.data(), key.size());

    logc::notice("# elapsed: " + Utils::SplitDot(Crypto::FetchRuntime(runtimestart).count()) + " ms");
}