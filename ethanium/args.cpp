#include <global.h>
#include <args.h>

#ifndef ETHANIUM_HELP_DEF
#define ETHANIUM_HELP_DEF

std::string ETHANIUM_HELP = std::string("ethanium ") + ETHANIUM_VERSION + R"(
usage: ethanium [--encrypt] [--decrypt] [--sensitive] file file ...
		[--password .]

XChaChaPoly1305-Argon2id cli, built on cryptopp & libsodium

positional arguments:
  file file ...          :: Files, separated with space

required arguments:
  --encrypt / --decrypt  :: Encrypt/decrypt file(s)
  --password             :: Password for encryption/decryption

security options for encryption:
  --interactive          :: Fastest, insecure        [64 MiB of RAM required]
  --moderate             :: Fast, moderate security  [256 MiB of RAM required]
  --sensitive            :: Slowest, secure          [1024 MiB of RAM required]

optional arguments:
  --mesh-key             :: Regenerate key for each file on encryption
  --help                 :: Display this help message
)";

#endif


ArgsParser::ArgsParser() {
    args.help = 0;
    args.mode = -1;
    args.passwd = "\0";
    args.security = -1;
    args.meshkey = 0;
}

bool ArgsParser::StructArgs(int argc, char* argv[]) {
    bool pass = false;

    // todo: better way to parse args

    for (int i = 1; i != argc; i++) {
        if (pass) {
            pass = false;
            continue;
        }

        if (!strcmp(argv[i], "--help")) {
            if (args.help == 1) {
                logc::error("arguments: --help already specified");
                return false;
            }

            args.help = 1;
        }

        else if (!strcmp(argv[i], "--encrypt") || !strcmp(argv[i], "--decrypt")) {
            if (args.mode != -1) {
                logc::error("arguments: --encrypt/--decrypt already specified");
                return false;
            }

            args.mode = (!strcmp(argv[i], "--encrypt")) ? 0 : 1;
        }

        else if (!strcmp(argv[i], "--interactive") || !strcmp(argv[i], "--moderate") || !strcmp(argv[i], "--sensitive")) {
            if (args.security != -1) {
                logc::error("arguments: --interactive/--moderate/--sensitive already specified");
                return false;
            }

            if (!strcmp(argv[i], "--interactive"))
                args.security = 0;
            else if (!strcmp(argv[i], "--moderate"))
                args.security = 1;
            else
                args.security = 2;
        }

        else if (!strcmp(argv[i], "--mesh-key")) {
            if (args.meshkey == 1) {
                logc::error("arguments: --mesh-key already specified");
                return false;
            }

            args.meshkey = 1;
        }

        else if (!strcmp(argv[i], "--password")) {
            if (i + 1 != argc) {
                args.passwd = argv[i + 1];
                pass = true;
            }
            else {
                logc::error("arguments: --password: excepted value after argument");
                return false;
            }
        }

        else {
            args.filesv.push_back(argv[i]);
        }
    }

    args.filescount = args.filesv.size();

    // ...

    if (args.help) {
        return true;
    }

    if (args.mode == -1) {
        logc::error("arguments: excepted --encrypt/--decrypt argument");
        return false;
    }

    if (args.passwd == "\0") {
        logc::error("arguments: excepted --password argument");
        return false;
    }

    if (!args.mode) {
        if (args.security != -1) {
            if (args.filescount) {
                return true;
            }
            else {
                logc::error("arguments: --encrypt: no input file(s) specified");
                return false;
            }
        }
        else {
            logc::error("arguments: --encrypt: excepted security option");
            return false;
        }
    }
    else {
        if (args.security != -1)
            logc::warn("arguments: --decrypt: not excepted security option");

        if (args.meshkey != 0)
            logc::warn("arguments: --decrypt: not excepted --mesh-key");

        if (args.filescount) {
            return true;
        }
        else {
            logc::error("arguments: --decrypt: no input file(s) specified");
            return false;
        }
    }
}

ETHANIUM_ARGS ArgsParser::GetArgs() {
    return args;
}