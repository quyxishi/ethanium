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

security options for argon2id:
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
	args.security = -1;
	args.mesh_key = 0;
}

bool ArgsParser::StructArgs(int argc, char* argv[]) {
	// todo: better way to parse args

	for (int i = 1; i != argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			if (args.help == 1) {
				cli::error("arguments: --help already specified");
				return false;
			}

			args.help = 1;
		}

		else if (!strcmp(argv[i], "--encrypt") || !strcmp(argv[i], "--decrypt")) {
			if (args.mode != -1) {
				cli::error("arguments: --encrypt/--decrypt already specified");
				return false;
			}

			args.mode = (!strcmp(argv[i], "--encrypt")) ? 0 : 1;
		}

		else if (!strcmp(argv[i], "--interactive") || !strcmp(argv[i], "--moderate") || !strcmp(argv[i], "--sensitive")) {
			if (args.security != -1) {
				cli::error("arguments: --interactive/--moderate/--sensitive already specified");
				return false;
			}

			if (!strcmp(argv[i], "--interactive")) {
				args.security = 0;
			}
			else if (!strcmp(argv[i], "--moderate")) {
				args.security = 1;
			}
			else {
				args.security = 2;
			}
		}

		else if (!strcmp(argv[i], "--mesh-key")) {
			if (args.mesh_key == 1) {
				cli::error("arguments: --mesh-key already specified");
				return false;
			}

			args.mesh_key = 1;
		}

		else {
			args.files.push_back(argv[i]);
		}
	}

	args.files_count = args.files.size();

	// ...

	if (args.help) {
		return true;
	}

	if (args.mode == -1) {
		cli::error("arguments: excepted --encrypt/--decrypt argument");
		return false;
	}

	if (!args.mode) {
		if (args.security != -1) {
			if (args.files_count) {
				return true;
			}
			else {
				cli::error("arguments: --encrypt: no input file(s) specified");
				return false;
			}
		}
		else {
			cli::error("arguments: --encrypt: excepted security option");
			return false;
		}
	}
	else {
		if (args.security != -1) {
			cli::warn("arguments: --decrypt: not excepted security option");
		}

		if (args.mesh_key != 0) {
			cli::warn("arguments: --decrypt: not excepted --mesh-key");
		}

		if (args.files_count) {
			return true;
		}
		else {
			cli::error("arguments: --decrypt: no input file(s) specified");
			return false;
		}
	}
}

ETHANIUM_ARGS ArgsParser::GetArgs() {
	return args;
}