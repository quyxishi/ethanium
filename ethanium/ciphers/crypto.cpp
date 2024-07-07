#include <global.h>

#include <ciphers/crypto.h>

namespace Crypto {
#ifndef CRYPTO_CONSTS
#define CRYPTO_CONSTS

	const char* errors[11] = {
		"ok", "open_failed", "argon2id_failed",
		"decrypt_failed", "postopen_failed", "preopen_failed",
		"file_empty", "not_encrypted", "security_corrupted",
		"memory_overflow", "mlock_failed"
	};

	extern const int buffer_size;

	unsigned int pw_ops_limit[3] = { crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_OPSLIMIT_SENSITIVE };
	unsigned int pw_mem_limit[3] = { crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_SENSITIVE };

#endif

	int DeriveKeyAndSalt(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& salt, CryptoPP::SecByteBlock& password, int security) {
		CryptoPP::OS_GenerateRandomBlock(false, salt, salt.size());

		return crypto_pwhash(key.data(), key.size(), (const char*)password.data(), password.size(), salt, pw_ops_limit[security], pw_mem_limit[security], crypto_pwhash_ALG_ARGON2ID13);
	}

	int DeriveKeyFromSalt(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& salt, CryptoPP::SecByteBlock& password, int security) {
		return crypto_pwhash(key.data(), key.size(), (const char*)password.data(), password.size(), salt, pw_ops_limit[security], pw_mem_limit[security], crypto_pwhash_ALG_ARGON2ID13);
	}

	milliseconds FetchRuntime(steady_clock::time_point& entry_time) {
		return (duration_cast<milliseconds>(high_resolution_clock::now() - entry_time));
	}
}