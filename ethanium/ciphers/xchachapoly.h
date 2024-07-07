#pragma once

#include <ciphers/crypto.h>

#include <cryptopp/chachapoly.h>

namespace XChaChaPoly1305 {
	struct result {
		int code;
		size_t file_size;
		milliseconds elapsed_ms;
	};

	void Cleanup(unsigned char* x[]);
	void Cleanup(unsigned char* x[], unsigned char* y[]);

	result _EncryptFile(const char* file_path, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& salt, int security, size_t mem_avail);
	result _DecryptFile(const char* file_path, CryptoPP::SecByteBlock& password, size_t mem_avail);
}