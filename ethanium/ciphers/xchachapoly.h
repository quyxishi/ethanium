#pragma once

#include <ciphers/crypto.h>

#include <cryptopp/chachapoly.h>


namespace XChaChaPoly1305 {
	struct result {
		int statuscode;
		size_t fsize;
		milliseconds runtimems;
	};

	void _Cleanup(unsigned char* x[]);
	void _Cleanup(unsigned char* x[], unsigned char* y[]);

	result _EncryptFile(const char* _absfilepath, CryptoPP::SecByteBlock &_key, CryptoPP::SecByteBlock &_salt, int _security, unsigned long long _memavail);
	result _DecryptFile(const char* _absfilepath, CryptoPP::SecByteBlock &_password, unsigned long long _memavail);
}