#pragma once

#define SODIUM_LIBRARY_MINIMAL

#include <cryptopp/cryptlib.h>
#include <sodium.h>

#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

const short header_size = 12;
const char header[header_size] = ";ethanium//";

namespace Crypto {
	extern const char* errors[];

	const int buffer_size = 1024 * 128;

	extern unsigned int pw_ops_limit[];
	extern unsigned int pw_mem_limit[];

	int DeriveKeyAndSalt(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& salt, CryptoPP::SecByteBlock& _password, int security = 2);
	int DeriveKeyFromSalt(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& salt, CryptoPP::SecByteBlock& _password, int security = 2);
	milliseconds FetchRuntime(steady_clock::time_point& timestart);
}
