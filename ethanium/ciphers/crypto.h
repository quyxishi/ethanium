#pragma once

#define SODIUM_LIBRARY_MINIMAL

#include <cryptopp/cryptlib.h>
#include <sodium.h>

#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>


const short stheader = 12;
const char header[stheader] = ";ethanium//";

namespace Crypto {
	extern const char* errorslist[];

	const int buffersize = 1024 * 128;

	extern unsigned int pwopslimit[];
	extern unsigned int pwmemlimit[];

	int DeriveKeyAndSalt(CryptoPP::SecByteBlock &key, CryptoPP::SecByteBlock &salt, CryptoPP::SecByteBlock &_password, int security = 2);
	int DeriveKeyFromSalt(CryptoPP::SecByteBlock &key, CryptoPP::SecByteBlock &salt, CryptoPP::SecByteBlock &_password, int security = 2);
	milliseconds FetchRuntime(steady_clock::time_point& timestart);
}
