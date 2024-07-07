#include <global.h>

#include <ciphers/xchachapoly.h>

namespace XChaChaPoly1305 {
	void Cleanup(unsigned char* x[]) {
		delete[] *x;
	}

	void Cleanup(unsigned char* x[], unsigned char* y[]) {
		delete[] *x;
		delete[] *y;
	}

	result _EncryptFile(const char* file_path, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& salt, int security, size_t mem_avail) {
		auto entry_time = high_resolution_clock::now();

		std::ifstream rfile(file_path, std::ios::binary | std::ios::ate);

		if (!rfile.is_open()) {
			return result{ 1, 0, Crypto::FetchRuntime(entry_time) };
		}

		const size_t rfile_size = rfile.tellg();

		if (!rfile_size) {
			rfile.close();
			return result{ 6, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		if ((rfile_size * 2) + 256 >= mem_avail) {
			rfile.close();
			return result{ 9, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		// *

		CryptoPP::byte* plain_buffer = new unsigned char[rfile_size];
		CryptoPP::byte* cipher_buffer = new unsigned char[rfile_size];

		rfile.seekg(0, std::ios::beg);
		rfile.read((char*)plain_buffer, rfile_size);

		rfile.close();

		// *

		CryptoPP::SecByteBlock iv(24), aad(32), mac(16);

		CryptoPP::OS_GenerateRandomBlock(false, iv, iv.size());
		CryptoPP::OS_GenerateRandomBlock(false, aad, aad.size());

		// *

		std::ofstream wfile(file_path, std::ios::binary);

		if (!wfile.is_open()) {
			Cleanup(&plain_buffer, &cipher_buffer);
			return result{ 5, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		wfile.write(header, header_size);
		wfile << security;
		wfile.write((const char*)salt.data(), salt.size());
		wfile.write((const char*)iv.data(), iv.size());
		wfile.write((const char*)aad.data(), aad.size());

		// *

		CryptoPP::XChaCha20Poly1305::Encryption xchachapoly;
		xchachapoly.SetKeyWithIV(key, key.size(), iv, iv.size());
		xchachapoly.EncryptAndAuthenticate(cipher_buffer, mac, mac.size(), iv, (int)iv.size(), aad, aad.size(), plain_buffer, rfile_size);

		Cleanup(&plain_buffer);

		// *

		CryptoPP::byte* write_buffer = new unsigned char[Crypto::buffer_size];
		size_t writted_size = 0, chunk_size;

		while (writted_size != rfile_size) {
			chunk_size = std::min(rfile_size - writted_size, (size_t)Crypto::buffer_size);

			for (size_t i = writted_size; i < (writted_size + chunk_size); i++) {
				write_buffer[i - writted_size] = cipher_buffer[i];
			}

			wfile.write((char*)write_buffer, chunk_size);
			writted_size += chunk_size;
		}

		Cleanup(&write_buffer);

		wfile.write((char*)mac.data(), mac.size());
		wfile.close();

		// *

		Cleanup(&cipher_buffer);

		return result{ 0, rfile_size, Crypto::FetchRuntime(entry_time) };
	}

	result _DecryptFile(const char* file_path, CryptoPP::SecByteBlock& password, size_t mem_avail) {
		auto entry_time = high_resolution_clock::now();

		std::ifstream rfile(file_path, std::ios::binary | std::ios::ate);

		if (!rfile.is_open()) {
			return result{ 1, 0, Crypto::FetchRuntime(entry_time) };
		}

		const size_t rfile_size = rfile.tellg(), rfile_data_size = rfile_size - ((size_t)89 + header_size);

		if (!rfile_size) {
			rfile.close();
			return result{ 6, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		if (rfile_size < ((size_t)90 + header_size)) {
			rfile.close();
			return result{ 7, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		char header_buffer[header_size]{};

		rfile.seekg(0, std::ios::beg);
		rfile.read(header_buffer, header_size);

		if (strcmp(header_buffer, header)) {
			rfile.close();
			return result{ 7, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		char security_char;
		rfile.get(security_char);
		int security = security_char - '0';

		if (security < 0 || security > 2) {
			rfile.close();
			return result{ 8, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		if ((rfile_size * 2) + Crypto::pw_mem_limit[security] + 256 >= mem_avail) {
			rfile.close();
			return result{ 9, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		// *

		CryptoPP::byte* retrieve_buffer = new unsigned char[rfile_data_size];
		CryptoPP::byte* cipher_buffer = new unsigned char[rfile_data_size];

		CryptoPP::SecByteBlock key(32), salt(16), iv(24), aad(32), mac(16);

#ifndef SUPPRESS_MLOCK
		if (sodium_mlock(key.data(), key.size())) {
			Cleanup(&retrieve_buffer, &cipher_buffer);
			return result{ 10, 0, Crypto::FetchRuntime(entry_time) };
		}
#endif

		rfile.read((char*)salt.data(), salt.size());
		rfile.read((char*)iv.data(), iv.size());
		rfile.read((char*)aad.data(), aad.size());

		// *

		if (Crypto::DeriveKeyFromSalt(key, salt, password, security)) {
			rfile.close();

#ifndef SUPPRESS_MLOCK
			sodium_munlock(key.data(), key.size());
#endif

			Cleanup(&retrieve_buffer, &cipher_buffer);
			return result{ 2, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		// *

		rfile.read((char*)cipher_buffer, rfile_data_size);
		rfile.read((char*)mac.data(), mac.size());
		rfile.close();

		CryptoPP::XChaCha20Poly1305::Decryption xchacha;
		xchacha.SetKeyWithIV(key, key.size(), iv, iv.size());
		bool decryption_status = xchacha.DecryptAndVerify(retrieve_buffer, mac, mac.size(), iv, (int)iv.size(), aad, aad.size(), cipher_buffer, rfile_data_size);

#ifndef SUPPRESS_MLOCK
		sodium_munlock(key.data(), key.size());
#endif

		if (!decryption_status) {
			Cleanup(&retrieve_buffer, &cipher_buffer);
			return result{ 3, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		Cleanup(&cipher_buffer);

		// *

		std::ofstream wfile(file_path, std::ios::binary | std::ios::trunc);

		if (!wfile.is_open()) {
			Cleanup(&retrieve_buffer);
			return result{ 4, rfile_size, Crypto::FetchRuntime(entry_time) };
		}

		// *

		CryptoPP::byte* write_buffer = new unsigned char[Crypto::buffer_size];
		size_t writted_size = 0, chunk_size;

		while (writted_size != rfile_data_size) {
			chunk_size = std::min(rfile_data_size - writted_size, (size_t)Crypto::buffer_size);

			for (size_t i = writted_size; i < (writted_size + chunk_size); i++) {
				write_buffer[i - writted_size] = retrieve_buffer[i];
			}

			wfile.write((char*)write_buffer, chunk_size);
			writted_size += chunk_size;
		}

		Cleanup(&write_buffer);
		wfile.close();

		// *

		Cleanup(&retrieve_buffer);

		return result{ 0, rfile_size, Crypto::FetchRuntime(entry_time) };
	}
}