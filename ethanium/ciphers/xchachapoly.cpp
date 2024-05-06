#include <global.h>

#include <ciphers/xchachapoly.h>


namespace XChaChaPoly1305 {
    void _Cleanup(unsigned char* x[]) {
        delete[] *x;
    }

    void _Cleanup(unsigned char* x[], unsigned char* y[]) {
        delete[] *x;
        delete[] *y;
    }

    result _EncryptFile(const char* _absfilepath, CryptoPP::SecByteBlock &_key, CryptoPP::SecByteBlock &_salt, int _security, size_t _memavail) {
        auto runtimestart = high_resolution_clock::now();

        std::ifstream rfile(_absfilepath, std::ios::binary | std::ios::ate);

        if (!rfile.is_open()) {
            return result{ 1, 0, Crypto::FetchRuntime(runtimestart) };
        }

        const size_t rfilesize = rfile.tellg();

        if (!rfilesize) {
            rfile.close();
            return result{ 6, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        if ((rfilesize * 2) + 256 >= _memavail) {
            rfile.close();
            return result{ 9, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        // *

        CryptoPP::byte* plaint = new unsigned char[rfilesize];
        CryptoPP::byte* ciphert = new unsigned char[rfilesize];

        rfile.seekg(0, std::ios::beg);
        rfile.read((char*)plaint, rfilesize);

        rfile.close();

        // *

        CryptoPP::SecByteBlock iv(24), aad(32), mac(16);

        CryptoPP::OS_GenerateRandomBlock(false, iv, iv.size());
        CryptoPP::OS_GenerateRandomBlock(false, aad, aad.size());

        // *

        std::ofstream wfile(_absfilepath, std::ios::binary);

        if (!wfile.is_open()) {
            _Cleanup(&plaint, &ciphert);
            return result{ 5, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        wfile.write(header, stheader);
        wfile << _security;
        wfile.write((const char*)_salt.data(), _salt.size());
        wfile.write((const char*)iv.data(), iv.size());
        wfile.write((const char*)aad.data(), aad.size());

        // *

        CryptoPP::XChaCha20Poly1305::Encryption xchachae;
        xchachae.SetKeyWithIV(_key, _key.size(), iv, iv.size());
        xchachae.EncryptAndAuthenticate(ciphert, mac, mac.size(), iv, (int)iv.size(), aad, aad.size(), plaint, rfilesize);

        _Cleanup(&plaint);

        // *

        CryptoPP::byte* wbuf = new unsigned char[Crypto::buffersize];
        size_t stwritted = 0, towrite;

        int ibuf;

        while (stwritted != rfilesize) {
            towrite = (Crypto::buffersize <= (rfilesize - stwritted)) ? Crypto::buffersize : rfilesize - stwritted;
            ibuf = 0;

            for (size_t i = stwritted; i < (stwritted + towrite); i++) {
                wbuf[ibuf] = ciphert[i];
                ibuf++;
            }

            wfile.write((char*)wbuf, towrite);

            stwritted += towrite;
        }

        _Cleanup(&wbuf);

        wfile.write((char*)mac.data(), mac.size());
        wfile.close();

        // *

        _Cleanup(&ciphert);

        return result{ 0, rfilesize, Crypto::FetchRuntime(runtimestart) };
    }


    result _DecryptFile(const char* _absfilepath, CryptoPP::SecByteBlock &_password, size_t _memavail) {
        auto runtimestart = high_resolution_clock::now();

        std::ifstream rfile(_absfilepath, std::ios::binary | std::ios::ate);

        if (!rfile.is_open()) {
            return result{ 1, 0, Crypto::FetchRuntime(runtimestart) };
        }

        const size_t rfilesize = rfile.tellg(), rfiledsize = rfilesize - ((size_t)89 + stheader);

        if (!rfilesize) {
            rfile.close();
            return result{ 6, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        if (rfilesize < ((size_t)90 + stheader)) {
            rfile.close();
            return result{ 7, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        char bufh[stheader]{};

        rfile.seekg(0, std::ios::beg);
        rfile.read(bufh, stheader);

        if (strcmp(bufh, header)) {
            rfile.close();
            return result{ 7, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }
        
        char _csecurity;
        rfile.get(_csecurity);
        int _security = _csecurity - '0';

        if (_security < 0 || _security > 2) {
            rfile.close();
            return result{ 8, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        if ((rfilesize * 2) + Crypto::pwmemlimit[_security] + 256 >= _memavail) {
            rfile.close();
            return result{ 9, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        // *

        CryptoPP::byte* retrievet = new unsigned char[rfiledsize];
        CryptoPP::byte* ciphert = new unsigned char[rfiledsize];

        CryptoPP::SecByteBlock key(32), salt(16), iv(24), aad(32), mac(16);

#ifndef SUPPRESS_MLOCK
        if (sodium_mlock(key.data(), key.size())) {
            _Cleanup(&retrievet, &ciphert);
            return result{ 10, 0, Crypto::FetchRuntime(runtimestart) };
        }
#endif

        rfile.read((char*)salt.data(), salt.size());
        rfile.read((char*)iv.data(), iv.size());
        rfile.read((char*)aad.data(), aad.size());

        // *

        int argonidstat = Crypto::DeriveKeyFromSalt(key, salt, _password, _security);

        if (argonidstat) {
            rfile.close();

#ifndef SUPPRESS_MLOCK
            sodium_munlock(key.data(), key.size());
#endif

            _Cleanup(&retrievet, &ciphert);

            return result{ 2, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        // *

        rfile.read((char*)ciphert, rfiledsize);
        rfile.read((char*)mac.data(), mac.size());
        rfile.close();

        bool decstatus;

        CryptoPP::XChaCha20Poly1305::Decryption xchacha;
        xchacha.SetKeyWithIV(key, key.size(), iv, iv.size());
        decstatus = xchacha.DecryptAndVerify(retrievet, mac, mac.size(), iv, (int)iv.size(), aad, aad.size(), ciphert, rfiledsize);

#ifndef SUPPRESS_MLOCK
        sodium_munlock(key.data(), key.size());
#endif

        if (!decstatus) {
            _Cleanup(&retrievet, &ciphert);
            return result{ 3, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        _Cleanup(&ciphert);

        // *

        std::ofstream wfile(_absfilepath, std::ios::binary | std::ios::trunc);

        if (!wfile.is_open()) {
            _Cleanup(&retrievet);
            return result{ 4, rfilesize, Crypto::FetchRuntime(runtimestart) };
        }

        // *

        CryptoPP::byte* wbuf = new unsigned char[Crypto::buffersize];
        size_t stwritted = 0, towrite;

        int ibuf;

        while (stwritted != rfiledsize) {
            towrite = (Crypto::buffersize <= (rfiledsize - stwritted)) ? Crypto::buffersize : rfiledsize - stwritted;
            ibuf = 0;

            for (size_t i = stwritted; i < (stwritted + towrite); i++) {
                wbuf[ibuf] = retrievet[i];
                ibuf++;
            }

            wfile.write((char*)wbuf, towrite);

            stwritted += towrite;
        }
        
        _Cleanup(&wbuf);

        wfile.close();

        // *

        _Cleanup(&retrievet);

        return result{ 0, rfilesize, Crypto::FetchRuntime(runtimestart) };
    }
}