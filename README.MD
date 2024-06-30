# ethanium
> XChaChaPoly1305-Argon2id `cli`, built on [cryptopp](https://cryptopp.com) &amp; [libsodium](https://libsodium.org/)

## Configure & Build
```
git clone https://github.com/quyxishi/ethanium.git --recurse-submodules
cd .\ethanium\
.\vcpkg\bootstrap-vcpkg -disableMetrics
.\vcpkg\vcpkg integrate install
.\ethanium.sln
```