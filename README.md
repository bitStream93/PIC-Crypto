# Crypto PIC Framework

A PIC cryptographic implementation. This project is built upon the PIC framework architecture developed by [Cracked5pider](https://github.com/Cracked5pider).

### Overview

* Implements a custom cryptographic library in C++ designed to run as position-independent code.
* **Asymmetric Cryptography**: Uses X25519 for DHKE to establish shared secrets between peers.
* **Symmetric Encryption**: Implements the ChaCha20-Poly1305.
* **Secure Hashing and Derivation**: Includes a full implementation of SHA-256, HMAC-SHA256 and PBKDF2 for password-based key derivation.
* **Entropy and PRNG**: Features a PRNG that gathers system entropy from hardware and software sources( better than rand() but please keep in mind this is a lightweight implementation and it is probably not cryptographically secure by todays standards ).

Note: While I made every effort to adhere strictly to the RFC standards for each algorithm, there very well could be mistakes. I had no prior experience in cryptography before starting this. 

### Build
```bash
mkdir build
cd build
cmake -G "MinGW Makefiles" --toolchain="../toolchain-mingw-clang.cmake" ..
cmake --build ../build
```
or
```bash
.\build.bat
```

<img width="1754" height="1024" alt="image" src="https://github.com/user-attachments/assets/876a18c4-96f6-44ac-bd8f-c02a479e50b9" />
