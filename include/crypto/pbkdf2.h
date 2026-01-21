#ifndef PBKDF2_H
#define PBKDF2_H
#include <common.h>
#define PBKDF2_DEFAULT_ITERATIONS 650000
#define PBKDF2_MIN_ITERATIONS 1000
#define PDKDF2_DEFAULT_SALT_LEN 16
declfn auto pbkdf2_hmac_sha256(_In_ const uint8_t* password,
                                         _In_ size_t         password_len,
                                         _In_ const uint8_t* salt,
                                         _In_ size_t         salt_len,
                                         _In_ uint32_t       iterations, _In_ size_t key_len,
                                         _Out_ uint8_t*      output) -> void;

declfn auto derive_key_and_iv(_In_ const uint8_t* password,
                                        _In_ size_t         password_len,
                                        _In_ const uint8_t* salt, _In_ size_t          salt_len,
                                        _In_ uint32_t       iterations, _Out_ uint8_t* key,
                                        _In_ size_t         key_len, _Out_ uint8_t*    iv,
                                        _In_ size_t         iv_len) -> void;

declfn auto derive_key_and_iv_from_shared_secret(
	_In_ const uint8_t* shared_secret, _In_ size_t shared_secret_len,
	_In_ const uint8_t* salt, _In_ size_t          salt_len, _In_ uint32_t iterations,
	_Out_ uint8_t*      key, _In_ size_t           key_len, _Out_ uint8_t* iv,
	_In_ size_t         iv_len) -> void;
#endif
