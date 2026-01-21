#ifndef CHACHA20_H
#define CHACHA20_H

#include <common.h>

#include <cstdint>

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_STATE_SIZE 16
#define POLY1305_TAG_SIZE 16
#define POLY1305_KEY_SIZE 32

typedef struct alignas(16) {
	uint32_t state[CHACHA20_STATE_SIZE];
	uint8_t  buffer[CHACHA20_BLOCK_SIZE];
	uint32_t buffer_used;
	uint32_t counter;
} CHACHA20_CTX,* PCHACHA20_CTX;

typedef struct {
	uint32_t r[5];
	uint32_t h[5];
	uint32_t pad[4];
	uint8_t  buffer[16];
	size_t   buffer_len;
} POLY1305_CTX,* PPOLY1305_CTX;

declfn auto chacha20_init(_Inout_ PCHACHA20_CTX ctx,
                                    _In_ const uint8_t    key[CHACHA20_KEY_SIZE],
                                    _In_ const uint8_t    nonce[CHACHA20_NONCE_SIZE],
                                    _In_ uint32_t         counter) -> void;

declfn auto chacha20_encrypt_decrypt(_Inout_ PCHACHA20_CTX ctx,
                                               _Inout_ uint8_t*      buf,
                                               _In_ size_t           length) -> void;

declfn auto chacha20_poly1305_encrypt(
	_In_ const uint8_t key[CHACHA20_KEY_SIZE],
	_In_ const uint8_t nonce[CHACHA20_NONCE_SIZE], _In_ const uint8_t* aad,
	_In_ size_t        aad_len, _In_ const uint8_t*                    plaintext,
	_In_ size_t        plaintext_len, _Out_ uint8_t*                   ciphertext,
	_Out_ uint8_t      tag[POLY1305_TAG_SIZE]) -> void;

declfn auto chacha20_poly1305_decrypt(
	_In_ const uint8_t key[CHACHA20_KEY_SIZE],
	_In_ const uint8_t nonce[CHACHA20_NONCE_SIZE], _In_ const uint8_t* aad,
	_In_ size_t        aad_len, _In_ const uint8_t*                    ciphertext,
	_In_ size_t        ciphertext_len, _In_ const uint8_t              tag[POLY1305_TAG_SIZE],
	_Out_ uint8_t*     plaintext) -> bool;

declfn auto constant_time_equals(_In_ const uint8_t* a,
                                           _In_ const uint8_t* b, _In_ size_t len) -> bool;

#endif
