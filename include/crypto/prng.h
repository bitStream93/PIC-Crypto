#ifndef PRNG_H
#define PRNG_H

#include <common.h>
#include <cstdint>

#define PRNG_KEY_SIZE 32
#define PRNG_NONCE_SIZE 12
#define PRNG_RESEED_INTERVAL (1024 * 1024)
#define PRNG_REKEY_INTERVAL (16 * 1024)

namespace Crypto {
	struct PRNG_CTX {
		uint8_t  key[PRNG_KEY_SIZE];
		uint8_t  nonce[PRNG_NONCE_SIZE];
		uint64_t counter;
		uint64_t bytes_generated;
		uint64_t rekey_counter;
		bool     initialized;
	};


	declfn auto prng_init(
		_In_ instance*  ctx,
		_Out_ PRNG_CTX* prng) -> void;


	declfn auto prng_add_entropy(
		_Inout_ PRNG_CTX*   prng,
		_In_ const uint8_t* entropy,
		_In_ size_t         len) -> void;


	declfn auto prng_random_bytes(
		_Inout_ PRNG_CTX* prng,
		_Out_ uint8_t*    output,
		_In_ size_t       length) -> void;


	declfn auto secure_random_bytes(
		_In_ instance* ctx,
		_Out_ uint8_t* output,
		_In_ size_t    length) -> void;


	declfn auto prng_destroy(
		_Inout_ PRNG_CTX* prng) -> void;
}

#endif
