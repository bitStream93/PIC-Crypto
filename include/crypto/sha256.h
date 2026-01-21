#pragma once
#include <common.h>

namespace Crypto {
#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE  32

	struct SHA256_CTX {
		uint8_t  data[64];
		uint32_t datalen;
		uint64_t bitlen;
		uint32_t state[8];
	};

	declfn auto sha256_init(_Out_ SHA256_CTX* ctx) -> void;

	declfn auto sha256_update(_Inout_ SHA256_CTX* ctx,
	                                    _In_ const uint8_t* data,
	                                    _In_ size_t         len) -> void;

	declfn auto sha256_final(_Inout_ SHA256_CTX* ctx,
	                                   _Out_ uint8_t       hash[SHA256_HASH_SIZE]) -> void;

	declfn auto sha256(_In_ const uint8_t* data, _In_ size_t len,
	                             _Out_ uint8_t       hash[SHA256_HASH_SIZE]) -> void;

	declfn auto hmac_sha256(_In_ const uint8_t* key, _In_ size_t  keylen,
	                                  _In_ const uint8_t* data, _In_ size_t datalen,
	                                  _Out_ uint8_t       hash[SHA256_HASH_SIZE]) -> void;
}
