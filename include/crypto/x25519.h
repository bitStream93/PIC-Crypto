#ifndef X25519_H
#define X25519_H

#include <common.h>
#include <cstdint>
#include <intrin.h>

#define X25519_KEY_SIZE 32
#define X25519_FIELD_ELEMENTS 16

namespace Crypto {
	typedef uint32_t fe[X25519_FIELD_ELEMENTS];

	typedef uint32_t limb_t;

	typedef uint64_t wide_t;

	declfn auto x25519(_Out_ uint8_t      public_key[X25519_KEY_SIZE],
	                             _In_ const uint8_t secret_key[X25519_KEY_SIZE],
	                             _In_ const uint8_t basepoint[X25519_KEY_SIZE]) -> void;

	declfn auto x25519_shared_secret(
		_Out_ uint8_t      shared_secret[X25519_KEY_SIZE],
		_In_ const uint8_t private_key[X25519_KEY_SIZE],
		_In_ const uint8_t peer_public[X25519_KEY_SIZE]) -> void;

	declfn auto x25519_generate_keypair(_In_ instance* ctx,
	                                              _Out_ uint8_t  public_key[X25519_KEY_SIZE],
	                                              _Out_ uint8_t  private_key[X25519_KEY_SIZE]) -> bool;

	declfn auto x25519_base(_Out_ uint8_t      public_key[X25519_KEY_SIZE],
	                                  _In_ const uint8_t secret_key[X25519_KEY_SIZE]) -> void;

	declfn auto x25519_clamp_private_key(
		_Inout_ uint8_t private_key[X25519_KEY_SIZE]) -> void;
}

#endif
