#include <memory.h>
#include <pbkdf2.h>
#include <sha256.h>
#include <common.h>

using namespace Crypto;

declfn auto pbkdf2_hmac_sha256(_In_ const uint8_t* password,
                                         _In_ size_t         password_len,
                                         _In_ const uint8_t* salt,
                                         _In_ size_t         salt_len,
                                         _In_ uint32_t       iterations,
                                         _In_ size_t         key_len,
                                         _Out_ uint8_t*      output) -> void {
	if (!password || password_len == 0 || !salt || salt_len == 0 ||
		iterations < PBKDF2_MIN_ITERATIONS || !output || key_len == 0 ||
		salt_len > 120) { return; }

	uint8_t key[SHA256_BLOCK_SIZE];
	memory::secure_erase (key, SHA256_BLOCK_SIZE);

	if (password_len > SHA256_BLOCK_SIZE) { sha256 (password, password_len, key); } else {
		memory::copy (key, password, password_len);
	}

	uint8_t k_ipad[SHA256_BLOCK_SIZE];
	uint8_t k_opad[SHA256_BLOCK_SIZE];

	for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
		k_ipad[i] = key[i] ^ 0x36;
		k_opad[i] = key[i] ^ 0x5c;
	}

	SHA256_CTX ctx_ipad_template;
	sha256_init (&ctx_ipad_template);
	sha256_update (&ctx_ipad_template, k_ipad, SHA256_BLOCK_SIZE);

	SHA256_CTX ctx_opad_template;
	sha256_init (&ctx_opad_template);
	sha256_update (&ctx_opad_template, k_opad, SHA256_BLOCK_SIZE);

	uint8_t u_buffer[SHA256_HASH_SIZE];
	uint8_t f_buffer[SHA256_HASH_SIZE];
	uint8_t salt_block[128];

	const size_t blocks = (key_len + SHA256_HASH_SIZE - 1) / SHA256_HASH_SIZE;

	for (size_t block = 1; block <= blocks; ++block) {
		memory::copy (salt_block, salt, salt_len);
		salt_block[salt_len] = static_cast<uint8_t> (block >> 24);
		salt_block[salt_len + 1] = static_cast<uint8_t> (block >> 16);
		salt_block[salt_len + 2] = static_cast<uint8_t> (block >> 8);
		salt_block[salt_len + 3] = static_cast<uint8_t> (block);

		SHA256_CTX ctx_inner = ctx_ipad_template;
		sha256_update (&ctx_inner, salt_block, salt_len + 4);
		sha256_final (&ctx_inner, u_buffer);

		SHA256_CTX ctx_outer = ctx_opad_template;
		sha256_update (&ctx_outer, u_buffer, SHA256_HASH_SIZE);
		sha256_final (&ctx_outer, u_buffer);

		memory::copy (f_buffer, u_buffer, SHA256_HASH_SIZE);

		for (uint32_t iter = 1; iter < iterations; ++iter) {
			ctx_inner = ctx_ipad_template;
			sha256_update (&ctx_inner, u_buffer, SHA256_HASH_SIZE);
			sha256_final (&ctx_inner, u_buffer);

			ctx_outer = ctx_opad_template;
			sha256_update (&ctx_outer, u_buffer, SHA256_HASH_SIZE);
			sha256_final (&ctx_outer, u_buffer);

			uint64_t*       f_ptr = reinterpret_cast<uint64_t *> (f_buffer);
			const uint64_t* u_ptr = reinterpret_cast<const uint64_t *> (u_buffer);

			f_ptr[0] ^= u_ptr[0];
			f_ptr[1] ^= u_ptr[1];
			f_ptr[2] ^= u_ptr[2];
			f_ptr[3] ^= u_ptr[3];
		}

		size_t copy_len = SHA256_HASH_SIZE;
		if (block == blocks) { copy_len = key_len - ((blocks - 1) * SHA256_HASH_SIZE); }
		memory::copy (output + (block - 1) * SHA256_HASH_SIZE, f_buffer, copy_len);
	}

	memory::secure_erase (key, sizeof(key));
	memory::secure_erase (k_ipad, sizeof(k_ipad));
	memory::secure_erase (k_opad, sizeof(k_opad));
	memory::secure_erase (u_buffer, sizeof(u_buffer));
	memory::secure_erase (f_buffer, sizeof(f_buffer));
	memory::secure_erase (salt_block, sizeof(salt_block));

	memory::secure_erase (&ctx_ipad_template, sizeof (SHA256_CTX));
	memory::secure_erase (&ctx_opad_template, sizeof (SHA256_CTX));
}

declfn auto derive_key_and_iv(_In_ const uint8_t* password,
                                        _In_ size_t         password_len,
                                        _In_ const uint8_t* salt,
                                        _In_ size_t         salt_len,
                                        _In_ uint32_t       iterations,
                                        _Out_ uint8_t*      key,
                                        _In_ size_t         key_len,
                                        _Out_ uint8_t*      iv,
                                        _In_ size_t         iv_len) -> void {
	if (!password || password_len == 0 || !salt || salt_len == 0 ||
		iterations < PBKDF2_MIN_ITERATIONS || !key || key_len == 0 || !iv ||
		iv_len == 0) { return; }

	const size_t total_len = key_len + iv_len;
	if (total_len > 128) { return; }

	uint8_t derived_material[128];
	pbkdf2_hmac_sha256 (password, password_len, salt, salt_len, iterations,
	                    total_len, derived_material);

	memory::copy (key, derived_material, key_len);
	memory::copy (iv, derived_material + key_len, iv_len);

	memory::secure_erase (derived_material, sizeof(derived_material));
}

declfn auto derive_key_and_iv_from_shared_secret(
	_In_ const uint8_t* shared_secret, _In_ size_t shared_secret_len,
	_In_ const uint8_t* salt, _In_ size_t          salt_len, _In_ uint32_t iterations,
	_Out_ uint8_t*      key, _In_ size_t           key_len, _Out_ uint8_t* iv,
	_In_ size_t         iv_len) -> void {
	derive_key_and_iv (shared_secret, shared_secret_len, salt, salt_len,
	                   iterations, key, key_len, iv, iv_len);
}
