#include <prng.h>
#include <sha256.h>
#include <chacha20.h>
#include <memory.h>
#include <common.h>

using namespace Crypto;

namespace {
	declfn auto gather_system_entropy(
		_In_ instance* ctx,
		_Out_ uint8_t* entropy_buffer,
		_In_ size_t    buffer_size) -> size_t {
		size_t offset = 0;

		if (offset + 8 <= buffer_size && ctx->kernel32.QueryPerformanceCounter) {
			int64_t qpc = 0;
			if (ctx->kernel32.
				QueryPerformanceCounter (static_cast<LARGE_INTEGER *> (reinterpret_cast<void *> (&qpc)))) {
				memory::copy (entropy_buffer + offset, &qpc, 8);
				offset += 8;
			}
		}

		if (offset + 8 <= buffer_size && ctx->kernel32.GetTickCount64) {
			uint64_t tick = ctx->kernel32.GetTickCount64();
			memory::copy (entropy_buffer + offset, &tick, 8);
			offset += 8;
		}

		if (offset + 4 <= buffer_size && ctx->kernel32.GetCurrentProcessId) {
			uint32_t pid = ctx->kernel32.GetCurrentProcessId();
			memory::copy (entropy_buffer + offset, &pid, 4);
			offset += 4;
		}

		if (offset + 4 <= buffer_size && ctx->kernel32.GetCurrentThreadId) {
			uint32_t tid = ctx->kernel32.GetCurrentThreadId();
			memory::copy (entropy_buffer + offset, &tid, 4);
			offset += 4;
		}

		if (offset + 8 <= buffer_size) {
			volatile uint8_t stack_var;
			auto             stack_addr = reinterpret_cast<uintptr_t> (&stack_var);
			memory::copy (entropy_buffer + offset, &stack_addr, 8);
			offset += 8;
		}

		for (int i = 0; i < 4 && offset + 8 <= buffer_size; i++) {
			uint64_t val;
			if (_rdrand64_step (&val)) {
				memory::copy (entropy_buffer + offset, &val, 8);
				offset += 8;
			}
		}

		return offset;
	}

	declfn auto mix_entropy(
		_In_ const uint8_t* entropy,
		_In_ size_t         entropy_len,
		_Out_ uint8_t       key[32],
		_Out_ uint8_t       nonce[12]) -> void {
		SHA256_CTX sha_ctx;

		uint8_t prefix_key = 0x01;
		sha256_init (&sha_ctx);
		sha256_update (&sha_ctx, &prefix_key, 1);
		sha256_update (&sha_ctx, entropy, entropy_len);
		sha256_final (&sha_ctx, key);

		uint8_t nonce_hash[32];
		uint8_t prefix_nonce = 0x02;
		sha256_init (&sha_ctx);
		sha256_update (&sha_ctx, &prefix_nonce, 1);
		sha256_update (&sha_ctx, entropy, entropy_len);
		sha256_update (&sha_ctx, key, 32);
		sha256_final (&sha_ctx, nonce_hash);

		memory::copy (nonce, nonce_hash, 12);

		memory::secure_erase (&sha_ctx, sizeof(sha_ctx));
		memory::secure_erase (nonce_hash, sizeof(nonce_hash));
	}

	declfn auto prng_rekey(_Inout_ Crypto::PRNG_CTX* prng) -> void {
		uint8_t new_key[32];
		uint8_t new_nonce[12];

		CHACHA20_CTX chacha;
		chacha20_init (&chacha, prng->key, prng->nonce, static_cast<uint32_t> (prng->counter));

		memory::set (new_key, 0, 32);
		chacha20_encrypt_decrypt (&chacha, new_key, 32);

		memory::set (new_nonce, 0, 12);
		chacha20_encrypt_decrypt (&chacha, new_nonce, 12);

		memory::secure_erase (prng->key, 32);
		memory::secure_erase (prng->nonce, 12);

		memory::copy (prng->key, new_key, 32);
		memory::copy (prng->nonce, new_nonce, 12);
		prng->counter = 0;
		prng->rekey_counter = 0;

		memory::secure_erase (&chacha, sizeof(chacha));
		memory::secure_erase (new_key, 32);
		memory::secure_erase (new_nonce, 12);
	}
}

declfn auto Crypto::prng_init(
	_In_ instance*  ctx,
	_Out_ PRNG_CTX* prng) -> void {
	memory::set (prng, 0, sizeof (PRNG_CTX));

	uint8_t entropy_buffer[256];
	memory::set (entropy_buffer, 0, sizeof(entropy_buffer));

	size_t entropy_len = gather_system_entropy (ctx, entropy_buffer, sizeof(entropy_buffer));

	mix_entropy (entropy_buffer, entropy_len, prng->key, prng->nonce);

	prng->counter = 0;
	prng->bytes_generated = 0;
	prng->rekey_counter = 0;
	prng->initialized = true;

	memory::secure_erase (entropy_buffer, sizeof(entropy_buffer));
}

declfn auto Crypto::prng_add_entropy(
	_Inout_ PRNG_CTX*   prng,
	_In_ const uint8_t* entropy,
	_In_ size_t         len) -> void {
	if (!prng || !prng->initialized || !entropy || len == 0) return;

	uint8_t combined[96];
	memory::copy (combined, prng->key, 32);
	memory::copy (combined + 32, prng->nonce, 12);

	size_t copy_len = len > 52 ? 52 : len;
	memory::copy (combined + 44, entropy, copy_len);

	mix_entropy (combined, 44 + copy_len, prng->key, prng->nonce);

	prng->counter = 0;
	prng->bytes_generated = 0;
	prng->rekey_counter = 0;

	memory::secure_erase (combined, sizeof(combined));
}

declfn auto Crypto::prng_random_bytes(
	_Inout_ PRNG_CTX* prng,
	_Out_ uint8_t*    output,
	_In_ size_t       length) -> void {
	if (!prng || !prng->initialized || !output || length == 0) return;

	CHACHA20_CTX chacha;
	size_t       remaining = length;
	size_t       offset = 0;

	while (remaining > 0) {
		if (prng->rekey_counter >= PRNG_REKEY_INTERVAL) { prng_rekey (prng); }

		chacha20_init (&chacha, prng->key, prng->nonce, static_cast<uint32_t> (prng->counter));

		size_t chunk = remaining;
		if (chunk > 64) chunk = 64;

		memory::set (output + offset, 0, chunk);
		chacha20_encrypt_decrypt (&chacha, output + offset, chunk);

		prng->counter++;
		prng->bytes_generated += chunk;
		prng->rekey_counter += chunk;

		offset += chunk;
		remaining -= chunk;
	}

	memory::secure_erase (&chacha, sizeof(chacha));
}

declfn auto Crypto::secure_random_bytes(
	_In_ instance* ctx,
	_Out_ uint8_t* output,
	_In_ size_t    length) -> void {
	PRNG_CTX prng;
	prng_init (ctx, &prng);
	prng_random_bytes (&prng, output, length);
	prng_destroy (&prng);
}

declfn auto Crypto::prng_destroy(
	_Inout_ PRNG_CTX* prng) -> void {
	if (!prng) return;
	memory::secure_erase (prng, sizeof (PRNG_CTX));
}
