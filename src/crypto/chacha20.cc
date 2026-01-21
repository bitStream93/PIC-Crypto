#include <chacha20.h>
#include <memory.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA20_QR(a, b, c, d) \
  do {                          \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
  } while (0)

static inline uint32_t load32_le(const uint8_t* b) {
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static inline void store32_le(uint8_t* b, uint32_t v) {
	b[0] = (uint8_t)(v & 0xff);
	b[1] = (uint8_t)((v >> 8) & 0xff);
	b[2] = (uint8_t)((v >> 16) & 0xff);
	b[3] = (uint8_t)((v >> 24) & 0xff);
}

declfn auto chacha20_init(_Inout_ PCHACHA20_CTX ctx,
                                    _In_ const uint8_t    key[CHACHA20_KEY_SIZE],
                                    _In_ const uint8_t    nonce[CHACHA20_NONCE_SIZE],
                                    _In_ uint32_t         counter) -> void {
	ctx->state[0] = 0x61707865;
	ctx->state[1] = 0x3320646e;
	ctx->state[2] = 0x79622d32;
	ctx->state[3] = 0x6b206574;

	for (size_t i = 0; i < 8; i++) { ctx->state[4 + i] = load32_le (&key[i * 4]); }

	ctx->state[12] = counter;
	ctx->counter = counter;

	for (size_t i = 0; i < 3; i++) { ctx->state[13 + i] = load32_le (&nonce[i * 4]); }

	ctx->buffer_used = CHACHA20_BLOCK_SIZE;
	memory::secure_erase (ctx->buffer, sizeof(ctx->buffer));
}

static auto chacha20_process_block_scalar(
	_Inout_ const uint32_t state[CHACHA20_STATE_SIZE],
	_Out_ uint8_t          output[CHACHA20_BLOCK_SIZE]) -> void {
	uint32_t working_state[16];

	for (int i = 0; i < 16; i++) { working_state[i] = state[i]; }

	for (int i = 0; i < 10; i++) {
		CHACHA20_QR (working_state[0], working_state[4], working_state[8],
		             working_state[12]);
		CHACHA20_QR (working_state[1], working_state[5], working_state[9],
		             working_state[13]);
		CHACHA20_QR (working_state[2], working_state[6], working_state[10],
		             working_state[14]);
		CHACHA20_QR (working_state[3], working_state[7], working_state[11],
		             working_state[15]);

		CHACHA20_QR (working_state[0], working_state[5], working_state[10],
		             working_state[15]);
		CHACHA20_QR (working_state[1], working_state[6], working_state[11],
		             working_state[12]);
		CHACHA20_QR (working_state[2], working_state[7], working_state[8],
		             working_state[13]);
		CHACHA20_QR (working_state[3], working_state[4], working_state[9],
		             working_state[14]);
	}

	for (int i = 0; i < 16; i++) { working_state[i] += state[i]; }

	for (int i = 0; i < 16; i++) {
		uint32_t w = working_state[i];
		output[i * 4 + 0] = (uint8_t)(w & 0xff);
		output[i * 4 + 1] = (uint8_t)((w >> 8) & 0xff);
		output[i * 4 + 2] = (uint8_t)((w >> 16) & 0xff);
		output[i * 4 + 3] = (uint8_t)((w >> 24) & 0xff);
	}
}

static declfn auto chacha20_process_block(_Inout_ PCHACHA20_CTX ctx) -> void {
	chacha20_process_block_scalar (ctx->state, ctx->buffer);
	ctx->buffer_used = 0;
	ctx->state[12]++;
	ctx->counter++;
}

static declfn auto chacha20_process_bytes(_Inout_ PCHACHA20_CTX ctx,
                                                    _Inout_ uint8_t*      buf,
                                                    _In_ size_t           length) -> void {
	while (length > 0) {
		if (ctx->buffer_used >= CHACHA20_BLOCK_SIZE) { chacha20_process_block (ctx); }

		const size_t available = CHACHA20_BLOCK_SIZE - ctx->buffer_used;
		const size_t to_process = length < available ? length : available;

		for (size_t i = 0; i < to_process; i++) { buf[i] ^= ctx->buffer[ctx->buffer_used + i]; }

		buf += to_process;
		ctx->buffer_used += to_process;
		length -= to_process;
	}
}

static declfn auto chacha20_encrypt_decrypt(_Inout_ PCHACHA20_CTX ctx,
                                                      _Inout_ uint8_t*      buf,
                                                      _In_ size_t           length) -> void {
	chacha20_process_bytes (ctx, buf, length);
}

static declfn auto chacha20_reset_counter(_Inout_ PCHACHA20_CTX ctx,
                                                    _In_ uint32_t         counter) -> void {
	ctx->state[12] = counter;
	ctx->counter = counter;
	ctx->buffer_used = CHACHA20_BLOCK_SIZE;
}

static declfn auto poly1305_init(_Out_ PPOLY1305_CTX ctx,
                                           _In_ const uint8_t  key[32]) -> void {
	uint8_t rbytes[16];
	for (int i = 0; i < 16; ++i) rbytes[i] = key[i];

	rbytes[3] &= 0x0f;
	rbytes[7] &= 0x0f;
	rbytes[11] &= 0x0f;
	rbytes[15] &= 0x0f;

	rbytes[4] &= 0xfc;
	rbytes[8] &= 0xfc;
	rbytes[12] &= 0xfc;

	uint32_t t0 = load32_le (rbytes + 0);
	uint32_t t1 = load32_le (rbytes + 4);
	uint32_t t2 = load32_le (rbytes + 8);
	uint32_t t3 = load32_le (rbytes + 12);

	ctx->r[0] = t0 & 0x3ffffff;
	ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
	ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
	ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
	ctx->r[4] = (t3 >> 8) & 0x3ffffff;

	ctx->pad[0] = load32_le (key + 16);
	ctx->pad[1] = load32_le (key + 20);
	ctx->pad[2] = load32_le (key + 24);
	ctx->pad[3] = load32_le (key + 28);

	for (unsigned int & i : ctx->h) i = 0;
	ctx->buffer_len = 0;
}

static auto poly1305_block(_Inout_ PPOLY1305_CTX ctx, _In_ const uint8_t* data,
                           uint8_t               hibit) -> void {
	uint32_t t0 = load32_le (data + 0);
	uint32_t t1 = load32_le (data + 4);
	uint32_t t2 = load32_le (data + 8);
	uint32_t t3 = load32_le (data + 12);

	uint32_t d0 = t0 & 0x3ffffff;
	uint32_t d1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
	uint32_t d2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
	uint32_t d3 = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
	uint32_t d4 = (t3 >> 8) & 0x3ffffff;

	if (hibit) { d4 |= (1 << 24); }

	ctx->h[0] += d0;
	ctx->h[1] += d1;
	ctx->h[2] += d2;
	ctx->h[3] += d3;
	ctx->h[4] += d4;

	uint64_t d_0 =
			(uint64_t)ctx->h[0] * ctx->r[0] + (uint64_t)ctx->h[1] * (ctx->r[4] * 5ULL) +
			(uint64_t)ctx->h[2] * (ctx->r[3] * 5ULL) + (uint64_t)ctx->h[3] * (ctx->r[2] * 5ULL) +
			(uint64_t)ctx->h[4] * (ctx->r[1] * 5ULL);
	uint64_t d_1 =
			(uint64_t)ctx->h[0] * ctx->r[1] + (uint64_t)ctx->h[1] * ctx->r[0] +
			(uint64_t)ctx->h[2] * (ctx->r[4] * 5ULL) + (uint64_t)ctx->h[3] * (ctx->r[3] * 5ULL) +
			(uint64_t)ctx->h[4] * (ctx->r[2] * 5ULL);
	uint64_t d_2 =
			(uint64_t)ctx->h[0] * ctx->r[2] + (uint64_t)ctx->h[1] * ctx->r[1] +
			(uint64_t)ctx->h[2] * ctx->r[0] + (uint64_t)ctx->h[3] * (ctx->r[4] * 5ULL) +
			(uint64_t)ctx->h[4] * (ctx->r[3] * 5ULL);
	uint64_t d_3 =
			(uint64_t)ctx->h[0] * ctx->r[3] + (uint64_t)ctx->h[1] * ctx->r[2] +
			(uint64_t)ctx->h[2] * ctx->r[1] + (uint64_t)ctx->h[3] * ctx->r[0] +
			(uint64_t)ctx->h[4] * (ctx->r[4] * 5ULL);
	uint64_t d_4 =
			(uint64_t)ctx->h[0] * ctx->r[4] + (uint64_t)ctx->h[1] * ctx->r[3] +
			(uint64_t)ctx->h[2] * ctx->r[2] + (uint64_t)ctx->h[3] * ctx->r[1] +
			(uint64_t)ctx->h[4] * ctx->r[0];

	ctx->h[0] = (uint32_t)(d_0 & 0x3ffffff);
	d_1 += (d_0 >> 26);
	ctx->h[1] = (uint32_t)(d_1 & 0x3ffffff);
	d_2 += (d_1 >> 26);
	ctx->h[2] = (uint32_t)(d_2 & 0x3ffffff);
	d_3 += (d_2 >> 26);
	ctx->h[3] = (uint32_t)(d_3 & 0x3ffffff);
	d_4 += (d_3 >> 26);
	ctx->h[4] = (uint32_t)(d_4 & 0x3ffffff);
	ctx->h[0] += (uint32_t)(d_4 >> 26) * 5;

	ctx->h[1] += ctx->h[0] >> 26;
	ctx->h[0] &= 0x3ffffff;
}

static declfn auto poly1305_update(_Inout_ PPOLY1305_CTX ctx,
                                             _In_ const uint8_t*   data, _In_ size_t len) -> void {
	if (len == 0) return;

	if (ctx->buffer_len > 0) {
		size_t need = 16 - ctx->buffer_len;
		if (len < need) {
			for (size_t i = 0; i < len; ++i) ctx->buffer[ctx->buffer_len + i] = data[i];
			ctx->buffer_len += (uint32_t)len;
			return;
		} else {
			for (size_t i = 0; i < need; ++i) ctx->buffer[ctx->buffer_len + i] = data[i];
			poly1305_block (ctx, ctx->buffer, 1);
			data += need;
			len -= need;
			ctx->buffer_len = 0;
		}
	}

	while (len >= 16) {
		poly1305_block (ctx, data, 1);
		data += 16;
		len -= 16;
	}

	if (len > 0) {
		for (size_t i = 0; i < len; ++i) ctx->buffer[i] = data[i];
		ctx->buffer_len = (uint32_t)len;
	}
}

static declfn auto poly1305_final(_Inout_ PPOLY1305_CTX ctx,
                                            _Out_ uint8_t         tag[16]) -> void {
	if (ctx->buffer_len > 0) {
		ctx->buffer[ctx->buffer_len] = 1;
		for (uint32_t i = ctx->buffer_len + 1; i < 16; ++i) ctx->buffer[i] = 0;
		poly1305_block (ctx, ctx->buffer, 0);
	}

	ctx->h[1] += ctx->h[0] >> 26;
	ctx->h[0] &= 0x3ffffff;
	ctx->h[2] += ctx->h[1] >> 26;
	ctx->h[1] &= 0x3ffffff;
	ctx->h[3] += ctx->h[2] >> 26;
	ctx->h[2] &= 0x3ffffff;
	ctx->h[4] += ctx->h[3] >> 26;
	ctx->h[3] &= 0x3ffffff;
	ctx->h[0] += (ctx->h[4] >> 26) * 5;
	ctx->h[4] &= 0x3ffffff;
	ctx->h[1] += ctx->h[0] >> 26;
	ctx->h[0] &= 0x3ffffff;

	ctx->h[2] += ctx->h[1] >> 26;
	ctx->h[1] &= 0x3ffffff;
	ctx->h[3] += ctx->h[2] >> 26;
	ctx->h[2] &= 0x3ffffff;
	ctx->h[4] += ctx->h[3] >> 26;
	ctx->h[3] &= 0x3ffffff;

	uint32_t g[5];
	uint32_t carry;

	g[0] = ctx->h[0] + 5;
	carry = g[0] >> 26;
	g[0] &= 0x3ffffff;
	g[1] = ctx->h[1] + carry;
	carry = g[1] >> 26;
	g[1] &= 0x3ffffff;
	g[2] = ctx->h[2] + carry;
	carry = g[2] >> 26;
	g[2] &= 0x3ffffff;
	g[3] = ctx->h[3] + carry;
	carry = g[3] >> 26;
	g[3] &= 0x3ffffff;
	g[4] = ctx->h[4] + carry;

	uint32_t is_g_ge_p = (g[4] >> 26) & 1;
	uint32_t mask = (uint32_t)0 - is_g_ge_p;

	for (int i = 0; i < 5; ++i) { ctx->h[i] = (ctx->h[i] & ~mask) | (g[i] & mask); }

	uint64_t f0 = (uint64_t)ctx->h[0] | ((uint64_t)ctx->h[1] << 26);
	uint64_t f1 = ((uint64_t)ctx->h[1] >> 6) | ((uint64_t)ctx->h[2] << 20);
	uint64_t f2 = ((uint64_t)ctx->h[2] >> 12) | ((uint64_t)ctx->h[3] << 14);
	uint64_t f3 = ((uint64_t)ctx->h[3] >> 18) | ((uint64_t)ctx->h[4] << 8);

	uint64_t tag0 = f0 + (uint64_t)ctx->pad[0];
	uint64_t tag1 = f1 + (uint64_t)ctx->pad[1] + (tag0 >> 32);
	uint64_t tag2 = f2 + (uint64_t)ctx->pad[2] + (tag1 >> 32);
	uint64_t tag3 = f3 + (uint64_t)ctx->pad[3] + (tag2 >> 32);

	store32_le (tag + 0, (uint32_t)tag0);
	store32_le (tag + 4, (uint32_t)tag1);
	store32_le (tag + 8, (uint32_t)tag2);
	store32_le (tag + 12, (uint32_t)tag3);
}

declfn auto chacha20_poly1305_encrypt(
	_In_ const uint8_t key[CHACHA20_KEY_SIZE],
	_In_ const uint8_t nonce[CHACHA20_NONCE_SIZE], _In_ const uint8_t* aad,
	_In_ size_t        aad_len, _In_ const uint8_t*                    plaintext,
	_In_ size_t        plaintext_len, _Out_ uint8_t*                   ciphertext,
	_Out_ uint8_t      tag[POLY1305_TAG_SIZE]) -> void {
	CHACHA20_CTX chacha_ctx;
	uint8_t      poly_key[POLY1305_KEY_SIZE];

	memory::secure_erase (poly_key, POLY1305_KEY_SIZE);

	chacha20_init (&chacha_ctx, key, nonce, 0);
	chacha20_encrypt_decrypt (&chacha_ctx, poly_key, POLY1305_KEY_SIZE);

	chacha20_reset_counter (&chacha_ctx, 1);
	if (plaintext_len > 0) {
		memory::copy (ciphertext, plaintext, plaintext_len);
		chacha20_encrypt_decrypt (&chacha_ctx, ciphertext, plaintext_len);
	}

	POLY1305_CTX poly_ctx;
	poly1305_init (&poly_ctx, poly_key);

	if (aad && aad_len > 0) {
		poly1305_update (&poly_ctx, aad, aad_len);
		size_t aad_pad = (16 - (aad_len % 16)) % 16;
		if (aad_pad) {
			uint8_t zero[16] = { 0 };
			poly1305_update (&poly_ctx, zero, aad_pad);
		}
	}

	if (plaintext_len > 0) {
		poly1305_update (&poly_ctx, ciphertext, plaintext_len);
		size_t ct_pad = (16 - (plaintext_len % 16)) % 16;
		if (ct_pad) {
			uint8_t zero[16] = { 0 };
			poly1305_update (&poly_ctx, zero, ct_pad);
		}
	}

	uint8_t  len_block[16];
	uint64_t aad_len_bytes = (uint64_t)aad_len;
	uint64_t pt_len_bytes = (uint64_t)plaintext_len;

	for (int i = 0; i < 8; ++i) len_block[i] = (uint8_t)((aad_len_bytes >> (8 * i)) & 0xff);
	for (int i = 0; i < 8; ++i) len_block[8 + i] = (uint8_t)((pt_len_bytes >> (8 * i)) & 0xff);

	poly1305_update (&poly_ctx, len_block, 16);
	poly1305_final (&poly_ctx, tag);

	memory::secure_erase (&chacha_ctx, sizeof(chacha_ctx));
	memory::secure_erase (poly_key, POLY1305_KEY_SIZE);
	memory::secure_erase (len_block, sizeof(len_block));
}

declfn auto chacha20_poly1305_decrypt(
	_In_ const uint8_t key[CHACHA20_KEY_SIZE],
	_In_ const uint8_t nonce[CHACHA20_NONCE_SIZE], _In_ const uint8_t* aad,
	_In_ size_t        aad_len, _In_ const uint8_t*                    ciphertext,
	_In_ size_t        ciphertext_len, _In_ const uint8_t              tag[POLY1305_TAG_SIZE],
	_Out_ uint8_t*     plaintext) -> bool {
	CHACHA20_CTX chacha_ctx;
	uint8_t      poly_key[POLY1305_KEY_SIZE];
	memory::secure_erase (poly_key, POLY1305_KEY_SIZE);

	chacha20_init (&chacha_ctx, key, nonce, 0);
	chacha20_encrypt_decrypt (&chacha_ctx, poly_key, POLY1305_KEY_SIZE);

	POLY1305_CTX poly_ctx;
	poly1305_init (&poly_ctx, poly_key);

	if (aad && aad_len > 0) {
		poly1305_update (&poly_ctx, aad, aad_len);
		size_t aad_pad = (16 - (aad_len % 16)) % 16;
		if (aad_pad) {
			uint8_t zero[16] = { 0 };
			poly1305_update (&poly_ctx, zero, aad_pad);
		}
	}

	if (ciphertext_len > 0) {
		poly1305_update (&poly_ctx, ciphertext, ciphertext_len);
		size_t ct_pad = (16 - (ciphertext_len % 16)) % 16;
		if (ct_pad) {
			uint8_t zero[16] = { 0 };
			poly1305_update (&poly_ctx, zero, ct_pad);
		}
	}

	uint8_t  len_block[16];
	uint64_t aad_len_bytes = (uint64_t)aad_len;
	uint64_t ct_len_bytes = (uint64_t)ciphertext_len;
	for (int i = 0; i < 8; ++i) len_block[i] = (uint8_t)((aad_len_bytes >> (8 * i)) & 0xff);
	for (int i = 0; i < 8; ++i) len_block[8 + i] = (uint8_t)((ct_len_bytes >> (8 * i)) & 0xff);

	poly1305_update (&poly_ctx, len_block, 16);

	uint8_t computed_tag[POLY1305_TAG_SIZE];
	poly1305_final (&poly_ctx, computed_tag);

	uint8_t res = 0;
	for (size_t i = 0; i < POLY1305_TAG_SIZE; ++i) res |= (tag[i] ^ computed_tag[i]);
	bool valid = (res == 0);

	if (!constant_time_equals(tag, computed_tag, POLY1305_TAG_SIZE)) {
		memory::secure_erase(plaintext, ciphertext_len);
		return false;
	}
	if (valid && ciphertext_len > 0) {
		chacha20_reset_counter (&chacha_ctx, 1);
		memory::copy (plaintext, ciphertext, ciphertext_len);
		chacha20_encrypt_decrypt (&chacha_ctx, plaintext, ciphertext_len);
	}

	memory::secure_erase (&chacha_ctx, sizeof(chacha_ctx));
	memory::secure_erase (poly_key, POLY1305_KEY_SIZE);
	memory::secure_erase (computed_tag, sizeof(computed_tag));
	memory::secure_erase (len_block, sizeof(len_block));

	return valid;
}

declfn auto constant_time_equals(_In_ const uint8_t* a,
                                           _In_ const uint8_t* b, _In_ size_t len) -> bool {
	if (!a || !b) return false;

	volatile uint8_t result = 0;
	for (size_t i = 0; i < len; i++) { result |= a[i] ^ b[i]; }
	asm volatile("" : "+r"(result) :: "memory");
	return result == 0;
}
