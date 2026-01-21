#include <memory.h>
#include <sha256.h>

namespace Crypto {
	static constexpr uint32_t K[64] = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
			0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
			0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
			0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
			0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
			0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))
#define SHA256_ROUND(a, b, c, d, e, f, g, h, w, k)  \
  do {                                              \
    uint32_t t1 = h + EP1(e) + CH(e, f, g) + k + w; \
    uint32_t t2 = EP0(a) + MAJ(a, b, c);            \
    h = g;                                          \
    g = f;                                          \
    f = e;                                          \
    e = d + t1;                                     \
    d = c;                                          \
    c = b;                                          \
    b = a;                                          \
    a = t1 + t2;                                    \
  } while (0)

	inline auto be32_unpack(const uint8_t* data) -> uint32_t {
		return (static_cast<uint32_t> (data[0]) << 24) |
				(static_cast<uint32_t> (data[1]) << 16) |
				(static_cast<uint32_t> (data[2]) << 8) | static_cast<uint32_t> (data[3]);
	}

	inline auto be32_pack(uint8_t* out, uint32_t val) -> void {
		out[0] = (val >> 24) & 0xff;
		out[1] = (val >> 16) & 0xff;
		out[2] = (val >> 8) & 0xff;
		out[3] = val & 0xff;
	}

	static declfn auto sha256_transform(
		_Inout_ SHA256_CTX* ctx, _In_ const uint8_t data[SHA256_BLOCK_SIZE]) -> void {
		uint32_t w[64];
		uint32_t S[8];
		uint32_t t1, t2;

		for (int i = 0; i < 8; i++) S[i] = ctx->state[i];

		for (int i = 0; i < 16; ++i) { w[i] = be32_unpack (&data[i * 4]); }
		for (int i = 16; i < 64; ++i) { w[i] = SIG1 (w[i - 2]) + w[i - 7] + SIG0 (w[i - 15]) + w[i - 16]; }

		for (int i = 0; i < 64; ++i) {
			t1 = S[7] + EP1 (S[4]) + CH (S[4], S[5], S[6]) + K[i] + w[i];
			t2 = EP0 (S[0]) + MAJ (S[0], S[1], S[2]);

			S[7] = S[6];
			S[6] = S[5];
			S[5] = S[4];
			S[4] = S[3] + t1;
			S[3] = S[2];
			S[2] = S[1];
			S[1] = S[0];
			S[0] = t1 + t2;
		}

		for (int i = 0; i < 8; i++) ctx->state[i] += S[i];

		memory::secure_erase (w, sizeof(w));
	}

	static declfn auto sha256_init(_Out_ SHA256_CTX* ctx) -> void {
		ctx->datalen = 0;
		ctx->bitlen = 0;
		ctx->state[0] = 0x6a09e667;
		ctx->state[1] = 0xbb67ae85;
		ctx->state[2] = 0x3c6ef372;
		ctx->state[3] = 0xa54ff53a;
		ctx->state[4] = 0x510e527f;
		ctx->state[5] = 0x9b05688c;
		ctx->state[6] = 0x1f83d9ab;
		ctx->state[7] = 0x5be0cd19;
	}

	static declfn auto sha256_update(_Inout_ SHA256_CTX* ctx,
	                                           _In_ const uint8_t* data, _In_ size_t len) -> void {
		while (len > 0) {
			size_t space = SHA256_BLOCK_SIZE - ctx->datalen;
			size_t to_copy = len < space ? len : space;

			memory::copy (&ctx->data[ctx->datalen], data, to_copy);
			ctx->datalen += to_copy;
			data += to_copy;
			len -= to_copy;

			if (ctx->datalen == SHA256_BLOCK_SIZE) {
				sha256_transform (ctx, ctx->data);
				ctx->bitlen += 512;
				ctx->datalen = 0;
			}
		}
	}

	static declfn auto sha256_final(_Inout_ SHA256_CTX* ctx,
	                                          _Out_ uint8_t       hash[SHA256_HASH_SIZE]) -> void {
		auto       i = ctx->datalen;
		const auto final_bitlen = ctx->bitlen + (ctx->datalen * 8);

		ctx->data[i++] = 0x80;

		if (i > 56) {
			memory::secure_erase (&ctx->data[i], SHA256_BLOCK_SIZE - i);
			sha256_transform (ctx, ctx->data);
			i = 0;
		}

		memory::secure_erase (&ctx->data[i], 56 - i);

		be32_pack (&ctx->data[56], static_cast<uint32_t> (final_bitlen >> 32));
		be32_pack (&ctx->data[60], static_cast<uint32_t> (final_bitlen));

		sha256_transform (ctx, ctx->data);

		for (size_t j = 0; j < 8; ++j) { be32_pack (&hash[j * 4], ctx->state[j]); }
	}

	declfn auto sha256(_In_ const uint8_t* data, _In_ size_t len,
	                             _Out_ uint8_t       hash[SHA256_HASH_SIZE]) -> void {
		SHA256_CTX ctx;
		sha256_init (&ctx);
		sha256_update (&ctx, data, len);
		sha256_final (&ctx, hash);
	}

	declfn auto hmac_sha256(_In_ const uint8_t* key, _In_ size_t  keylen,
	                                  _In_ const uint8_t* data, _In_ size_t datalen,
	                                  _Out_ uint8_t       hash[SHA256_HASH_SIZE]) -> void {
		uint8_t k_ipad[SHA256_BLOCK_SIZE];
		uint8_t k_opad[SHA256_BLOCK_SIZE];
		uint8_t tk[SHA256_HASH_SIZE];
		uint8_t inner_hash[SHA256_HASH_SIZE];

		if (keylen > SHA256_BLOCK_SIZE) {
			sha256 (key, keylen, tk);
			key = tk;
			keylen = SHA256_HASH_SIZE;
		}

		memory::secure_erase (k_ipad, SHA256_BLOCK_SIZE);
		memory::secure_erase (k_opad, SHA256_BLOCK_SIZE);
		memory::copy (k_ipad, key, keylen);
		memory::copy (k_opad, key, keylen);

		for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
			k_ipad[i] ^= 0x36;
			k_opad[i] ^= 0x5c;
		}

		SHA256_CTX ctx;
		sha256_init (&ctx);
		sha256_update (&ctx, k_ipad, SHA256_BLOCK_SIZE);
		sha256_update (&ctx, data, datalen);
		sha256_final (&ctx, inner_hash);

		sha256_init (&ctx);
		sha256_update (&ctx, k_opad, SHA256_BLOCK_SIZE);
		sha256_update (&ctx, inner_hash, SHA256_HASH_SIZE);
		sha256_final (&ctx, hash);

		memory::secure_erase (k_ipad, SHA256_BLOCK_SIZE);
		memory::secure_erase (k_opad, SHA256_BLOCK_SIZE);
		memory::secure_erase (tk, SHA256_HASH_SIZE);
		memory::secure_erase (inner_hash, SHA256_HASH_SIZE);
	}
}
