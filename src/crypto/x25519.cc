#include <x25519.h>
#include <prng.h>
#include <memory.h>
#include <common.h>

using namespace Crypto;

namespace {
	typedef uint8_t u8;
	typedef int32_t s32;
	typedef int64_t limb;

	static void fsum(limb* output, const limb* in) {
		unsigned i;
		for (i = 0; i < 10; i += 2) {
			output[0 + i] = output[0 + i] + in[0 + i];
			output[1 + i] = output[1 + i] + in[1 + i];
		}
	}

	static void fdifference(limb* output, const limb* in) {
		unsigned i;
		for (i = 0; i < 10; ++i) { output[i] = in[i] - output[i]; }
	}

	static void fscalar_product(limb* output, const limb* in, const limb scalar) {
		unsigned i;
		for (i = 0; i < 10; ++i) { output[i] = in[i] * scalar; }
	}

	static void fproduct(limb* output, const limb* in2, const limb* in) {
		output[0] = ((limb)((s32)in2[0])) * ((s32)in[0]);
		output[1] = ((limb)((s32)in2[0])) * ((s32)in[1]) +
				((limb)((s32)in2[1])) * ((s32)in[0]);
		output[2] = 2 * ((limb)((s32)in2[1])) * ((s32)in[1]) +
				((limb)((s32)in2[0])) * ((s32)in[2]) +
				((limb)((s32)in2[2])) * ((s32)in[0]);
		output[3] = ((limb)((s32)in2[1])) * ((s32)in[2]) +
				((limb)((s32)in2[2])) * ((s32)in[1]) +
				((limb)((s32)in2[0])) * ((s32)in[3]) +
				((limb)((s32)in2[3])) * ((s32)in[0]);
		output[4] = ((limb)((s32)in2[2])) * ((s32)in[2]) +
				2 * (((limb)((s32)in2[1])) * ((s32)in[3]) +
					((limb)((s32)in2[3])) * ((s32)in[1])) +
				((limb)((s32)in2[0])) * ((s32)in[4]) +
				((limb)((s32)in2[4])) * ((s32)in[0]);
		output[5] = ((limb)((s32)in2[2])) * ((s32)in[3]) +
				((limb)((s32)in2[3])) * ((s32)in[2]) +
				((limb)((s32)in2[1])) * ((s32)in[4]) +
				((limb)((s32)in2[4])) * ((s32)in[1]) +
				((limb)((s32)in2[0])) * ((s32)in[5]) +
				((limb)((s32)in2[5])) * ((s32)in[0]);
		output[6] = 2 * (((limb)((s32)in2[3])) * ((s32)in[3]) +
					((limb)((s32)in2[1])) * ((s32)in[5]) +
					((limb)((s32)in2[5])) * ((s32)in[1])) +
				((limb)((s32)in2[2])) * ((s32)in[4]) +
				((limb)((s32)in2[4])) * ((s32)in[2]) +
				((limb)((s32)in2[0])) * ((s32)in[6]) +
				((limb)((s32)in2[6])) * ((s32)in[0]);
		output[7] = ((limb)((s32)in2[3])) * ((s32)in[4]) +
				((limb)((s32)in2[4])) * ((s32)in[3]) +
				((limb)((s32)in2[2])) * ((s32)in[5]) +
				((limb)((s32)in2[5])) * ((s32)in[2]) +
				((limb)((s32)in2[1])) * ((s32)in[6]) +
				((limb)((s32)in2[6])) * ((s32)in[1]) +
				((limb)((s32)in2[0])) * ((s32)in[7]) +
				((limb)((s32)in2[7])) * ((s32)in[0]);
		output[8] = ((limb)((s32)in2[4])) * ((s32)in[4]) +
				2 * (((limb)((s32)in2[3])) * ((s32)in[5]) +
					((limb)((s32)in2[5])) * ((s32)in[3]) +
					((limb)((s32)in2[1])) * ((s32)in[7]) +
					((limb)((s32)in2[7])) * ((s32)in[1])) +
				((limb)((s32)in2[2])) * ((s32)in[6]) +
				((limb)((s32)in2[6])) * ((s32)in[2]) +
				((limb)((s32)in2[0])) * ((s32)in[8]) +
				((limb)((s32)in2[8])) * ((s32)in[0]);
		output[9] = ((limb)((s32)in2[4])) * ((s32)in[5]) +
				((limb)((s32)in2[5])) * ((s32)in[4]) +
				((limb)((s32)in2[3])) * ((s32)in[6]) +
				((limb)((s32)in2[6])) * ((s32)in[3]) +
				((limb)((s32)in2[2])) * ((s32)in[7]) +
				((limb)((s32)in2[7])) * ((s32)in[2]) +
				((limb)((s32)in2[1])) * ((s32)in[8]) +
				((limb)((s32)in2[8])) * ((s32)in[1]) +
				((limb)((s32)in2[0])) * ((s32)in[9]) +
				((limb)((s32)in2[9])) * ((s32)in[0]);
		output[10] = 2 * (((limb)((s32)in2[5])) * ((s32)in[5]) +
					((limb)((s32)in2[3])) * ((s32)in[7]) +
					((limb)((s32)in2[7])) * ((s32)in[3]) +
					((limb)((s32)in2[1])) * ((s32)in[9]) +
					((limb)((s32)in2[9])) * ((s32)in[1])) +
				((limb)((s32)in2[4])) * ((s32)in[6]) +
				((limb)((s32)in2[6])) * ((s32)in[4]) +
				((limb)((s32)in2[2])) * ((s32)in[8]) +
				((limb)((s32)in2[8])) * ((s32)in[2]);
		output[11] = ((limb)((s32)in2[5])) * ((s32)in[6]) +
				((limb)((s32)in2[6])) * ((s32)in[5]) +
				((limb)((s32)in2[4])) * ((s32)in[7]) +
				((limb)((s32)in2[7])) * ((s32)in[4]) +
				((limb)((s32)in2[3])) * ((s32)in[8]) +
				((limb)((s32)in2[8])) * ((s32)in[3]) +
				((limb)((s32)in2[2])) * ((s32)in[9]) +
				((limb)((s32)in2[9])) * ((s32)in[2]);
		output[12] = ((limb)((s32)in2[6])) * ((s32)in[6]) +
				2 * (((limb)((s32)in2[5])) * ((s32)in[7]) +
					((limb)((s32)in2[7])) * ((s32)in[5]) +
					((limb)((s32)in2[3])) * ((s32)in[9]) +
					((limb)((s32)in2[9])) * ((s32)in[3])) +
				((limb)((s32)in2[4])) * ((s32)in[8]) +
				((limb)((s32)in2[8])) * ((s32)in[4]);
		output[13] = ((limb)((s32)in2[6])) * ((s32)in[7]) +
				((limb)((s32)in2[7])) * ((s32)in[6]) +
				((limb)((s32)in2[5])) * ((s32)in[8]) +
				((limb)((s32)in2[8])) * ((s32)in[5]) +
				((limb)((s32)in2[4])) * ((s32)in[9]) +
				((limb)((s32)in2[9])) * ((s32)in[4]);
		output[14] = 2 * (((limb)((s32)in2[7])) * ((s32)in[7]) +
					((limb)((s32)in2[5])) * ((s32)in[9]) +
					((limb)((s32)in2[9])) * ((s32)in[5])) +
				((limb)((s32)in2[6])) * ((s32)in[8]) +
				((limb)((s32)in2[8])) * ((s32)in[6]);
		output[15] = ((limb)((s32)in2[7])) * ((s32)in[8]) +
				((limb)((s32)in2[8])) * ((s32)in[7]) +
				((limb)((s32)in2[6])) * ((s32)in[9]) +
				((limb)((s32)in2[9])) * ((s32)in[6]);
		output[16] = ((limb)((s32)in2[8])) * ((s32)in[8]) +
				2 * (((limb)((s32)in2[7])) * ((s32)in[9]) +
					((limb)((s32)in2[9])) * ((s32)in[7]));
		output[17] = ((limb)((s32)in2[8])) * ((s32)in[9]) +
				((limb)((s32)in2[9])) * ((s32)in[8]);
		output[18] = 2 * ((limb)((s32)in2[9])) * ((s32)in[9]);
	}

	static void freduce_degree(limb* output) {
		output[8] += output[18] << 4;
		output[8] += output[18] << 1;
		output[8] += output[18];
		output[7] += output[17] << 4;
		output[7] += output[17] << 1;
		output[7] += output[17];
		output[6] += output[16] << 4;
		output[6] += output[16] << 1;
		output[6] += output[16];
		output[5] += output[15] << 4;
		output[5] += output[15] << 1;
		output[5] += output[15];
		output[4] += output[14] << 4;
		output[4] += output[14] << 1;
		output[4] += output[14];
		output[3] += output[13] << 4;
		output[3] += output[13] << 1;
		output[3] += output[13];
		output[2] += output[12] << 4;
		output[2] += output[12] << 1;
		output[2] += output[12];
		output[1] += output[11] << 4;
		output[1] += output[11] << 1;
		output[1] += output[11];
		output[0] += output[10] << 4;
		output[0] += output[10] << 1;
		output[0] += output[10];
	}
#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif

	static inline limb div_by_2_26(const limb v) {
		const uint32_t highword = (uint32_t)(((uint64_t)v) >> 32);

		const int32_t sign = ((int32_t)highword) >> 31;

		const int32_t roundoff = ((uint32_t)sign) >> 6;

		return (v + roundoff) >> 26;
	}

	static inline limb div_by_2_25(const limb v) {
		const uint32_t highword = (uint32_t)(((uint64_t)v) >> 32);

		const int32_t sign = ((int32_t)highword) >> 31;

		const int32_t roundoff = ((uint32_t)sign) >> 7;

		return (v + roundoff) >> 25;
	}

	static void freduce_coefficients(limb* output) {
		unsigned i;
		output[10] = 0;
		for (i = 0; i < 10; i += 2) {
			limb over = div_by_2_26 (output[i]);

			output[i] -= over << 26;
			output[i + 1] += over;

			over = div_by_2_25 (output[i + 1]);
			output[i + 1] -= over << 25;
			output[i + 2] += over;
		}

		output[0] += output[10] << 4;
		output[0] += output[10] << 1;
		output[0] += output[10];
		output[10] = 0; {
			limb over = div_by_2_26 (output[0]);
			output[0] -= over << 26;
			output[1] += over;
		}
	}

	static void fmul(limb* output, const limb* in, const limb* in2) {
		limb t[19];
		fproduct (t, in, in2);

		freduce_degree (t);
		freduce_coefficients (t);

		memory::copy (output, t, sizeof (limb) * 10);
	}

	static void fsquare_inner(limb* output, const limb* in) {
		output[0] = ((limb)((s32)in[0])) * ((s32)in[0]);
		output[1] = 2 * ((limb)((s32)in[0])) * ((s32)in[1]);
		output[2] = 2 * (((limb)((s32)in[1])) * ((s32)in[1]) +
			((limb)((s32)in[0])) * ((s32)in[2]));
		output[3] = 2 * (((limb)((s32)in[1])) * ((s32)in[2]) +
			((limb)((s32)in[0])) * ((s32)in[3]));
		output[4] = ((limb)((s32)in[2])) * ((s32)in[2]) +
				4 * ((limb)((s32)in[1])) * ((s32)in[3]) +
				2 * ((limb)((s32)in[0])) * ((s32)in[4]);
		output[5] = 2 * (((limb)((s32)in[2])) * ((s32)in[3]) +
			((limb)((s32)in[1])) * ((s32)in[4]) +
			((limb)((s32)in[0])) * ((s32)in[5]));
		output[6] = 2 * (((limb)((s32)in[3])) * ((s32)in[3]) +
			((limb)((s32)in[2])) * ((s32)in[4]) +
			((limb)((s32)in[0])) * ((s32)in[6]) +
			2 * ((limb)((s32)in[1])) * ((s32)in[5]));
		output[7] = 2 * (((limb)((s32)in[3])) * ((s32)in[4]) +
			((limb)((s32)in[2])) * ((s32)in[5]) +
			((limb)((s32)in[1])) * ((s32)in[6]) +
			((limb)((s32)in[0])) * ((s32)in[7]));
		output[8] = ((limb)((s32)in[4])) * ((s32)in[4]) +
				2 * (((limb)((s32)in[2])) * ((s32)in[6]) +
					((limb)((s32)in[0])) * ((s32)in[8]) +
					2 * (((limb)((s32)in[1])) * ((s32)in[7]) +
						((limb)((s32)in[3])) * ((s32)in[5])));
		output[9] = 2 * (((limb)((s32)in[4])) * ((s32)in[5]) +
			((limb)((s32)in[3])) * ((s32)in[6]) +
			((limb)((s32)in[2])) * ((s32)in[7]) +
			((limb)((s32)in[1])) * ((s32)in[8]) +
			((limb)((s32)in[0])) * ((s32)in[9]));
		output[10] = 2 * (((limb)((s32)in[5])) * ((s32)in[5]) +
			((limb)((s32)in[4])) * ((s32)in[6]) +
			((limb)((s32)in[2])) * ((s32)in[8]) +
			2 * (((limb)((s32)in[3])) * ((s32)in[7]) +
				((limb)((s32)in[1])) * ((s32)in[9])));
		output[11] = 2 * (((limb)((s32)in[5])) * ((s32)in[6]) +
			((limb)((s32)in[4])) * ((s32)in[7]) +
			((limb)((s32)in[3])) * ((s32)in[8]) +
			((limb)((s32)in[2])) * ((s32)in[9]));
		output[12] = ((limb)((s32)in[6])) * ((s32)in[6]) +
				2 * (((limb)((s32)in[4])) * ((s32)in[8]) +
					2 * (((limb)((s32)in[5])) * ((s32)in[7]) +
						((limb)((s32)in[3])) * ((s32)in[9])));
		output[13] = 2 * (((limb)((s32)in[6])) * ((s32)in[7]) +
			((limb)((s32)in[5])) * ((s32)in[8]) +
			((limb)((s32)in[4])) * ((s32)in[9]));
		output[14] = 2 * (((limb)((s32)in[7])) * ((s32)in[7]) +
			((limb)((s32)in[6])) * ((s32)in[8]) +
			2 * ((limb)((s32)in[5])) * ((s32)in[9]));
		output[15] = 2 * (((limb)((s32)in[7])) * ((s32)in[8]) +
			((limb)((s32)in[6])) * ((s32)in[9]));
		output[16] = ((limb)((s32)in[8])) * ((s32)in[8]) +
				4 * ((limb)((s32)in[7])) * ((s32)in[9]);
		output[17] = 2 * ((limb)((s32)in[8])) * ((s32)in[9]);
		output[18] = 2 * ((limb)((s32)in[9])) * ((s32)in[9]);
	}

	static void fsquare(limb* output, const limb* in) {
		limb t[19];
		fsquare_inner (t, in);

		freduce_degree (t);
		freduce_coefficients (t);

		memory::copy (output, t, sizeof (limb) * 10);
	}

	static void fexpand(limb* output, const u8* input) {
#define F(n,start,shift,mask) \
  output[n] = ((((limb) input[start + 0]) | \
                ((limb) input[start + 1]) << 8 | \
                ((limb) input[start + 2]) << 16 | \
                ((limb) input[start + 3]) << 24) >> shift) & mask;
		F (0, 0, 0, 0x3ffffff);
		F (1, 3, 2, 0x1ffffff);
		F (2, 6, 3, 0x3ffffff);
		F (3, 9, 5, 0x1ffffff);
		F (4, 12, 6, 0x3ffffff);
		F (5, 16, 0, 0x1ffffff);
		F (6, 19, 1, 0x3ffffff);
		F (7, 22, 3, 0x1ffffff);
		F (8, 25, 4, 0x3ffffff);
		F (9, 28, 6, 0x1ffffff);
#undef F
	}
#if (-32 >> 1) != -16
#error "This code only works when >> does sign-extension on negative numbers"
#endif

	static s32 s32_eq(s32 a, s32 b) {
		a = ~(a ^ b);
		a &= a << 16;
		a &= a << 8;
		a &= a << 4;
		a &= a << 2;
		a &= a << 1;
		return a >> 31;
	}

	static s32 s32_gte(s32 a, s32 b) {
		a -= b;

		return ~(a >> 31);
	}

	static void fcontract(u8* output, limb* input_limbs) {
		int i;
		int j;
		s32 input[10];
		s32 mask;

		for (i = 0; i < 10; i++) { input[i] = input_limbs[i]; }
		for (j = 0; j < 2; ++j) {
			for (i = 0; i < 9; ++i) {
				if ((i & 1) == 1) {
					const s32 mask = input[i] >> 31;
					const s32 carry = -((input[i] & mask) >> 25);
					input[i] = input[i] + (carry << 25);
					input[i + 1] = input[i + 1] - carry;
				} else {
					const s32 mask = input[i] >> 31;
					const s32 carry = -((input[i] & mask) >> 26);
					input[i] = input[i] + (carry << 26);
					input[i + 1] = input[i + 1] - carry;
				}
			} {
				const s32 mask = input[9] >> 31;
				const s32 carry = -((input[9] & mask) >> 25);
				input[9] = input[9] + (carry << 25);
				input[0] = input[0] - (carry * 19);
			}
		} {
			const s32 mask = input[0] >> 31;
			const s32 carry = -((input[0] & mask) >> 26);
			input[0] = input[0] + (carry << 26);
			input[1] = input[1] - carry;
		}

		for (j = 0; j < 2; j++) {
			for (i = 0; i < 9; i++) {
				if ((i & 1) == 1) {
					const s32 carry = input[i] >> 25;
					input[i] &= 0x1ffffff;
					input[i + 1] += carry;
				} else {
					const s32 carry = input[i] >> 26;
					input[i] &= 0x3ffffff;
					input[i + 1] += carry;
				}
			} {
				const s32 carry = input[9] >> 25;
				input[9] &= 0x1ffffff;
				input[0] += 19 * carry;
			}
		}

		mask = s32_gte (input[0], 0x3ffffed);
		for (i = 1; i < 10; i++) {
			if ((i & 1) == 1) { mask &= s32_eq (input[i], 0x1ffffff); } else { mask &= s32_eq (input[i], 0x3ffffff); }
		}

		input[0] -= mask & 0x3ffffed;
		for (i = 1; i < 10; i++) {
			if ((i & 1) == 1) { input[i] -= mask & 0x1ffffff; } else { input[i] -= mask & 0x3ffffff; }
		}
		input[1] <<= 2;
		input[2] <<= 3;
		input[3] <<= 5;
		input[4] <<= 6;
		input[6] <<= 1;
		input[7] <<= 3;
		input[8] <<= 4;
		input[9] <<= 6;
#define F(i, s) \
  output[s+0] |=  input[i] & 0xff; \
  output[s+1]  = (input[i] >> 8) & 0xff; \
  output[s+2]  = (input[i] >> 16) & 0xff; \
  output[s+3]  = (input[i] >> 24) & 0xff;
		output[0] = 0;
		output[16] = 0;
		F (0, 0);
		F (1, 3);
		F (2, 6);
		F (3, 9);
		F (4, 12);
		F (5, 16);
		F (6, 19);
		F (7, 22);
		F (8, 25);
		F (9, 28);
#undef F
	}

	static void fmonty(limb*       x2, limb*     z2,
	                   limb*       x3, limb*     z3,
	                   limb*       x, limb*      z,
	                   limb*       xprime, limb* zprime,
	                   const limb* qmqp) {
		limb                           origx[10],    origxprime[10], zzz[19], xx[19], zz[19], xxprime[19],
		                  zzprime[19], zzzprime[19], xxxprime[19];
		memory::copy (origx, x, 10 * sizeof (limb));
		fsum (x, z);

		fdifference (z, origx);

		memory::copy (origxprime, xprime, sizeof (limb) * 10);
		fsum (xprime, zprime);

		fdifference (zprime, origxprime);

		fproduct (xxprime, xprime, z);

		fproduct (zzprime, x, zprime);

		freduce_degree (xxprime);
		freduce_coefficients (xxprime);

		freduce_degree (zzprime);
		freduce_coefficients (zzprime);

		memory::copy (origxprime, xxprime, sizeof (limb) * 10);
		fsum (xxprime, zzprime);

		fdifference (zzprime, origxprime);

		fsquare (xxxprime, xxprime);

		fsquare (zzzprime, zzprime);

		fproduct (zzprime, zzzprime, qmqp);

		freduce_degree (zzprime);
		freduce_coefficients (zzprime);

		memory::copy (x3, xxxprime, sizeof (limb) * 10);
		memory::copy (z3, zzprime, sizeof (limb) * 10);
		fsquare (xx, x);

		fsquare (zz, z);

		fproduct (x2, xx, zz);

		freduce_degree (x2);
		freduce_coefficients (x2);

		fdifference (zz, xx);

		memory::set (zzz + 10, 0, sizeof (limb) * 9);
		fscalar_product (zzz, zz, 121665);

		freduce_coefficients (zzz);

		fsum (zzz, xx);

		fproduct (z2, zz, zzz);

		freduce_degree (z2);
		freduce_coefficients (z2);
	}

	static void swap_conditional(limb a[19], limb b[19], limb iswap) {
		unsigned  i;
		const s32 swap = (s32)-iswap;
		for (i = 0; i < 10; ++i) {
			const s32 x = swap & (((s32)a[i]) ^ ((s32)b[i]));
			a[i] = ((s32)a[i]) ^ x;
			b[i] = ((s32)b[i]) ^ x;
		}
	}

	static void cmult(limb* resultx, limb* resultz, const u8* n, const limb* q) {
		limb     a[19] = { 0 }, b[19] = { 1 }, c[19] = { 1 }, d[19] = { 0 };
		limb*    nqpqx = a,*    nqpqz = b,*    nqx = c,*      nqz = d,* t;
		limb     e[19] = { 0 }, f[19] = { 1 }, g[19] = { 0 }, h[19] = { 1 };
		limb*    nqpqx2 = e,*   nqpqz2 = f,*   nqx2 = g,*     nqz2 = h;
		unsigned i,             j;
		memory::copy (nqpqx, q, sizeof (limb) * 10);
		for (i = 0; i < 32; ++i) {
			u8 byte = n[31 - i];
			for (j = 0; j < 8; ++j) {
				const limb bit = byte >> 7;
				swap_conditional (nqx, nqpqx, bit);
				swap_conditional (nqz, nqpqz, bit);
				fmonty (nqx2, nqz2,
				        nqpqx2, nqpqz2,
				        nqx, nqz,
				        nqpqx, nqpqz,
				        q);
				swap_conditional (nqx2, nqpqx2, bit);
				swap_conditional (nqz2, nqpqz2, bit);
				t = nqx;
				nqx = nqx2;
				nqx2 = t;
				t = nqz;
				nqz = nqz2;
				nqz2 = t;
				t = nqpqx;
				nqpqx = nqpqx2;
				nqpqx2 = t;
				t = nqpqz;
				nqpqz = nqpqz2;
				nqpqz2 = t;
				byte <<= 1;
			}
		}
		memory::copy (resultx, nqx, sizeof (limb) * 10);
		memory::copy (resultz, nqz, sizeof (limb) * 10);
	}

	static void crecip(limb* out, const limb* z) {
		limb z2[10];
		limb z9[10];
		limb z11[10];
		limb z2_5_0[10];
		limb z2_10_0[10];
		limb z2_20_0[10];
		limb z2_50_0[10];
		limb z2_100_0[10];
		limb t0[10];
		limb t1[10];
		int  i;

		fsquare (z2, z);

		fsquare (t1, z2);

		fsquare (t0, t1);

		fmul (z9, t0, z);

		fmul (z11, z9, z2);

		fsquare (t0, z11);

		fmul (z2_5_0, t0, z9);

		fsquare (t0, z2_5_0);

		fsquare (t1, t0);

		fsquare (t0, t1);

		fsquare (t1, t0);

		fsquare (t0, t1);

		fmul (z2_10_0, t0, z2_5_0);

		fsquare (t0, z2_10_0);

		fsquare (t1, t0);

		for (i = 2; i < 10; i += 2) {
			fsquare (t0, t1);
			fsquare (t1, t0);
		}

		fmul (z2_20_0, t1, z2_10_0);

		fsquare (t0, z2_20_0);

		fsquare (t1, t0);

		for (i = 2; i < 20; i += 2) {
			fsquare (t0, t1);
			fsquare (t1, t0);
		}

		fmul (t0, t1, z2_20_0);

		fsquare (t1, t0);

		fsquare (t0, t1);

		for (i = 2; i < 10; i += 2) {
			fsquare (t1, t0);
			fsquare (t0, t1);
		}

		fmul (z2_50_0, t0, z2_10_0);

		fsquare (t0, z2_50_0);

		fsquare (t1, t0);

		for (i = 2; i < 50; i += 2) {
			fsquare (t0, t1);
			fsquare (t1, t0);
		}

		fmul (z2_100_0, t1, z2_50_0);

		fsquare (t1, z2_100_0);

		fsquare (t0, t1);

		for (i = 2; i < 100; i += 2) {
			fsquare (t1, t0);
			fsquare (t0, t1);
		}

		fmul (t1, t0, z2_100_0);

		fsquare (t0, t1);

		fsquare (t1, t0);

		for (i = 2; i < 50; i += 2) {
			fsquare (t0, t1);
			fsquare (t1, t0);
		}

		fmul (t0, t1, z2_50_0);

		fsquare (t1, t0);

		fsquare (t0, t1);

		fsquare (t1, t0);

		fsquare (t0, t1);

		fsquare (t1, t0);

		fmul (out, t1, z11);
	}
	int curve25519_donna(u8* mypublic, const u8* secret, const u8* basepoint) {
		limb    bp[10], x[10], z[11], zmone[10];
		uint8_t e[32];
		int     i;
		for (i = 0; i < 32; ++i) e[i] = secret[i];
		e[0] &= 248;
		e[31] &= 127;
		e[31] |= 64;
		fexpand (bp, basepoint);
		cmult (x, z, e, bp);
		crecip (zmone, z);
		fmul (z, x, zmone);
		fcontract (mypublic, z);
		return 0;
	}
}

declfn void Crypto::x25519_shared_secret(
	_Out_ uint8_t      shared_secret[X25519_KEY_SIZE],
	_In_ const uint8_t private_key[X25519_KEY_SIZE],
	_In_ const uint8_t peer_public[X25519_KEY_SIZE]) { curve25519_donna (shared_secret, private_key, peer_public); }

declfn void Crypto::x25519_base(
	_Out_ uint8_t      public_key[X25519_KEY_SIZE],
	_In_ const uint8_t private_key[X25519_KEY_SIZE]) {
	static const uint8_t basepoint[32] = { 9 };
	curve25519_donna (public_key, private_key, basepoint);
}

declfn void Crypto::x25519_clamp_private_key(_Inout_ uint8_t private_key[X25519_KEY_SIZE]) {
	private_key[0] &= 248;
	private_key[31] &= 127;
	private_key[31] |= 64;
}

declfn auto Crypto::x25519_generate_keypair(
	_In_ instance* ctx,
	_Out_ uint8_t  public_key[X25519_KEY_SIZE],
	_Out_ uint8_t  private_key[X25519_KEY_SIZE]) -> bool {

	secure_random_bytes (ctx, private_key, X25519_KEY_SIZE);


	x25519_clamp_private_key (private_key);


	x25519_base (public_key, private_key);
	return true;
}
