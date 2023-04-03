#ifndef _LIBSHA256_H
#define _LIBSHA256_H 1

/*
 * This is my implementation of the SHA-256 algorithm in C.
 * Link to the SHA-256 Standard and technical specification:
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#include <endian.h>
#include <stdint.h>
#include <string.h>

#define MIN(a, b) a < b ? a : b

#define SHA256_HASH_SIZE 32

uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (~x & z));
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (y & z) ^ (z & x));
}

uint32_t SHR(uint32_t n, uint32_t x)
{
	return (x >> n);
}

uint32_t ROTR(uint32_t n, uint32_t x)
{
	return ((x >> n) | (x << (sizeof(uint32_t) * 8 - n)));
}

uint32_t SIGMA_0(uint32_t x)
{
	return (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x));
}
uint32_t SIGMA_1(uint32_t x)
{
	return (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x));
}
uint32_t sigma_0(uint32_t x)
{
	return (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x));
}
uint32_t sigma_1(uint32_t x)
{
	return (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x));
}

uint64_t length_to_blocks(size_t length)
{
	uint64_t l = length * 8;
	l += 1;
	uint64_t k = (448 - l) % 512;
	uint64_t padded = l + k + 64;

	return padded / 512;
}

void copy_to_block(uint32_t *block, void *source, size_t amount)
{
	memset(block, 0, 64);
	memcpy(block, source, amount);
}

void add_block_padding(void *block, size_t msg_remaining, size_t length,
		       uint8_t *bit_appended)
{

	if (msg_remaining < 64 && *bit_appended == 0) {
		((uint8_t *)block)[msg_remaining] = 0b10000000;
		msg_remaining += 1;
		*bit_appended = 1;
	}

	if (msg_remaining <= 64 - 8) {
		((uint64_t *)block)[7] = htobe64((uint64_t)length * 8);
	}
}

void convert_block_endianness(uint32_t *block)
{
	for (uint32_t i = 0; i < 16; i++) {
		block[i] = be32toh(block[i]);
	}
}

void sha256(uint8_t *message, size_t length, void *buffer_out)
{
	uint8_t bit_appended = 0;

	uint64_t block_count = length_to_blocks(length);
	size_t msg_remaining = length;

	uint32_t W[64] = {};
	uint32_t vars[8] = {};

	uint32_t H[8] = {
	    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};

	uint32_t M[16] = {};

	for (uint64_t i = 0; i < block_count; i++) {
		size_t msg_portion = MIN(msg_remaining, 64);
		copy_to_block(M, message + (i * 64), msg_portion);
		add_block_padding(M, msg_portion, length, &bit_appended);
		convert_block_endianness(M);

		for (int t = 0; t < 16; t++) {
			W[t] = M[t];
		}

		for (int t = 16; t < 64; t++) {
			W[t] = sigma_1(W[t - 2]) + W[t - 7] +
			       sigma_0(W[t - 15]) + W[t - 16];
		}

		for (int v = 0; v < 8; v++) {
			vars[v] = H[v];
		}

		for (int t = 0; t < 64; t++) {
			uint32_t h = vars[7];
			uint32_t S1 = SIGMA_1(vars[4]);
			uint32_t Choice = Ch(vars[4], vars[5], vars[6]);
			uint32_t kt = K[t];

			uint32_t S0 = SIGMA_0(vars[0]);
			uint32_t Majority = Maj(vars[0], vars[1], vars[2]);

			uint32_t t1 = h + S1 + Choice + kt + W[t];
			uint32_t t2 = S0 + Majority;

			vars[7] = vars[6];
			vars[6] = vars[5];
			vars[5] = vars[4];
			vars[4] = vars[3] + t1;
			vars[3] = vars[2];
			vars[2] = vars[1];
			vars[1] = vars[0];
			vars[0] = t1 + t2;
		}

		H[0] = H[0] + vars[0];
		H[1] = H[1] + vars[1];
		H[2] = H[2] + vars[2];
		H[3] = H[3] + vars[3];
		H[4] = H[4] + vars[4];
		H[5] = H[5] + vars[5];
		H[6] = H[6] + vars[6];
		H[7] = H[7] + vars[7];

		msg_remaining -= MIN(msg_remaining, 64);
	}

	memcpy(buffer_out, H, SHA256_HASH_SIZE);
}

#endif /* #ifndef _LIBSHA256_H */
