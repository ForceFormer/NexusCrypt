#pragma once

namespace Sha3
{
	typedef unsigned char u8;
	typedef unsigned long long int u64;
	typedef unsigned int ui;

	void Keccak(ui r, ui c, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen);

	inline void Keccak256(const u8 *in, u64 inLen, u8 *out) { Keccak(1088, 512, in, inLen, 0x01, out, 32); }

	inline void FIPS202_SHAKE128(const u8 *in, u64 inLen, u8 *out, u64 outLen) { Keccak(1344, 256, in, inLen, 0x1F, out, outLen); }
	inline void FIPS202_SHAKE256(const u8 *in, u64 inLen, u8 *out, u64 outLen) { Keccak(1088, 512, in, inLen, 0x1F, out, outLen); }
	inline void FIPS202_SHA3_224(const u8 *in, u64 inLen, u8 *out) { Keccak(1152, 448, in, inLen, 0x06, out, 28); }
	inline void FIPS202_SHA3_256(const u8 *in, u64 inLen, u8 *out) { Keccak(1088, 512, in, inLen, 0x06, out, 32); }
	inline void FIPS202_SHA3_384(const u8 *in, u64 inLen, u8 *out) { Keccak(832, 768, in, inLen, 0x06, out, 48); }
	inline void FIPS202_SHA3_512(const u8 *in, u64 inLen, u8 *out) { Keccak(576, 1024, in, inLen, 0x06, out, 64); }
}