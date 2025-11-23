#include "crypto.h"
#include <windows.h>
#include <bcrypt.h>

static unsigned char aes_sbox[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static unsigned char aes_rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static unsigned char gf_mul(unsigned char a, unsigned char b) {
	unsigned char p = 0;
	unsigned char hi;
	int i;
	for (i = 0; i < 8; i++) {
		if (b & 1) p ^= a;
		hi = a & 0x80;
		a <<= 1;
		if (hi) a ^= 0x1b;
		b >>= 1;
	}
	return p;
}

static void aes_key_expansion(unsigned char* key, unsigned char* round_keys) {
	int i, j;
	unsigned char temp[4];

	for (i = 0; i < 32; i++) round_keys[i] = key[i];

	for (i = 8; i < 60; i++) {
		for (j = 0; j < 4; j++) temp[j] = round_keys[(i - 1) * 4 + j];

		if (i % 8 == 0) {
			unsigned char t = temp[0];
			temp[0] = aes_sbox[temp[1]] ^ aes_rcon[i / 8];
			temp[1] = aes_sbox[temp[2]];
			temp[2] = aes_sbox[temp[3]];
			temp[3] = aes_sbox[t];
		} else if (i % 8 == 4) {
			for (j = 0; j < 4; j++) temp[j] = aes_sbox[temp[j]];
		}

		for (j = 0; j < 4; j++) round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j];
	}
}

static void aes_sub_bytes(unsigned char* state) {
	int i;
	for (i = 0; i < 16; i++) state[i] = aes_sbox[state[i]];
}

static void aes_shift_rows(unsigned char* state) {
	unsigned char temp;
	temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
	temp = state[2]; state[2] = state[10]; state[10] = temp;
	temp = state[6]; state[6] = state[14]; state[14] = temp;
	temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

static void aes_mix_columns(unsigned char* state) {
	int i;
	unsigned char a, b, c, d;
	for (i = 0; i < 4; i++) {
		a = state[i * 4 + 0];
		b = state[i * 4 + 1];
		c = state[i * 4 + 2];
		d = state[i * 4 + 3];
		state[i * 4 + 0] = gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d;
		state[i * 4 + 1] = a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d;
		state[i * 4 + 2] = a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3);
		state[i * 4 + 3] = gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2);
	}
}

static void aes_add_round_key(unsigned char* state, unsigned char* round_key) {
	int i;
	for (i = 0; i < 16; i++) state[i] ^= round_key[i];
}

static void aes_encrypt_block(unsigned char* input, unsigned char* output, unsigned char* round_keys) {
	unsigned char state[16];
	int i, round;

	for (i = 0; i < 16; i++) state[i] = input[i];

	aes_add_round_key(state, round_keys);

	for (round = 1; round < 14; round++) {
		aes_sub_bytes(state);
		aes_shift_rows(state);
		aes_mix_columns(state);
		aes_add_round_key(state, round_keys + round * 16);
	}

	aes_sub_bytes(state);
	aes_shift_rows(state);
	aes_add_round_key(state, round_keys + 14 * 16);

	for (i = 0; i < 16; i++) output[i] = state[i];
}

BOOL EncryptXOR(LPBYTE data, SIZE_T size, BYTE key) {
	SIZE_T i;
	for (i = 0; i < size; i++) {
		data[i] ^= key;
	}
	return TRUE;
}

BOOL EncryptAES256(LPBYTE data, SIZE_T size, BYTE* key, BYTE* iv) {
	unsigned char round_keys[240];
	unsigned char block[16];
	unsigned char prev_block[16];
	SIZE_T i, j;
	SIZE_T num_blocks;
	SIZE_T padded_size;
	BYTE pad_value;

	aes_key_expansion(key, round_keys);

	for (i = 0; i < 16; i++) prev_block[i] = iv[i];

	num_blocks = size / 16;
	padded_size = (num_blocks + 1) * 16;

	for (i = 0; i < num_blocks; i++) {
		for (j = 0; j < 16; j++) block[j] = data[i * 16 + j] ^ prev_block[j];
		aes_encrypt_block(block, data + i * 16, round_keys);
		for (j = 0; j < 16; j++) prev_block[j] = data[i * 16 + j];
	}

	pad_value = (BYTE)(16 - (size % 16));
	if (pad_value == 16) pad_value = 16;
	for (j = 0; j < 16; j++) {
		if (j < size % 16) {
			block[j] = data[num_blocks * 16 + j] ^ prev_block[j];
		} else {
			block[j] = pad_value ^ prev_block[j];
		}
	}
	aes_encrypt_block(block, data + num_blocks * 16, round_keys);

	return TRUE;
}

BOOL EncryptRC4(LPBYTE data, SIZE_T size, BYTE* key, SIZE_T key_len) {
	unsigned char S[256];
	SIZE_T i, j;
	unsigned char temp;

	for (i = 0; i < 256; i++) S[i] = (unsigned char)i;

	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[i % key_len]) % 256;
		temp = S[i]; S[i] = S[j]; S[j] = temp;
	}

	i = 0; j = 0;
	for (SIZE_T k = 0; k < size; k++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		temp = S[i]; S[i] = S[j]; S[j] = temp;
		data[k] ^= S[(S[i] + S[j]) % 256];
	}

	return TRUE;
}

VOID GenerateRandomBytes(LPBYTE buffer, SIZE_T size) {
	HCRYPTPROV hProv;
	if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		CryptGenRandom(hProv, (DWORD)size, buffer);
		CryptReleaseContext(hProv, 0);
	} else {
		SIZE_T i;
		srand(GetTickCount());
		for (i = 0; i < size; i++) {
			buffer[i] = (BYTE)(rand() % 256);
		}
	}
}
