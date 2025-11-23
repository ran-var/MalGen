#ifndef CRYPTO_H
#define CRYPTO_H

#include "../config.h"

#define ENC_NONE 0
#define ENC_XOR 1
#define ENC_AES 2
#define ENC_RC4 3

BOOL EncryptXOR(LPBYTE data, SIZE_T size, BYTE key);
BOOL EncryptAES256(LPBYTE data, SIZE_T size, BYTE* key, BYTE* iv);
BOOL EncryptRC4(LPBYTE data, SIZE_T size, BYTE* key, SIZE_T key_len);

VOID GenerateRandomBytes(LPBYTE buffer, SIZE_T size);

#endif
