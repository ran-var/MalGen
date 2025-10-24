#ifndef CRYPTO_H
#define CRYPTO_H

#include "../config.h"

BOOL EncryptPayload(LPBYTE data, SIZE_T size, EncryptionMethod method, BYTE key);
BOOL DecryptPayload(LPBYTE data, SIZE_T size, EncryptionMethod method, BYTE key);

#endif
