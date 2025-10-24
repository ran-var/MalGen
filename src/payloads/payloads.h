#ifndef PAYLOADS_H
#define PAYLOADS_H

#include "../config.h"

BOOL GetPayload(PayloadType type, LPVOID* payload_out, SIZE_T* size_out);

#endif
