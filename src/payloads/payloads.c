#include "payloads.h"
#include "shellcode.h"
#include <stdlib.h>

BOOL GetPayload(PayloadType type, LPVOID* payload_out, SIZE_T* size_out) {
    switch (type) {
    case PAYLOAD_CALC:
        *payload_out = malloc(calc_shellcode_size);
        if (*payload_out == NULL) {
            return FALSE;
        }
        memcpy(*payload_out, calc_shellcode, calc_shellcode_size);
        *size_out = calc_shellcode_size;
        return TRUE;

    case PAYLOAD_REVERSE_SHELL:
    case PAYLOAD_CUSTOM_SHELLCODE:
        return FALSE;

    default:
        return FALSE;
    }
}
