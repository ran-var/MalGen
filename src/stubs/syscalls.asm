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

SysNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtAllocateVirtualMemory
    syscall
    ret
SysNtAllocateVirtualMemory ENDP

SysNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtWriteVirtualMemory
    syscall
    ret
SysNtWriteVirtualMemory ENDP

SysNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, wNtProtectVirtualMemory
    syscall
    ret
SysNtProtectVirtualMemory ENDP

SysNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, wNtCreateThreadEx
    syscall
    ret
SysNtCreateThreadEx ENDP

SysNtQueueApcThread PROC
    mov r10, rcx
    mov eax, wNtQueueApcThread
    syscall
    ret
SysNtQueueApcThread ENDP

SysNtCreateSection PROC
    mov r10, rcx
    mov eax, wNtCreateSection
    syscall
    ret
SysNtCreateSection ENDP

SysNtMapViewOfSection PROC
    mov r10, rcx
    mov eax, wNtMapViewOfSection
    syscall
    ret
SysNtMapViewOfSection ENDP

SysNtUnmapViewOfSection PROC
    mov r10, rcx
    mov eax, wNtUnmapViewOfSection
    syscall
    ret
SysNtUnmapViewOfSection ENDP

SysNtResumeThread PROC
    mov r10, rcx
    mov eax, wNtResumeThread
    syscall
    ret
SysNtResumeThread ENDP

SysNtClose PROC
    mov r10, rcx
    mov eax, wNtClose
    syscall
    ret
SysNtClose ENDP

end
