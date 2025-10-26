#include <windows.h>
#include <stdio.h>
#include "config.h"
#include "generator.h"

CHAR g_repo_root[MAX_PATH];

VOID GetRepoRoot() {
    CHAR exe_path[MAX_PATH];
    CHAR* last_slash;
    DWORD i;

    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    lstrcpyA(g_repo_root, exe_path);

    for (i = 0; i < 3; i++) {
        last_slash = NULL;
        for (CHAR* p = g_repo_root; *p; p++) {
            if (*p == '\\') last_slash = p;
        }
        if (last_slash) *last_slash = '\0';
    }
}

VOID BuildPath(CHAR* dest, SIZE_T dest_size, const CHAR* relative_path) {
    wsprintfA(dest, "%s\\%s", g_repo_root, relative_path);
}

BOOL CheckStubsExist() {
    HANDLE hWinapi, hNtdll;
    BOOL winapi_exists, ntdll_exists;
    CHAR winapi_path[MAX_PATH], ntdll_path[MAX_PATH];

    BuildPath(winapi_path, MAX_PATH, "src\\stubs\\stub_winapi.exe");
    BuildPath(ntdll_path, MAX_PATH, "src\\stubs\\stub_ntdll.exe");

    hWinapi = CreateFileA(winapi_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    winapi_exists = (hWinapi != INVALID_HANDLE_VALUE);
    if (winapi_exists) CloseHandle(hWinapi);

    hNtdll = CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ntdll_exists = (hNtdll != INVALID_HANDLE_VALUE);
    if (ntdll_exists) CloseHandle(hNtdll);

    return winapi_exists && ntdll_exists;
}

BOOL BuildStubs() {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    DWORD exit_code;
    CHAR stubs_dir[MAX_PATH], cmd[MAX_PATH * 2];

    printf("stubs not found, building...\n");

    BuildPath(stubs_dir, MAX_PATH, "src\\stubs");
    wsprintfA(cmd, "cmd.exe /c cd /d \"%s\" && build_stubs.bat", stubs_dir);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("failed to start build process\n");
        printf("please run src\\stubs\\build_stubs.bat manually from Developer Command Prompt\n");
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exit_code != 0) {
        printf("stub build failed\n");
        printf("please run src\\stubs\\build_stubs.bat manually from Developer Command Prompt\n");
        return FALSE;
    }

    printf("stubs built successfully\n\n");
    return TRUE;
}

VOID PrintBanner() {
    HANDLE hBanner;
    DWORD bytes_read;
    CHAR buffer[1024];
    CHAR banner_path[MAX_PATH];

    BuildPath(banner_path, MAX_PATH, "src\\banner.txt");

    hBanner = CreateFileA(banner_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hBanner != INVALID_HANDLE_VALUE) {
        if (ReadFile(hBanner, buffer, sizeof(buffer) - 1, &bytes_read, NULL)) {
            buffer[bytes_read] = '\0';
            printf("%s", buffer);
        }
        CloseHandle(hBanner);
    }
    printf("\nfor authorized lab use only\n");
}

VOID InitConfig(MalgenConfig* cfg) {
    LARGE_INTEGER perf_counter;

    ZeroMemory(cfg, sizeof(MalgenConfig));
    cfg->payload_type = PAYLOAD_CALC;
    cfg->encryption = ENCRYPTION_NONE;
    cfg->injection = INJECTION_CREATE_REMOTE_THREAD;
    cfg->api_level = API_WINAPI;
    cfg->persistence = PERSISTENCE_NONE;
    cfg->target.use_sacrificial = TRUE;

    QueryPerformanceCounter(&perf_counter);
    cfg->xor_key = (BYTE)(perf_counter.LowPart & 0xFF);

    BuildPath(cfg->output_path, sizeof(cfg->output_path), "output\\malware.exe");
}

VOID ShowMenu(MalgenConfig* cfg) {
    INT choice;

    printf("\n━━━━ malware configuration ━━━━\n");

    printf("[1] payload type\n");
    printf("\t1. calc.exe (pop calculator)\n");
    printf("\tselection: ");
    scanf_s("%d", &choice);
    cfg->payload_type = PAYLOAD_CALC;

    printf("\n[2] encryption method\n");
    printf("\t1. none\n");
    printf("\t2. XOR (random key)\n");
    printf("\tselection: ");
    scanf_s("%d", &choice);
    switch (choice) {
    case 2:
        cfg->encryption = ENCRYPTION_XOR;
        break;
    default:
        cfg->encryption = ENCRYPTION_NONE;
        break;
    }

    printf("\n[3] injection technique\n");
    printf("\t1. CreateRemoteThread\n");
    printf("\tselection: ");
    scanf_s("%d", &choice);
    cfg->injection = INJECTION_CREATE_REMOTE_THREAD;

    printf("\n[4] target process\n");
    printf("\t1. spawn sacrificial notepad.exe\n");
    printf("\tselection: ");
    scanf_s("%d", &choice);
    cfg->target.use_sacrificial = TRUE;
    lstrcpyA(cfg->target.process_name, "notepad.exe");

    printf("\n[5] API level\n");
    printf("\t1. WinAPI\n");
    printf("\tselection: ");
    scanf_s("%d", &choice);
    cfg->api_level = API_WINAPI;

    printf("\n[6] output path\n");
    printf("\tdefault: %s\n", cfg->output_path);
    printf("\tpress enter to continue");
    while (getchar() != '\n');
    (void)getchar();
}

int wmain(int argc, char* argv[]) {
    MalgenConfig config;

    GetRepoRoot();
    PrintBanner();

    if (!CheckStubsExist()) {
        if (!BuildStubs()) {
            return 1;
        }
    }

    InitConfig(&config);
    ShowMenu(&config);

    printf("\n━━━━ generating malware ━━━━\n");
    if (GenerateMalware(&config)) {
        printf("\nmalware generated successfully: %s\n", config.output_path);
    } else {
        printf("\nmalware generation failed\n");
        return 1;
    }

    return 0;
}
