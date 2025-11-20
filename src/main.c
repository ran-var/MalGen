#include <windows.h>
#include <stdio.h>
#include "config.h"
#include "generator.h"
#include "menu.h"

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
        printf("couldnt start build\n");
        printf("run src\\stubs\\build_stubs.bat manually from developer command prompt\n");
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exit_code != 0) {
        printf("stub build failed\n");
        printf("run src\\stubs\\build_stubs.bat manually from developer command prompt\n");
        return FALSE;
    }

    printf("stubs built\n\n");
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
    lstrcpyA(cfg->target.process_name, "notepad.exe");

    QueryPerformanceCounter(&perf_counter);
    cfg->xor_key = (BYTE)(perf_counter.LowPart & 0xFF);

    BuildPath(cfg->output_path, sizeof(cfg->output_path), "output\\malware.exe");
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
    RunInteractiveMenu(&config);

    if (config.payload_type == (PayloadType)-1) {
        printf("\ncancelled\n");
        return 0;
    }

    printf("\n====== generating ======\n");
    if (GenerateMalware(&config)) {
        printf("\ngenerated: %s\n", config.output_path);
    } else {
        printf("\ngeneration failed\n");
        return 1;
    }

    return 0;
}
