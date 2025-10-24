#include <windows.h>
#include <stdio.h>
#include "config.h"
#include "generator.h"

VOID PrintBanner() {
    printf("\n");
    printf("  ˆˆˆW   ˆˆˆW ˆˆˆˆˆW ˆˆW      ˆˆˆˆˆˆW ˆˆˆˆˆˆˆWˆˆˆW   ˆˆW\n");
    printf("  ˆˆˆˆW ˆˆˆˆQˆˆTPPˆˆWˆˆQ     ˆˆTPPPP] ˆˆTPPPP]ˆˆˆˆW  ˆˆQ\n");
    printf("  ˆˆTˆˆˆˆTˆˆQˆˆˆˆˆˆˆQˆˆQ     ˆˆQ  ˆˆˆWˆˆˆˆˆW  ˆˆTˆˆW ˆˆQ\n");
    printf("  ˆˆQZˆˆT]ˆˆQˆˆTPPˆˆQˆˆQ     ˆˆQ   ˆˆQˆˆTPP]  ˆˆQZˆˆWˆˆQ\n");
    printf("  ˆˆQ ZP] ˆˆQˆˆQ  ˆˆQˆˆˆˆˆˆˆWZˆˆˆˆˆˆT]ˆˆˆˆˆˆˆWˆˆQ ZˆˆˆˆQ\n");
    printf("  ZP]     ZP]ZP]  ZP]ZPPPPPP] ZPPPPP] ZPPPPPP]ZP]  ZPPP]\n");
    printf("\n");
    printf("  Educational Malware Generator - Maldev Academy\n");
    printf("  For Authorized Lab Use Only\n");
    printf("\n");
}

VOID InitConfig(MalgenConfig* cfg) {
    ZeroMemory(cfg, sizeof(MalgenConfig));
    cfg->payload_type = PAYLOAD_CALC;
    cfg->encryption = ENCRYPTION_NONE;
    cfg->injection = INJECTION_CREATE_REMOTE_THREAD;
    cfg->api_level = API_WINAPI;
    cfg->persistence = PERSISTENCE_NONE;
    cfg->target.use_sacrificial = TRUE;
    lstrcpyA(cfg->output_path, "output\\malware.exe");
}

int wmain(int argc, char* argv[]) {
    MalgenConfig config;

    PrintBanner();
    InitConfig(&config);

    printf("Press any key to continue...\n");
    getchar();

    return 0;
}
