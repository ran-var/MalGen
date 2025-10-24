#include <windows.h>
#include <stdio.h>
#include "config.h"
#include "generator.h"

VOID PrintBanner() {
    printf("\n");
    printf("  ���W   ���W �����W ��W      ������W �������W���W   ��W\n");
    printf("  ����W ����Q��TPP��W��Q     ��TPPPP] ��TPPPP]����W  ��Q\n");
    printf("  ��T����T��Q�������Q��Q     ��Q  ���W�����W  ��T��W ��Q\n");
    printf("  ��QZ��T]��Q��TPP��Q��Q     ��Q   ��Q��TPP]  ��QZ��W��Q\n");
    printf("  ��Q ZP] ��Q��Q  ��Q�������WZ������T]�������W��Q Z����Q\n");
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
