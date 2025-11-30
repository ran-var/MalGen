#include "menu.h"
#include <stdio.h>
#include <conio.h>
#include <windows.h>

#define KEY_UP 72
#define KEY_DOWN 80
#define KEY_LEFT 75
#define KEY_RIGHT 77
#define KEY_ENTER 13
#define KEY_ESC 27

#define COLOR_NORMAL 7
#define COLOR_SELECTED 10
#define COLOR_GENERATE 10

VOID ClearScreen() {
    system("cls");
}

VOID SetCursorPosition(INT x, INT y) {
    COORD coord;
    coord.X = x;
    coord.Y = y;
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

VOID SetConsoleColor(INT color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

INT GetKeyPress() {
    INT ch = _getch();
    if (ch == 0 || ch == 224) {
        ch = _getch();
    }
    return ch;
}

VOID CalculateDetectionRisk(const MalgenConfig* config, DetectionRisk* risk) {
    risk->static_risk = 2;
    risk->dynamic_risk = 2;
    risk->behavior_risk = 3;

    if (config->encryption == ENCRYPTION_NONE) {
        risk->static_risk += 2;
    } else if (config->encryption == ENCRYPTION_XOR) {
        risk->static_risk += 1;
    }

    if (config->anti_analysis.anti_debug.check_peb_being_debugged ||
        config->anti_analysis.anti_debug.check_debug_port ||
        config->anti_analysis.anti_debug.check_debug_object ||
        config->anti_analysis.anti_debug.check_hardware_breakpoints ||
        config->anti_analysis.anti_debug.check_remote_debugger) {
        risk->dynamic_risk -= 1;
    }
    if (config->anti_analysis.anti_vm.check_registry_keys ||
        config->anti_analysis.anti_vm.check_files ||
        config->anti_analysis.anti_vm.check_cpuid) {
        risk->dynamic_risk -= 1;
    }
    if (config->anti_analysis.anti_sandbox.check_sleep_acceleration ||
        config->anti_analysis.anti_sandbox.check_mouse_movement ||
        config->anti_analysis.anti_sandbox.check_username) {
        risk->dynamic_risk -= 1;
    }

    if (config->api_level == API_WINAPI) {
        risk->behavior_risk += 1;
    } else if (config->api_level == API_DIRECT_SYSCALLS) {
        risk->behavior_risk -= 2;
    } else if (config->api_level == API_INDIRECT_SYSCALLS) {
        risk->behavior_risk -= 3;
    }

    if (config->persistence != PERSISTENCE_NONE) {
        risk->behavior_risk += 1;
    }

    if (risk->static_risk < 1) risk->static_risk = 1;
    if (risk->static_risk > 5) risk->static_risk = 5;
    if (risk->dynamic_risk < 1) risk->dynamic_risk = 1;
    if (risk->dynamic_risk > 5) risk->dynamic_risk = 5;
    if (risk->behavior_risk < 1) risk->behavior_risk = 1;
    if (risk->behavior_risk > 5) risk->behavior_risk = 5;

    risk->overall_risk = (risk->static_risk + risk->dynamic_risk + risk->behavior_risk) * 10 / 15;
    if (risk->overall_risk > 10) risk->overall_risk = 10;
}

VOID DrawProgressBar(INT value, INT max, INT width) {
    INT filled = (value * width) / max;
    INT i;
    for (i = 0; i < filled; i++) {
        printf("\xDB");
    }
    for (i = filled; i < width; i++) {
        printf("\xB0");
    }
}

const CHAR* GetPayloadName(PayloadType type) {
    switch (type) {
    case PAYLOAD_CALC: return "calc.exe";
    case PAYLOAD_REVERSE_SHELL: return "reverse shell";
    case PAYLOAD_CUSTOM_SHELLCODE: return "custom shellcode";
    default: return "unknown";
    }
}

const CHAR* GetEncryptionName(EncryptionMethod method) {
    switch (method) {
    case ENCRYPTION_NONE: return "none";
    case ENCRYPTION_XOR: return "XOR";
    case ENCRYPTION_AES: return "AES-256";
    case ENCRYPTION_RC4: return "RC4";
    default: return "unknown";
    }
}

const CHAR* GetInjectionName(InjectionTechnique technique) {
    switch (technique) {
    case INJECTION_CREATE_REMOTE_THREAD: return "CreateRemoteThread";
    case INJECTION_EARLY_BIRD_APC: return "early bird APC";
    case INJECTION_THREAD_HIJACKING: return "thread hijacking";
    case INJECTION_PROCESS_HOLLOWING: return "process hollowing";
    case INJECTION_REMOTE_MAPPING: return "remote mapping";
    default: return "unknown";
    }
}

const CHAR* GetApiLevelName(ApiLevel level) {
    switch (level) {
    case API_WINAPI: return "WinAPI";
    case API_NTDLL: return "NTDLL";
    case API_DIRECT_SYSCALLS: return "direct syscalls";
    case API_INDIRECT_SYSCALLS: return "indirect syscalls";
    default: return "unknown";
    }
}

const CHAR* GetPersistenceName(PersistenceMethod method) {
    switch (method) {
    case PERSISTENCE_NONE: return "none";
    case PERSISTENCE_REGISTRY_RUN: return "registry run";
    case PERSISTENCE_STARTUP_FOLDER: return "startup folder";
    case PERSISTENCE_SCHEDULED_TASK: return "scheduled task";
    case PERSISTENCE_SERVICE: return "service";
    default: return "unknown";
    }
}

VOID GetEvasionSummary(const MalgenConfig* config, CHAR* buffer, SIZE_T size) {
    INT count = 0;
    if (config->anti_analysis.anti_debug.check_peb_being_debugged) count++;
    if (config->anti_analysis.anti_debug.check_debug_port) count++;
    if (config->anti_analysis.anti_debug.check_debug_object) count++;
    if (config->anti_analysis.anti_debug.check_hardware_breakpoints) count++;
    if (config->anti_analysis.anti_debug.check_remote_debugger) count++;
    if (config->anti_analysis.anti_vm.check_registry_keys) count++;
    if (config->anti_analysis.anti_vm.check_files) count++;
    if (config->anti_analysis.anti_vm.check_cpuid) count++;
    if (config->anti_analysis.anti_sandbox.check_sleep_acceleration) count++;
    if (config->anti_analysis.anti_sandbox.check_mouse_movement) count++;
    if (config->anti_analysis.anti_sandbox.check_username) count++;
    if (config->anti_analysis.obfuscate_strings) count++;

    if (count == 0) {
        lstrcpyA(buffer, "none");
    } else {
        wsprintfA(buffer, "%d enabled", count);
    }
}

VOID DrawMainMenu(const MalgenConfig* config, INT selected) {
    DetectionRisk risk;
    CHAR evasion_summary[64];

    CalculateDetectionRisk(config, &risk);
    GetEvasionSummary(config, evasion_summary, sizeof(evasion_summary));

    ClearScreen();
    printf("===============================================================\n");
    printf("                     malware loadout builder\n");
    printf("===============================================================\n\n");

    printf("%c- current build --------------------%c  %c- detection risk -----%c\n", 218, 191, 218, 191);

    printf("%c ", 179);
    if (selected == MAIN_PAYLOAD) SetConsoleColor(COLOR_SELECTED);
    printf("payload:      %-20s", GetPayloadName(config->payload_type));
    SetConsoleColor(COLOR_NORMAL);
    printf(" %c  %c                       %c\n", 179, 179, 179);

    printf("%c ", 179);
    if (selected == MAIN_ENCRYPTION) SetConsoleColor(COLOR_SELECTED);
    printf("encryption:   %-20s", GetEncryptionName(config->encryption));
    SetConsoleColor(COLOR_NORMAL);
    printf(" %c  %c  ", 179, 179);
    DrawProgressBar(risk.overall_risk, 10, 10);
    printf("  %d/10     %c\n", risk.overall_risk, 179);

    printf("%c ", 179);
    if (selected == MAIN_INJECTION) SetConsoleColor(COLOR_SELECTED);
    printf("injection:    %-20s", GetInjectionName(config->injection));
    SetConsoleColor(COLOR_NORMAL);
    printf(" %c  %c                       %c\n", 179, 179, 179);

    printf("%c ", 179);
    if (selected == MAIN_EVASION) SetConsoleColor(COLOR_SELECTED);
    printf("evasion:      %-20s", evasion_summary);
    SetConsoleColor(COLOR_NORMAL);
    printf(" %c  %c  static:  ", 179, 179);
    DrawProgressBar(risk.static_risk, 5, 5);
    printf(" %d/5   %c\n", risk.static_risk, 179);

    printf("%c ", 179);
    if (selected == MAIN_PERSISTENCE) SetConsoleColor(COLOR_SELECTED);
    printf("persistence:  %-20s", GetPersistenceName(config->persistence));
    SetConsoleColor(COLOR_NORMAL);
    printf(" %c  %c  dynamic: ", 179, 179);
    DrawProgressBar(risk.dynamic_risk, 5, 5);
    printf(" %d/5   %c\n", risk.dynamic_risk, 179);

    printf("%c ", 179);
    if (selected == MAIN_API) SetConsoleColor(COLOR_SELECTED);
    printf("API:          %-20s", GetApiLevelName(config->api_level));
    SetConsoleColor(COLOR_NORMAL);
    printf(" %c  %c  behavior:", 179, 179);
    DrawProgressBar(risk.behavior_risk, 5, 5);
    printf(" %d/5   %c\n", risk.behavior_risk, 179);

    printf("%c ", 179);
    if (selected == MAIN_TARGET) SetConsoleColor(COLOR_SELECTED);
    printf("target:       %-20s", config->target.process_name);
    SetConsoleColor(COLOR_NORMAL);
    printf(" %c  %c                       %c\n", 179, 179, 179);

    printf("%c---------------------------------------%c  %c-----------------------%c\n\n", 192, 217, 192, 217);

    printf("                      ");
    if (selected == MAIN_GENERATE) SetConsoleColor(COLOR_GENERATE);
    printf("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", 201, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 187);
    printf("                      %c   [G] GENERATE    %c\n", 186, 186);
    printf("                      %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", 200, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 188);
    SetConsoleColor(COLOR_NORMAL);

    printf("\narrow keys to navigate, enter to select, esc/q to quit\n");
}

VOID PayloadMenu(MalgenConfig* config) {
    INT selected = config->payload_type;
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                         payload selection\n");
        printf("===============================================================\n\n");

        printf("%s calc.exe (pop calculator)\n", selected == PAYLOAD_CALC ? ">" : " ");
        printf("%s reverse shell (LHOST:LPORT) [not implemented]\n", selected == PAYLOAD_REVERSE_SHELL ? ">" : " ");
        printf("%s custom shellcode file [not implemented]\n\n", selected == PAYLOAD_CUSTOM_SHELLCODE ? ">" : " ");

        printf("esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected < 2) {
            selected++;
        } else if (key == KEY_ENTER) {
            if (selected == PAYLOAD_CALC) {
                config->payload_type = selected;
                running = FALSE;
            }
        } else if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID DeliveryMenu(MalgenConfig* config) {
    INT selected = 0;
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                       delivery configuration\n");
        printf("===============================================================\n\n");

        printf("injection technique:\n");
        printf("%s CreateRemoteThread\n", selected == 0 ? ">" : " ");
        printf("%s early bird APC\n", selected == 1 ? ">" : " ");
        printf("%s thread hijacking\n", selected == 2 ? ">" : " ");
        printf("%s process hollowing\n", selected == 3 ? ">" : " ");
        printf("%s remote mapping\n\n", selected == 4 ? ">" : " ");

        printf("API level:\n");
        printf("%s WinAPI\n", selected == 5 ? ">" : " ");
        printf("%s NTDLL\n", selected == 6 ? ">" : " ");
        printf("%s direct syscalls\n", selected == 7 ? ">" : " ");
        printf("%s indirect syscalls\n\n", selected == 8 ? ">" : " ");

        printf("target process:\n");
        printf("%s spawn sacrificial: %s\n\n", selected == 9 ? ">" : " ", config->target.process_name);

        printf("esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected < 9) {
            selected++;
        } else if (key == KEY_ENTER) {
            switch (selected) {
            case 0:
                config->injection = INJECTION_CREATE_REMOTE_THREAD;
                break;
            case 1:
                config->injection = INJECTION_EARLY_BIRD_APC;
                break;
            case 2:
                config->injection = INJECTION_THREAD_HIJACKING;
                break;
            case 3:
                config->injection = INJECTION_PROCESS_HOLLOWING;
                break;
            case 4:
                config->injection = INJECTION_REMOTE_MAPPING;
                break;
            case 5:
                config->api_level = API_WINAPI;
                break;
            case 6:
                config->api_level = API_NTDLL;
                break;
            case 7:
                config->api_level = API_DIRECT_SYSCALLS;
                break;
            case 8:
                config->api_level = API_INDIRECT_SYSCALLS;
                break;
            }
        } else if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID EncryptionMenu(MalgenConfig* config) {
    INT selected = config->encryption;
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                      encryption selection\n");
        printf("===============================================================\n\n");

        printf("%s none (plaintext payload)\n", selected == ENCRYPTION_NONE ? ">" : " ");
        printf("%s XOR (single-byte key)\n", selected == ENCRYPTION_XOR ? ">" : " ");
        printf("%s AES-256-CBC (random key)\n", selected == ENCRYPTION_AES ? ">" : " ");
        printf("%s RC4 (random key)\n\n", selected == ENCRYPTION_RC4 ? ">" : " ");

        if (config->encryption == ENCRYPTION_XOR) {
            printf("current XOR key: 0x%02X\n\n", config->xor_key);
        }

        printf("esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected < 3) {
            selected++;
        } else if (key == KEY_ENTER) {
            config->encryption = selected;
            running = FALSE;
        } else if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID EvasionMenu(MalgenConfig* config) {
    INT selected = 0;
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                      evasion configuration\n");
        printf("===============================================================\n\n");

        printf("anti-debug:\n");
        printf("%s [%c] PEB BeingDebugged check\n", selected == 0 ? ">" : " ", config->anti_analysis.anti_debug.check_peb_being_debugged ? 'X' : ' ');
        printf("%s [%c] NtQueryInformationProcess debug port\n", selected == 1 ? ">" : " ", config->anti_analysis.anti_debug.check_debug_port ? 'X' : ' ');
        printf("%s [%c] NtQueryInformationProcess debug object\n", selected == 2 ? ">" : " ", config->anti_analysis.anti_debug.check_debug_object ? 'X' : ' ');
        printf("%s [%c] hardware breakpoints (DR0-DR3)\n", selected == 3 ? ">" : " ", config->anti_analysis.anti_debug.check_hardware_breakpoints ? 'X' : ' ');
        printf("%s [%c] CheckRemoteDebuggerPresent\n\n", selected == 4 ? ">" : " ", config->anti_analysis.anti_debug.check_remote_debugger ? 'X' : ' ');

        printf("anti-VM:\n");
        printf("%s [%c] registry keys (VBox/VMware services)\n", selected == 5 ? ">" : " ", config->anti_analysis.anti_vm.check_registry_keys ? 'X' : ' ');
        printf("%s [%c] VM driver files\n", selected == 6 ? ">" : " ", config->anti_analysis.anti_vm.check_files ? 'X' : ' ');
        printf("%s [%c] CPUID hypervisor bit\n\n", selected == 7 ? ">" : " ", config->anti_analysis.anti_vm.check_cpuid ? 'X' : ' ');

        printf("anti-sandbox:\n");
        printf("%s [%c] sleep acceleration detection\n", selected == 8 ? ">" : " ", config->anti_analysis.anti_sandbox.check_sleep_acceleration ? 'X' : ' ');
        printf("%s [%c] mouse movement check\n", selected == 9 ? ">" : " ", config->anti_analysis.anti_sandbox.check_mouse_movement ? 'X' : ' ');
        printf("%s [%c] username check (sandbox/malware/test)\n\n", selected == 10 ? ">" : " ", config->anti_analysis.anti_sandbox.check_username ? 'X' : ' ');

        printf("obfuscation:\n");
        printf("%s [%c] API hashing (resolve funcs by hash)\n\n", selected == 11 ? ">" : " ", config->anti_analysis.obfuscate_strings ? 'X' : ' ');

        printf("arrow keys to navigate, enter to toggle, esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected < 11) {
            selected++;
        } else if (key == KEY_ENTER) {
            switch (selected) {
            case 0:
                config->anti_analysis.anti_debug.check_peb_being_debugged = !config->anti_analysis.anti_debug.check_peb_being_debugged;
                break;
            case 1:
                config->anti_analysis.anti_debug.check_debug_port = !config->anti_analysis.anti_debug.check_debug_port;
                break;
            case 2:
                config->anti_analysis.anti_debug.check_debug_object = !config->anti_analysis.anti_debug.check_debug_object;
                break;
            case 3:
                config->anti_analysis.anti_debug.check_hardware_breakpoints = !config->anti_analysis.anti_debug.check_hardware_breakpoints;
                break;
            case 4:
                config->anti_analysis.anti_debug.check_remote_debugger = !config->anti_analysis.anti_debug.check_remote_debugger;
                break;
            case 5:
                config->anti_analysis.anti_vm.check_registry_keys = !config->anti_analysis.anti_vm.check_registry_keys;
                break;
            case 6:
                config->anti_analysis.anti_vm.check_files = !config->anti_analysis.anti_vm.check_files;
                break;
            case 7:
                config->anti_analysis.anti_vm.check_cpuid = !config->anti_analysis.anti_vm.check_cpuid;
                break;
            case 8:
                config->anti_analysis.anti_sandbox.check_sleep_acceleration = !config->anti_analysis.anti_sandbox.check_sleep_acceleration;
                break;
            case 9:
                config->anti_analysis.anti_sandbox.check_mouse_movement = !config->anti_analysis.anti_sandbox.check_mouse_movement;
                break;
            case 10:
                config->anti_analysis.anti_sandbox.check_username = !config->anti_analysis.anti_sandbox.check_username;
                break;
            case 11:
                config->anti_analysis.obfuscate_strings = !config->anti_analysis.obfuscate_strings;
                break;
            }
        } else if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID PersistenceMenu(MalgenConfig* config) {
    INT selected = config->persistence;
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                    persistence configuration\n");
        printf("===============================================================\n\n");

        printf("%s none\n", selected == PERSISTENCE_NONE ? ">" : " ");
        printf("%s registry run key [not implemented]\n", selected == PERSISTENCE_REGISTRY_RUN ? ">" : " ");
        printf("%s startup folder [not implemented]\n", selected == PERSISTENCE_STARTUP_FOLDER ? ">" : " ");
        printf("%s scheduled task [not implemented]\n", selected == PERSISTENCE_SCHEDULED_TASK ? ">" : " ");
        printf("%s windows service [not implemented]\n\n", selected == PERSISTENCE_SERVICE ? ">" : " ");

        printf("esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected < 4) {
            selected++;
        } else if (key == KEY_ENTER) {
            if (selected == PERSISTENCE_NONE) {
                config->persistence = selected;
                running = FALSE;
            }
        } else if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID AdvancedMenu(MalgenConfig* config) {
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                     advanced configuration\n");
        printf("===============================================================\n\n");

        printf("output path:\n");
        printf("  %s\n\n", config->output_path);

        printf("additional features: [not implemented]\n");
        printf("  [ ] AMSI bypass\n");
        printf("  [ ] ETW patching\n\n");

        printf("presets: [not implemented]\n");
        printf("  [1] stealth (max evasion)\n");
        printf("  [2] aggressive (fast execution)\n");
        printf("  [3] research (balanced)\n\n");

        printf("esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID InjectionMenu(MalgenConfig* config) {
    INT selected = config->injection;
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                      injection technique\n");
        printf("===============================================================\n\n");

        printf("%s CreateRemoteThread\n", selected == INJECTION_CREATE_REMOTE_THREAD ? ">" : " ");
        printf("%s early bird APC\n", selected == INJECTION_EARLY_BIRD_APC ? ">" : " ");
        printf("%s thread hijacking\n", selected == INJECTION_THREAD_HIJACKING ? ">" : " ");
        printf("%s process hollowing\n", selected == INJECTION_PROCESS_HOLLOWING ? ">" : " ");
        printf("%s remote mapping\n\n", selected == INJECTION_REMOTE_MAPPING ? ">" : " ");

        printf("esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected < 4) {
            selected++;
        } else if (key == KEY_ENTER) {
            config->injection = selected;
            running = FALSE;
        } else if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID ApiMenu(MalgenConfig* config) {
    INT selected = config->api_level;
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                           API level\n");
        printf("===============================================================\n\n");

        printf("%s WinAPI\n", selected == API_WINAPI ? ">" : " ");
        printf("%s NTDLL\n", selected == API_NTDLL ? ">" : " ");
        printf("%s direct syscalls\n", selected == API_DIRECT_SYSCALLS ? ">" : " ");
        printf("%s indirect syscalls\n\n", selected == API_INDIRECT_SYSCALLS ? ">" : " ");

        printf("esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected < 3) {
            selected++;
        } else if (key == KEY_ENTER) {
            config->api_level = selected;
            running = FALSE;
        } else if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID TargetMenu(MalgenConfig* config) {
    BOOL running = TRUE;

    while (running) {
        ClearScreen();
        printf("===============================================================\n");
        printf("                        target process\n");
        printf("===============================================================\n\n");

        printf("current target: %s\n\n", config->target.process_name);
        printf("target process options:\n");
        printf("  [not implemented]\n\n");
        printf("esc to go back\n");

        INT key = GetKeyPress();
        if (key == KEY_ESC) {
            running = FALSE;
        }
    }
}

VOID RunInteractiveMenu(MalgenConfig* config) {
    INT selected = MAIN_PAYLOAD;
    BOOL running = TRUE;
    MenuState state = MENU_MAIN;

    while (running) {
        DrawMainMenu(config, selected);

        INT key = GetKeyPress();

        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected < MAIN_GENERATE) {
            selected++;
        } else if (key == KEY_ENTER || key == 'g' || key == 'G' || key == 'q' || key == 'Q') {
            INT choice = selected;

            if (key == 'g' || key == 'G') {
                choice = MAIN_GENERATE;
            } else if (key == 'q' || key == 'Q') {
                choice = MAIN_QUIT;
            }

            switch (choice) {
            case MAIN_PAYLOAD:
                PayloadMenu(config);
                break;
            case MAIN_ENCRYPTION:
                EncryptionMenu(config);
                break;
            case MAIN_INJECTION:
                InjectionMenu(config);
                break;
            case MAIN_EVASION:
                EvasionMenu(config);
                break;
            case MAIN_PERSISTENCE:
                PersistenceMenu(config);
                break;
            case MAIN_API:
                ApiMenu(config);
                break;
            case MAIN_TARGET:
                TargetMenu(config);
                break;
            case MAIN_GENERATE:
                running = FALSE;
                state = MENU_GENERATE;
                break;
            case MAIN_QUIT:
                running = FALSE;
                config->payload_type = (PayloadType)-1;
                break;
            }
        } else if (key == KEY_ESC) {
            running = FALSE;
            config->payload_type = (PayloadType)-1;
        }
    }
}
