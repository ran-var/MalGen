#ifndef MENU_H
#define MENU_H

#include "config.h"

typedef enum {
    MENU_MAIN,
    MENU_PAYLOAD,
    MENU_DELIVERY,
    MENU_ENCRYPTION,
    MENU_EVASION,
    MENU_PERSISTENCE,
    MENU_ADVANCED,
    MENU_GENERATE
} MenuState;

typedef enum {
    MAIN_PAYLOAD = 0,
    MAIN_ENCRYPTION,
    MAIN_INJECTION,
    MAIN_EVASION,
    MAIN_PERSISTENCE,
    MAIN_API,
    MAIN_TARGET,
    MAIN_GENERATE,
    MAIN_QUIT,
    MAIN_ITEM_COUNT
} MainMenuItem;

typedef struct {
    INT static_risk;
    INT dynamic_risk;
    INT behavior_risk;
    INT overall_risk;
} DetectionRisk;

VOID RunInteractiveMenu(MalgenConfig* config);

#endif
