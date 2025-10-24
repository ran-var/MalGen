#ifndef INJECTION_H
#define INJECTION_H

#include "../config.h"

BOOL InjectPayload(LPVOID payload, SIZE_T size, const TargetProcess* target, InjectionTechnique technique);

#endif
