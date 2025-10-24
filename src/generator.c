#include "generator.h"
#include <stdio.h>

BOOL GenerateMalware(const MalgenConfig* config) {
    printf("[*] Generating malware with selected configuration...\n");
    printf("[*] Output: %s\n", config->output_path);

    return TRUE;
}
