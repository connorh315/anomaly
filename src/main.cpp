// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/LightHook.h"
#include "common/assert.h"
#include "common/logging.h"
#include "common/types.h"
#include "main.h"
#include "globals.h"
#include "utils.h"

#include "orbis/libkernel.h"

#include "hooks/hooks.h"

#include "symbols.h"

extern "C" void sceSysUtilSendSystemNotificationWithText(int type, const char* message);

HOOK_INIT(Log_Note);
void Log_Note(char* message, char* arg1) {
    LOG_INFO("GAME NOTE: {} {}", message, arg1);
}

void patch_nuisance_functions() {
    PATCH(0x0718c16,
          "\x90\x90\x90\x90\x90"); // Patch out the sceRemotePlayProhibit call (spams the console)
    PATCH(0x0715095,
          "\x90\x90\x90\x90\x90"); // Patch out the sceVideoOutSetWindowModeMargins call (spams the console)
    PATCH(0x04b994b,
          "\x90\x90\x90\x90\x90"); // Patch out the scePadSetLightbar call 1 (spams the
                                   // console)
    PATCH(0x04b9964,
          "\x90\x90\x90\x90\x90"); // Patch out the scePadSetLightbar call 2 (spams the
                                   // console)
} 

bool initialize(u64 base_addr) {
    g_base_addr = base_addr;
    LOG_INFO("{} Loading...", ANOMALY_VERSION);
    patch_nuisance_functions();

    LOG_INFO("Resolving game symbols");
    ResolveGameSymbols(base_addr);

    LOG_INFO("Hooking eboot functions");
    return HookGUIFunctions() && HookFileFunctions();
}

extern "C" int32_t __wrap__init(size_t, void*) {
    OrbisKernelModuleInfo* module_info = new OrbisKernelModuleInfo();
    module_info->size = sizeof(OrbisKernelModuleInfo);
    sceKernelGetModuleInfo(0, module_info);
    u64 eboot_base_addr = (u64)module_info->segmentInfo[0].address;

    if (!ends_with_case_insensitive((char*)(eboot_base_addr + 0x2421EBD), "_PATCH11C")) {
        LOG_INFO("Invalid LEGO Dimensions version. Ensure your game is up to date!");
        return 0;
    }

    if (!initialize((u64)module_info->segmentInfo[0].address)) {
        LOG_ERROR("Something went wrong when initializing!");
        return 0;
    }

    sceSysUtilSendSystemNotificationWithText(222, ANOMALY_INITIALISED);

    LOG_INFO(ANOMALY_INITIALISED);

    return 0;
}
