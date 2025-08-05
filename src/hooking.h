#pragma once

#include <stdarg.h>
#include <stdio.h>

#include "common/types.h"
#include "fmt/format.h"

#define HOOK_FUNC __attribute__((noinline)) __attribute__((sysv_abi))

#define HOOK_INIT_VAL(name) info_##name
#define HOOK_INIT(name) HookInformation info_##name;
#define HOOK(addr, name)                                                                           \
    do {                                                                                           \
        HOOK_INIT_VAL(name) = CreateHook((void*)(base_addr + addr), (void*)name);                  \
        if (!EnableHook(&HOOK_INIT_VAL(name)))                                                     \
            return false;                                                                          \
        LOG_INFO("addr {:#x} hooked\n", (base_addr + addr));                                       \
    } while (0);
#define CONTINUE(name, type, ...) ((type)(info_##name.Trampoline))(__VA_ARGS__);

#define PATCH(addr, data_literal)                                                                  \
    do {                                                                                           \
        static_assert(sizeof(data_literal) - 1 <= 16, "Patch too large");                          \
        u8* patch_target = (u8*)(eboot_base_addr + addr);                                                \
        memcpy(patch_target, data_literal, sizeof(data_literal) - 1);                              \
        LOG_INFO("patched addr {:#x}\n", (eboot_base_addr + addr));                                      \
    } while (0)


extern "C" int32_t __wrap__init(size_t, void*);

long* OpenDATFile(long param_1, char* filename, int counter);

typedef struct SceFiosDirEntry {
    uint64_t fileSize;
    uint32_t statFlags;
    uint16_t nameLength;
    uint16_t fullPathLength;
    uint16_t offsetToName;
    uint16_t reserved[3];
    char fullPath[1024];
} SceFiosDirEntry;