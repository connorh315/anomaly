#include <cstdint>
#include "common/types.h"

#include "symbols.h"

static u64 g_base_addr = 0;

#pragma region Memory

DEFINE_SYMBOL(t_NuMemoryGet, NuMemoryGet);
DEFINE_SYMBOL(t_NuMemory_GetThreadMem, NuMemory_GetThreadMem);
DEFINE_SYMBOL(t_NuMemoryManager__BlockAlloc, NuMemoryManager__BlockAlloc);

void resolve_memory() {
    RESOLVE_SYMBOL(NuMemoryGet, 0x4adb10);
    RESOLVE_SYMBOL(NuMemory_GetThreadMem, 0x4adb90);
    RESOLVE_SYMBOL(NuMemoryManager__BlockAlloc, 0x4a83d0);
}

#pragma endregion

#pragma region Locale

DEFINE_SYMBOL(t_NuStringTableLoadCSV, NuStringTableLoadCSV);

void resolve_locale() {
    RESOLVE_SYMBOL(NuStringTableLoadCSV, 0x4ef570);
}

#pragma endregion

#pragma region GUI

DEFINE_SYMBOL(t_GUI2MenuEntry_SetText, GUI2MenuEntry_SetText);
DEFINE_SYMBOL(t_MainMenuScreen_FindObject, MainMenuScreen_FindObject);

void resolve_gui() {
    RESOLVE_SYMBOL(GUI2MenuEntry_SetText, 0xb74d80);
    RESOLVE_SYMBOL(MainMenuScreen_FindObject, 0xcbaf80);
}

#pragma endregion

void ResolveGameSymbols(u64 base_addr) {
    g_base_addr = base_addr;

    resolve_memory();
    resolve_locale();
    resolve_gui();
}