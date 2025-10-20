#pragma once

void ResolveGameSymbols(uint64_t base_addr);

#define DECLARE_SYMBOL(type, name) extern type name
#define DEFINE_SYMBOL(type, name) type name = nullptr
#define RESOLVE_SYMBOL(name, addr) name = (decltype(name))(g_base_addr + addr)

#pragma region Memory
typedef void* (*t_NuMemoryGet)();
DECLARE_SYMBOL(t_NuMemoryGet, NuMemoryGet);

typedef void* (*t_NuMemory_GetThreadMem)(void* numemory);
DECLARE_SYMBOL(t_NuMemory_GetThreadMem, NuMemory_GetThreadMem);

typedef void* (*t_NuMemoryManager__BlockAlloc)(void* numemory_manager, int align, int size, int heap, void* tracker, int);
DECLARE_SYMBOL(t_NuMemoryManager__BlockAlloc, NuMemoryManager__BlockAlloc);
#pragma endregion

#pragma region Locale
typedef int (*t_NuStringTableLoadCSV)(char*, long*, uint64_t, uint8_t*, int, int, void*, int, char);
DECLARE_SYMBOL(t_NuStringTableLoadCSV, NuStringTableLoadCSV);
#pragma endregion

#pragma region GUI
typedef void (*t_GUI2MenuEntry_SetText)(long* menu_entry, char* locale_key);
DECLARE_SYMBOL(t_GUI2MenuEntry_SetText, GUI2MenuEntry_SetText);

typedef long* (*t_MainMenuScreen_FindObject)(long* main_menu_screen, char* object_name);
DECLARE_SYMBOL(t_MainMenuScreen_FindObject, MainMenuScreen_FindObject);
#pragma endregion