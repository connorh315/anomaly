// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/LightHook.h"
#include "common/assert.h"
#include "common/logging.h"
#include "common/types.h"
#include "hooking.h"

#include "orbis/libkernel.h"

extern "C" void sceSysUtilSendSystemNotificationWithText(int type, const char* message);
extern "C" int sceFiosDHOpen(uint32_t param_1, uint32_t* dh, char* path, uint32_t param_4, uint32_t param_5);
extern "C" void sceFiosOpWait(uint32_t dh);
extern "C" int sceFiosOpGetActualCount(uint32_t dh);
extern "C" void sceFiosOpDelete(uint32_t dh);
extern "C" void sceFiosDHCloseSync(uint32_t param_1, uint32_t dh);
extern "C" int sceFiosDHOpenSync(uint8_t* handle_1, uint32_t* handle_2, char* path, uint8_t* handle_3, int actual_count);
extern "C" int sceFiosDHReadSync(uint32_t param_1, uint32_t dh, SceFiosDirEntry* entry);

HOOK_INIT(FindFileContainer);
void* HOOK_FUNC FindFileContainer(char* flag) {
    void* ret = CONTINUE(FindFileContainer, void* (*)(char*), flag);

    return ret;
}

int (*ParseTextCSV)(char*, long*, uint64_t, uint8_t*, int, int, void*, int, char);


bool is_textcsv_loaded = false;
bool is_textcsv_overrided = false;

int index_to_return = -1;

#define TEXTCSV ((char*)"stuff\\text\\text.csv")
#define TEXTCSV2 ((char*)"stuff/text/text.csv") 

/// <summary>
/// How does this work?
/// ParseTextCSV takes in a filename, and then calls a GetFile function, which will return the file's data, and the GetFile function calls this FindFileIndex to find it in the global file store
/// This intercepts the call to find the index of stuff/text/text.csv (which is only ever called by ParseTextCSV) and will then call ParseTextCSV itself, 
/// but will force the FindFileIndex call of that instance of ParseTextCSV to return an index to the other various text.csv files, rather than just returning the first.
/// </summary>
HOOK_INIT(FindFileIndex);
int FindFileIndex(int* container, unsigned int fileHash, char* filePath) {
    if (!strcmp(filePath, TEXTCSV)) {
        if (index_to_return != -1)
            return index_to_return;

        if (!is_textcsv_overrided && !is_textcsv_loaded) {
            is_textcsv_overrided = true;
            is_textcsv_loaded = true;
        }

        if (is_textcsv_overrided) {
            const int stringCount = *(const int*)((char*)container + 0x20);
            const char* ptr = *(const char**)((char*)container + 0x28);

            for (int i = 0; i < stringCount; i++) {
                size_t len = strlen(ptr);

                // Compare the string BEFORE advancing ptr
                if (!strcmp(ptr, TEXTCSV2)) {
                    const char* string_start = ptr;

                    ptr += len + 1;
                    if ((uintptr_t)ptr & 1)
                        ptr++;

                    uint16_t value = *(const uint16_t*)ptr;
                    index_to_return = value;
                    int result = ParseTextCSV(TEXTCSV, 0, 0, (uint8_t*)"LABEL", 2, -1, 0, 0, 0);
                    LOG_INFO("Custom text.csv returned {}", result);
                    index_to_return = -1;

                    ptr += 2;
                    continue;
                }

                // Still advance ptr even if string doesn't match
                ptr += len + 1;
                if ((uintptr_t)ptr & 1)
                    ptr++;
                ptr += 2;
            }
        }
    }

    is_textcsv_overrided = false;

    int ret =
        CONTINUE(FindFileIndex, int (*)(int*, unsigned int, char*), container, fileHash, filePath);

    return ret;
}

u64 eboot_base_addr = 0;
bool is_deduplicator_enabled = 1;

void toggle_path_deduplication(bool disable) {
    if (is_deduplicator_enabled == !disable) {
        return;
    }

    if (disable) {
        PATCH(0x0004da4d5, "\x48\xE9\xC5\x00\x00\x00"); // Always jump (skip the de-duplication)
    } else {
        PATCH(0x0004da4d5, "\x0F\x87\xC5\x00\x00\x00"); // Conditional jump (de-duplicate where needed)
    }

    is_deduplicator_enabled = !disable;
}

/// <summary>
/// This ensures that all text.csv files will be loaded, rather than just the first. Allowing the FindFileIndex to then return numerous indices, rather than only having access to 1.
/// </summary>
/// <param name=""></param>
HOOK_INIT(BuildPathFromSegments);
void BuildPathFromSegments(long param_1, long* built_path, unsigned int param_3, char zero) {
    CONTINUE(BuildPathFromSegments, void (*)(long, long*, unsigned int, char), param_1, built_path,
             param_3, zero);

    //LOG_INFO("Built path: {}", (char*)(*built_path));

    bool should_disable_dedup = (strcmp((char*)(*built_path), "stuff/text/text.csv") == 0);
    toggle_path_deduplication(should_disable_dedup);
}

void (*PrintDirectoryTree)(long*, char*, unsigned int);

bool ends_with_case_insensitive(const char* str, const char* suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    if (suffix_len > str_len)
        return false;

    const char* str_end = str + str_len - suffix_len;

    for (size_t i = 0; i < suffix_len; i++) {
        if (tolower((unsigned char)str_end[i]) != tolower((unsigned char)suffix[i]))
            return false;
    }

    return true;
}
void get_mods_path_with_filename(const char* entryPath, char* out, size_t maxLen) {
    const char* lastSlash = strrchr(entryPath, '/');
    const char* filename = (lastSlash != NULL) ? lastSlash + 1 : entryPath;

    const char* lastDot = strrchr(filename, '.');
    size_t nameLen = (lastDot != NULL) ? (size_t)(lastDot - filename) : strlen(filename);

    const char* prefix = "mods/";
    size_t prefixLen = strlen(prefix);

    // Ensure the full output fits in the buffer
    if (prefixLen + nameLen >= maxLen)
        nameLen = maxLen - prefixLen - 1;

    memcpy(out, prefix, prefixLen);
    memcpy(out + prefixLen, filename, nameLen);
    out[prefixLen + nameLen] = '\0';
}

void get_filename_without_extension(const char* entryPath, char* out, size_t maxLen) {
    const char* lastSlash = strrchr(entryPath, '/');
    const char* filename = (lastSlash != NULL) ? lastSlash + 1 : entryPath;

    const char* lastDot = strrchr(filename, '.');
    size_t nameLen = (lastDot != NULL) ? (size_t)(lastDot - filename) : strlen(filename);

    if (nameLen >= maxLen)
        nameLen = maxLen - 1;

    memcpy(out, filename, nameLen);
    out[nameLen] = '\0';
}

#define MODS_FOLDER_PATH "/app0/mods"

void get_app0_mods_path(const char* entryPath, char* out, size_t maxLen) {
    const char* lastSlash = strrchr(entryPath, '/');
    const char* filename = (lastSlash != NULL) ? lastSlash + 1 : entryPath;

    const char* lastDot = strrchr(filename, '.');
    size_t nameLen = (lastDot != NULL) ? (size_t)(lastDot - filename) : strlen(filename);

    const char* prefix = MODS_FOLDER_PATH;
    size_t prefixLen = strlen(prefix) + 1; // + 1 for the slash at the end

    // Ensure total length fits in buffer
    if (prefixLen + nameLen >= maxLen)
        nameLen = maxLen - prefixLen - 1;

    memcpy(out, prefix, prefixLen);
    out[prefixLen - 1] = '/';
    memcpy(out + prefixLen, filename, nameLen);
    out[prefixLen + nameLen] = '\0';
}

void* (*GetMemoryArena)();
void* (*GetMemoryAllocator)(void*);
void* (*AllocateMemory)(void*, int, int, int, void*, int);

void load_mods(long param_1) {
    uint32_t handle = 0;
    int result = sceFiosDHOpen(0, &handle, (char*)MODS_FOLDER_PATH, 0, 0);
    sceFiosOpWait(result);
    sceFiosDHCloseSync(0, handle);

    int actualCount = sceFiosOpGetActualCount(result);
    sceFiosOpDelete(result);

    uint64_t handle2 = 0;
    uint32_t handle3 = 0;
    SceFiosDirEntry* entry = (SceFiosDirEntry*)aligned_alloc(16, sizeof(SceFiosDirEntry)); 
    memset(entry, 0, sizeof(SceFiosDirEntry));

    // This chunk of code was such a pita. If someone can get this working without having to use the game's allocator please help :)
    void* tag = reinterpret_cast<void*>(0x800242d079);

    void* arena = GetMemoryArena();
    void* allocator = GetMemoryAllocator(arena);
    void* mem = AllocateMemory(allocator, actualCount, 0x40, 1, tag, 0);
    alignas(8) uint8_t handle_block[0x30] = {};

    result = sceFiosDHOpenSync(handle_block, &handle, (char*)MODS_FOLDER_PATH, (uint8_t*)mem, actualCount); 
    LOG_INFO("Flag 4 {} {} {} {}", handle3, handle, handle2, result);
    if (result == 0) {
        while (sceFiosDHReadSync(0, handle, entry) == 0) {
            LOG_INFO("string length: {}", strlen(entry->fullPath));
            if (ends_with_case_insensitive(entry->fullPath, ".dat")) {
                char modName[128];
                get_app0_mods_path(entry->fullPath, modName, sizeof(modName));
                LOG_INFO("Loading mod {}", modName);
                long* dat = OpenDATFile(
                    (long)0, modName, -1);
                
                LOG_INFO("Pointer address: {}", static_cast<void*>(dat)); 


                if (dat != nullptr) {
                    *(uint32_t*)((char*)dat + 0x128) = 0;

                    // Get the current count
                    int* count_ptr = reinterpret_cast<int*>(param_1 + 0xe40);
                    int count = *count_ptr;

                    // Get the pointer to the list base
                    long** list_base = reinterpret_cast<long**>(param_1 + 0xe48);

                    // Write to the next slot in the list
                    list_base[count] = dat;

                    // Increment the count
                    *count_ptr = count + 1;
                }
            }
        }
        sceFiosDHCloseSync(0, handle);
    }

    // Teeheehee I don't even free it :)
}

HOOK_INIT(OpenDATFile);
long* OpenDATFile(long param_1, char* filename, int counter) {
    if (!strcmp(filename, "upd:PATCH") && counter < 0) { // This is the first ever call to the OpenDATFile function, which means we stop it, load our mods, then let it continue execution. Meaning mods are the first DATs in.
        load_mods(param_1);
    }

    return CONTINUE(OpenDATFile, long* (*)(long, char*, int), param_1, filename, counter);
}




#define ZERO "\x00"

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

bool eboot_hook(u64 base_addr) {
    LOG_INFO("Adding MODFILE loading");
    patch_nuisance_functions();

    LOG_INFO("Hooking eboot functions");
    // HOOK(0x0005ab4b0, FindFileContainer); // Always returns dat container
    HOOK(0x0004d3ec0, FindFileIndex);
    HOOK(0x0005adc70, OpenDATFile);
    HOOK(0x0004d7b90, BuildPathFromSegments);

    ParseTextCSV = (int (*)(char*, long*, uint64_t, uint8_t*, int, int, void*, int, char))(
        base_addr + 0x4ef570);

    PrintDirectoryTree = (void (*)(long*, char*, unsigned int))(base_addr + 0x5c87c4);

    GetMemoryArena = (void* (*)())(base_addr + 0x4adb10);
    GetMemoryAllocator = (void* (*)(void*))(base_addr + 0x4adb90);
    AllocateMemory = (void* (*)(void*, int, int, int, void*, int))(base_addr + 0x4a83d0);

    return true;
}

#define ANOMALY_INITIALISED "Anomaly BETA v1.0.0 initialised!"

extern "C" int32_t __wrap__init(size_t, void*) {
    OrbisKernelModuleInfo* module_info = new OrbisKernelModuleInfo();
    module_info->size = sizeof(OrbisKernelModuleInfo);
    sceKernelGetModuleInfo(0, module_info);
    eboot_base_addr = (u64)module_info->segmentInfo[0].address;

    if (strcmp((char*)(eboot_base_addr + 0x2421EBD), "EU_PATCH11C")) {
        LOG_INFO("Invalid LEGO Dimensions version. Ensure your game is the EU version and up to date!");
        return 0;
    }

    if (!eboot_hook((u64)module_info->segmentInfo[0].address)) {
        LOG_ERROR("Something went wrong with hooking setup!");
        return 0;
    }

    sceSysUtilSendSystemNotificationWithText(222, ANOMALY_INITIALISED);

    LOG_INFO(ANOMALY_INITIALISED);

    return 0;
}
