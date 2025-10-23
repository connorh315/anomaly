#include "hooks/hooks.h"
#include "symbols.h"
#include "globals.h"
#include "utils.h"

#include "systems/layerable.h"

extern "C" int sceFiosDHOpen(uint32_t param_1, uint32_t* dh, char* path, uint32_t param_4,
                             uint32_t param_5);
extern "C" void sceFiosOpWait(uint32_t dh);
extern "C" int sceFiosOpGetActualCount(uint32_t dh);
extern "C" void sceFiosOpDelete(uint32_t dh);
extern "C" void sceFiosDHCloseSync(uint32_t param_1, uint32_t dh);
extern "C" int sceFiosDHOpenSync(uint8_t* handle_1, uint32_t* handle_2, char* path,
                                 uint8_t* handle_3, int actual_count);
extern "C" int sceFiosDHReadSync(uint32_t param_1, uint32_t dh, SceFiosDirEntry* entry);

#define TEXTCSV ((char*)"stuff\\text\\text.csv")
#define TEXTCSV2 ((char*)"stuff/text/text.csv")

#define COLLECTIONTXT ((char*)"chars/collection.txt")

/// <summary>
/// How does this work?
/// ParseTextCSV takes in a filename, and then calls a GetFile function, which will return the
/// file's data, and the GetFile function calls this FindHash to find it in the global file
/// store This intercepts the call to find the index of stuff/text/text.csv (which is only ever
/// called by ParseTextCSV) and will then call ParseTextCSV itself, but will force the FindHash
/// call of that instance of ParseTextCSV to return an index to the other various text.csv files,
/// rather than just returning the first.
/// </summary>
HOOK_INIT(NuFileTable_FindHash);
int NuFileTable_FindHash(int* file_table, unsigned int fileHash, char* filePath) {
    //LOG_INFO("FindFileIndex called with filePath: {}", filePath);

    const int stringCount = *(const int*)((char*)file_table + 0x20);
    const char* ptr = *(const char**)((char*)file_table + 0x28);

    auto* layerable = FindLayerableFileByHash(fileHash);
    if (layerable && layerable->isActive && !layerable->isLoaded) {
        if (layerable->last_yielded_index != layerable->last_collisions_index) {
            LOG_INFO("Yielding control back to ParseTextCSV for {}", layerable->path);
            return layerable->last_collisions_index; // Yield control back to ParseTextCSV
        }

        int prev_index = -1;
        for (int i = 0; i < stringCount; i++) {
            size_t len = strlen(ptr);

            LOG_INFO("Checking file entry: {}", ptr);

            if (i > layerable->last_collisions_index && !strcmp(ptr, layerable->path)) {
                if (layerable->lookAhead && prev_index != -1)
                    return prev_index;

                ptr += len + 1;
                if ((uintptr_t)ptr & 1)
                    ptr++;



                prev_index = *(const uint16_t*)ptr;
                LOG_INFO("Returning value {}", prev_index);
                layerable->last_collisions_index = i;
                ptr += 2;
                if (!layerable->lookAhead)
                    return prev_index;
                else
                    continue;
            }

            // Advance to next
            ptr += len + 1;
            if ((uintptr_t)ptr & 1)
                ptr++;
            ptr += 2;
        }

        if (prev_index != -1) {
            layerable->isExhausted = true;
            LOG_INFO("Layers complete, returning {}", prev_index);
            return prev_index; // Final lookahead return
        }

        LOG_INFO("Finished loading all layers for {}", layerable->path);
        layerable->isLoaded = true;
    }

    int ret =
        CONTINUE(NuFileTable_FindHash, int (*)(int*, unsigned int, char*), file_table, fileHash, filePath);

    return ret;
}

HOOK_INIT(NuStringTableLoadCSV);
int NuStringTableLoadCSV(char* path, long* param_2, uint64_t param_3, uint8_t* label, int param_5, int param_6, void* param_7, int param_8, char param_9) {
    uint32_t hash = 0x1347d7cd;

    auto* layerable = FindLayerableFileByHash(hash);
    if (!strcmp(path, TEXTCSV) && layerable && !layerable->isActive) {
        layerable->isActive = true;
        bool cleared = false;
        int result = 0;

        // Keep loading until this file’s entries are fully processed
        while (!layerable->isLoaded) {
            result = CONTINUE(
                NuStringTableLoadCSV,
                int (*)(char*, long*, uint64_t, uint8_t*, int, int, void*, int, char), path,
                param_2, param_3, label, param_5, param_6, param_7, param_8, param_9);

            if (cleared == false) {
                PATCH(0x004ef7b4, "\x90\x90\x90\x90\x90"); // Stops clearing the table
                cleared = true;
            }

            LayerableFileHasYielded(layerable);
        }

        return result; // Don’t fall through after layering is done
    }

    return CONTINUE(NuStringTableLoadCSV,
                    int (*)(char*, long*, uint64_t, uint8_t*, int, int, void*, int, char), path,
                    param_2, param_3, label, param_5, param_6, param_7, param_8, param_9);
}

HOOK_INIT(MechCollections_ImportCollectionFile);
void MechCollections_ImportCollectionFile(long* mech_collections, char* path, long* param_3, long* dlc_collection) {
    uint32_t hash = 0x874ca1b4;
    LOG_INFO("MechCollections_ImportCollectionFile called with path: {}", path);

    CONTINUE(MechCollections_ImportCollectionFile, void (*)(long*, char*, long*, long*),
            mech_collections, path, param_3, dlc_collection);

    LOG_INFO("Vector size: {}", *(long*)((char*)param_3 + 12));

    if (path[0] == '.' && path[1] == '/') { // Loading main collection.txt file
        auto* layerable = FindLayerableFileByHash(hash);
        if (layerable && !layerable->isActive) {
            layerable->isActive = true;
            PATCH(0x011c457f, "\xeb\x32");

            // Keep loading until this file’s entries are fully processed
            while (!layerable->isLoaded && !layerable->isExhausted) {
                CONTINUE(MechCollections_ImportCollectionFile,
                         void (*)(long*, char*, long*, long*), mech_collections, path, param_3,
                         dlc_collection);
                LOG_INFO("Vector size: {}", *(long*)((char*)param_3 + 12));
                LayerableFileHasYielded(layerable);
            }
            return; // Don’t fall through after layering is done
        }
    }


    
}

bool is_deduplicator_enabled = 1;

void toggle_path_deduplication(bool disable) {
    if (is_deduplicator_enabled == !disable) {
        return;
    }

    if (disable) {
        PATCH(0x0004da4d5, "\x48\xE9\xC5\x00\x00\x00"); // Always jump (skip the de-duplication)
    } else {
        PATCH(0x0004da4d5,
              "\x0F\x87\xC5\x00\x00\x00"); // Conditional jump (de-duplicate where needed)
    }

    is_deduplicator_enabled = !disable;
}

/// <summary>
/// This ensures that all text.csv files will be loaded, rather than just the first. Allowing the
/// FindFileIndex to then return numerous indices, rather than only having access to 1.
/// </summary>
/// <param name=""></param>
HOOK_INIT(NuFileTree_GetFilename);
void NuFileTree_GetFilename(long file_tree, long* built_path, unsigned int param_3, char zero) {
    CONTINUE(NuFileTree_GetFilename, void (*)(long, long*, unsigned int, char), file_tree, built_path,
             param_3, zero);

    bool should_disable_dedup = (strcmp((char*)(*built_path), "stuff/text/text.csv") == 0);
    toggle_path_deduplication(should_disable_dedup);
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

long* NuFileDeviceDat_OpenIndividual(long param_1, char* filename, int counter);

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

    // This chunk of code was such a pita. If someone can get this working without having to use the
    // game's allocator please help :)
    void* tag = reinterpret_cast<void*>(0x800242d079);

    void* arena = NuMemoryGet();
    void* allocator = NuMemory_GetThreadMem(arena);
    void* mem = NuMemoryManager__BlockAlloc(allocator, actualCount, 0x40, 1, tag, 0);
    alignas(8) uint8_t handle_block[0x30] = {};

    result = sceFiosDHOpenSync(handle_block, &handle, (char*)MODS_FOLDER_PATH, (uint8_t*)mem,
                               actualCount);
    LOG_INFO("Flag 4 {} {} {} {}", handle3, handle, handle2, result);
    if (result == 0) {
        while (sceFiosDHReadSync(0, handle, entry) == 0) {
            LOG_INFO("string length: {}", strlen(entry->fullPath));
            if (ends_with_case_insensitive(entry->fullPath, ".dat")) {
                char modName[128];
                get_app0_mods_path(entry->fullPath, modName, sizeof(modName));
                LOG_INFO("Loading mod {}", modName);
                long* dat = NuFileDeviceDat_OpenIndividual((long)0, modName, -1);

                LOG_INFO("Pointer address: {}", static_cast<void*>(dat));

                if (dat != nullptr) {
                    g_mods_loaded++;
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

    NuMemoryManager_BlockFree(allocator, mem, 0);
}

HOOK_INIT(NuFileDeviceDat_OpenIndividual);
long* NuFileDeviceDat_OpenIndividual(long param_1, char* filename, int counter) {
    if (!strcmp(filename, "upd:PATCH") &&
        counter < 0) { // This is the first ever call to the OpenDATFile function, which means we
                       // stop it, load our mods, then let it continue execution. Meaning mods are
                       // the first DATs in.
        load_mods(param_1);
    }

    return CONTINUE(NuFileDeviceDat_OpenIndividual, long* (*)(long, char*, int), param_1, filename, counter);
}

bool HookFileFunctions() {
    HOOK(0x0004d3ec0, NuFileTable_FindHash);
    HOOK(0x0004d7b90, NuFileTree_GetFilename);
    HOOK(0x0005adc70, NuFileDeviceDat_OpenIndividual);
    HOOK(0x0004ef570, NuStringTableLoadCSV);
    HOOK(0x0011c4540, MechCollections_ImportCollectionFile);

    return true;
}