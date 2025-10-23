#pragma once
#include <cstdint>

struct LayerableFile {
    uint32_t hash;
    const char* path;
    bool isActive;
    int last_collisions_index;
    int last_yielded_index;
    bool isLoaded;
    bool lookAhead;
    bool isExhausted;
};

extern LayerableFile g_layerable_Files[];

LayerableFile* FindLayerableFileByHash(uint32_t hash);
void LayerableFileHasYielded(LayerableFile* file);