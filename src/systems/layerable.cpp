#include "layerable.h"

LayerableFile g_layerable_files[] = {
    {0x1347d7cd, "stuff/text/text.csv", false, -1, -1, false, false, false},
    {0x874ca1b4, "chars/collection.txt", false, -1, -1, false, true, false},
};

LayerableFile* FindLayerableFileByHash(uint32_t hash) {
    for (auto& file : g_layerable_files)
        if (file.hash == hash)
            return &file;
    return nullptr;
}

void LayerableFileHasYielded(LayerableFile* file) {
    file->last_yielded_index = file->last_collisions_index;
}