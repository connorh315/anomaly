#pragma once

#include <stdarg.h>
#include <stdio.h>

#include "common/types.h"
#include "fmt/format.h"

extern "C" int32_t __wrap__init(size_t, void*);

long* OpenDATFile(long param_1, char* filename, int counter);

//typedef struct SceFiosDirEntry {
//    uint64_t fileSize;
//    uint32_t statFlags;
//    uint16_t nameLength;
//    uint16_t fullPathLength;
//    uint16_t offsetToName;
//    uint16_t reserved[3];
//    char fullPath[1024];
//} SceFiosDirEntry;