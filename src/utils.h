#pragma once

#include <stdarg.h>
#include <stdio.h>

#include "common/types.h"
#include "fmt/format.h"

bool ends_with_case_insensitive(const char* str, const char* suffix);