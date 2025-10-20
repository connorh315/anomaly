#include "utils.h"

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