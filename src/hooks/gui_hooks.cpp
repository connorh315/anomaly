#include "hooks/hooks.h"
#include "symbols.h"
#include "globals.h"

HOOK_INIT(MainMenuScreen_AboutToShow);
void MainMenuScreen_AboutToShow(long* main_menu_screen) {
    CONTINUE(MainMenuScreen_AboutToShow, void (*)(long*), main_menu_screen);
    long* switchprofile = MainMenuScreen_FindObject(main_menu_screen, "xml_switchprofile");
    if (switchprofile) {
        char text[64];
        snprintf(text, sizeof(text), "Anomaly (%d loaded)", g_mods_loaded);
        GUI2MenuEntry_SetText(switchprofile, text);
    }
}

bool HookGUIFunctions() {
    PATCH(0x0cb9286,
          "\x90\x90\x90\x90\x90"); // RemoveMenuEntries (Disables: Remove SwitchProfile Entry)

    HOOK(0x000cb9430, MainMenuScreen_AboutToShow);

    return true;
}