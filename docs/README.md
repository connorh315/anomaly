# Anomaly Mod Loader

Anomaly is an Open-Source mod loader for LEGO Dimensions PS4!

Installing Anomaly and adding mods is quick and easy - no special tools or knowledge required.

Built and tested on the Windows version of shadPS4 v0.10.1 but should work on other platforms too.

[!IMPORTANT]
Your game must be the **EU version**, and on **version 1.24** for this to work. Other versions are not supported.

## Installing Anomaly

1. Go to the [releases](releases/) page, and download the most recent version.
2. Locate where your game is installed, and place the downloaded `.PRX` file into the `sce_module` folder.

## Installing mods

1. Download some mods that you would like to use. 
2. In your game folder (where `data`, `sce_module`, and `sce_sys` are), create a new folder called `mods`.
3. Place your mods inside the `mods` folder.

[!NOTE]
The mod must include both a `.DAT` as well as a `.HDR` file for the game to include it.

## Uninstalling mods

To uninstall mods, simply remove them from the mods folder. They will then not be included on the next run of the game.

To remove Anomaly altogether: Remove the `anomaly.prx` file from the `sce_module` folder.

## Creating mods

See the ["Getting started"](docs/gettingstarted.md) page.

## Features

- Adds the ability to load in custom .DAT files that take priority over regular GAME/PATCH .DAT files.
- Adds support for layered `text.csv` files, allowing mods to coexist without overwriting each other.
- Removes the annoying spam in the console from unimplemented (and unnecessary) functions such as `sceVideoOutSetWindowModeMargins`, `sceRemotePlayProhibit` and others.

This mod was implemented using [kalaposfos13's eboot-hooks-prx template](https://github.com/kalaposfos13/eboot-hooks-prx).