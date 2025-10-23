# Anomaly Mod Loader
## Modding state of play

Anomaly is a mod loader, enabling modders to create and share mods, and users to easily install and manage them.

The original method for modding LEGO games was to extract all of the game files (significantly decompressing them), and then pasting files over the top of them. This led to mods being incompatible with each other if they modified the same file (which most will) and also made it a headache for users, as it was not a drag-and-drop solution, requiring significant work, just to add a single character to the game.

Anomaly has significantly improved the distribution, installation, and management of mods. It allows multiple mods to edit the same file, and conglomerates all of the changes as best as possible.

However, Anomaly does not facilitate the creation of mods. Modders still need to understand the proprietary file formats, and how to edit them. The extent to which this is possible varies significantly between file types.

The table below summarises the current state of modding for each file type in LEGO Dimensions (specifically the PS4 version).

| File Type | Purpose | Modding Status | Notes |
| --- | --- | --- | --- |
| .ABILITY / .ABILITIES | Ability Definition | ✅ Fully supported | [AbilityEditor]() can be used to edit these files |
| .AN4 | Animation | 🚧 Work in progress | No tools currently exist to edit these files |
| .AS | Animation set | ✅ Fully supported | [Flux](https://github.com/connorh315/flux) can be used to edit these files |
| .BINARY | Defines collections | ✅ Fully supported | Editable with any text editor |
| .CBX | Highly-compressed audio | ⚪ Irrelevant | CBX files are only used in low-power platforms (Wii U). Tools like [CBXDecoder]() and [vgmstream](https://vgmstream.org/) can play CBX files if needed |
| .CD | Character Definition | ✅ Fully supported | [Flux](https://github.com/connorh315/flux) can be used to edit these files |
| .CFG | Configuration | ✅ Fully supported | Editable with any text editor |
| .CPD | Character Skeleton Definition | ✅ Fully supported | [Flux](https://github.com/connorh315/flux) can be used to edit these files |
| .CPJ | Character Project | ✅ Fully supported | [Flux](https://github.com/connorh315/flux) can be used to edit these files |
| .CSV | Data table | ✅ Fully supported | Editable with any text editor |
| .CU3 | Cutscene | 🚧 Work in progress | No tools currently exist to edit these files |
| .DNO | Dyno (Physics Mesh) | 🚧 Work in progress | No tools currently exist to edit these files |
| .FMV | Pre-rendered video | ⚠️ Partial support | No tools currently exist to edit these files. They can be viewed with [EveryFileExplorer](https://github.com/PabloMK7/EveryFileExplorer) |
| .FNT | Old font format | ⚪ Irrelevant | Not used in LEGO Dimensions PS4 |
| .FST | Footsteps | 🚧 Work in progress | No tools currently exist to edit these files |
| .FT2 | New font format | 🚧 Work in progress | No tools currently exist to edit these files |
| .GHG | Model Geometry (Skinned) | 🚧 Work in progress | No tools currently exist to edit these files |
| .GIZ | Gizmos | 🚧 Work in progress | No tools currently exist to edit these files |
| .GLM | Grid map | ⚪ Irrelevant | Purpose is unclear, no tools currently exist to edit these files |
| .GSC | Model Geometry (Static) | 🚧 Work in progress | No tools currently exist to edit these files |
| .KRW | Krawlie | 🚧 Work in progress | No tools currently exist to edit these files |
| .LED | Lego Editor Data | ✅ Fully supported | [Flux](https://github.com/connorh315/flux) can be used to edit these files |
| .NXG_TEXTURES | Textures | ✅ Fully supported | [NUTCracker](https://github.com/JayFrancoe/NuTCrackerV3/) can be used to edit these files |
| .OGG | Audio | ✅ Fully supported | OGG files can be edited with many audio editors |
| .PAR | Parts | 🚧 Work in progress | No tools currently exist to edit these files |
| .PTL | Particle | 🚧 Work in progress | No tools currently exist to edit these files |
| .RES | Resource | ⚪ Irrelevant | Used by the game to build a resource queue, can be ignored |
| .SF | Script | ✅ Fully supported | Editable with any text editor |
| .SOUND_EVENT | Sound Event | ✅ Fully supported | [SoundEventEditor]() can be used to edit these files |
| .SUB | Subtitle | ✅ Fully supported | Editable with any text editor |
| .TEX | Texture | ✅ Fully supported | This is just a DDS file, which can be edited with many image editors |
| .TSH | Texture Sheet | ✅ Fully supported | [BacTSH](https://github.com/AlubJ/BacTSH) can be used to edit these files |
| .TXC | Collectables | ✅ Fully supported | Editable with any text editor |

> [!NOTE]
> Most file types are included here for completeness, but many will not be relevant to most modders. The remaining WIP file types that are likely to be of interest to modders are: `AN4`, `CU3`, `DNO`, `GHG`, `GSC`.

Despite many file types being marked as "Work in progress", a significant amount of modding is already possible. Mods such as adding in new characters, with custom audio and textures, are already possible. Adding in static models will greatly increase modding potential. 

Additionally, it's important that each mod introduces content in a way that minimises conflicts with other mods. For example, creating a character mod that adds in custom text should not override the entire `TEXT.CSV` file, which is why the [Layered Files](LAYEREDFILES.md) system was introduced.

The current list of layered files supported by Anomaly can be found in the [Layered Files](LAYEREDFILES.md) document.