# Anomaly Mod Loader

Anomaly is used to load custom mods into the PS4 version of LEGO Dimensions. This guide will help you get set up with creating your own mods.

By the end of this guide, you will know how to build, install, and test your own Anomaly mods.

## How Anomaly works

Anomaly works by loading custom `.DAT` files from the `mods` folder in your game directory. These files take priority over the `.DAT` files packaged with the game, allowing you to override / add new content.

## Requirements

You will need to have successfully installed LEGO Dimensions in shadPS4, and have Anomaly installed as per the [README](README.md) instructions.

To create a mod archive (a `.DAT` file), you will need to download and use [BrickVault](https://github.com/connorh315/BrickVault) to package your mod's content. BrickVault is a tool that allows you to view the contents of existing mods / game archives, as well as create your own.

## Example text-edit mod

Let's create a very simple mod, that will change some of the in-game text. For other examples, see the [example mods directory](examples/).

### 1. Creating the folder structure

In this tutorial, you will be creating a mod that changes the name of the hub world `Vorton` to `Portal room!`. This will give you a basic understanding of how text overrides work, and how to package mods.

Begin by creating a new folder somewhere on your PC (I will create a folder called `MyFirstMod`). This will be the directory that will hold your mod's files. In later steps, we will package this folder into a `.DAT` archive that Anomaly can load.

Inside this folder, create a new folder called `STUFF`. Inside of `STUFF`, create another folder called `TEXT`.

> [!TIP]
> The case of the folders/files is not important, as uppercase/lowercase information is stripped when packaged into a `.DAT` file. However, it is recommended to use uppercase names for consistency.

Your folder structure should now look like this:

```
MyFirstMod/
└── STUFF/
    └── TEXT/
```

### 2. Creating the TEXT.CSV file

The `TEXT.CSV` file is where all of the in-game text is stored. We will be creating our own version of this file to override some of the game's text.

Instead of creating the file from scratch, let's take the existing `TEXT.CSV` file from the game, and modify it. This way we can see what the format should be, and ensure we follow it correctly.

> [!IMPORTANT]
> Dimensions has multiple versions of the same file, stored across different `.DAT` archives. To ensure our mod works correctly, we will be using the `TEXT.CSV` file from the `PATCH` archive, as these archives have the highest priority.

Using BrickVault, go to `File -> Open` and locate and open the `PATCH.DAT` file in your LEGO Dimensions installation (it should be located in the `data/chunk1` folder). Once opened, navigate to the `STUFF/TEXT/` folder, and extract the `TEXT.CSV` file somewhere temporary on your PC (i.e. your Desktop). Do not save it directly into your mod folder.

Open the extracted `TEXT.CSV` file in a text editor (such as Notepad, or Visual Studio Code). 

> [!WARNING]
> The `TEXT.CSV` file does not conform to standard CSV formatting, so opening it in software such as Excel will cause the file to be saved incorrectly (and not load properly in-game). Use a standard text editor!

This large file contains all of the in-game text, for various languages. Each line starts with a unique identifier that is used to "look up" the translation. Following the identifier are multiple columns, beginning with the platform (i.e. PS4, WII, ALL), and then a type (Marketing, Game, Hint, etc.). The columns after this are the actual text, for various languages.

Let's now make our own `TEXT.CSV` file inside of the `TEXT/` folder in our mod directory. Copy the **first and second line** of the extracted `TEXT.CSV` file (the line that begins `"LABEL",...` and the line that is just empty strings) into your new `TEXT.CSV` file. Both lines are required.

For this example, let's do a really simple change: `Vorton` to `Portal room!`. Inside of the extracted `TEXT.CSV`, **search** for the line that begins with `"HUB_HUB"` - It should look like this:

`"HUB_HUB","All","Level","Vorton","Vorton","Vorton",...`

Copy the line over from the game's `TEXT.CSV` to the bottom of our mod's `TEXT.CSV`, and change all instances of `Vorton` to `Portal room!`, so it looks like this:
`"HUB_HUB","All","Level","Portal room!","Portal room!","Portal room!",...`

The `TEXT.CSV` file should have three lines in total now:
```
"LABEL","PLATFORM","TYPE","ENGLISH","AMERICAN","FRENCH",...
"","","","","","",...
"HUB_HUB","All","Level","Vorton","Vorton","Vorton",...
```

> [!IMPORTANT]
> The ellipses above indicate that there are more columns in the actual file. Ensure that you copy the entire line, do not use the ellipses!

Make sure to save the file, and move on to the next step.

> [!CAUTION]
> If you have experience modding other LEGO games, you might be tempted to copy over the entire `TEXT.CSV` file just to add/edit the few lines you want to modify. This is unnecessary, and will cause conflicts with other mods (making your mod less desirable!).
> See the section on [Layered Files](LAYEREDFILES.md) to understand how Anomaly handles multiple mods modifying the same files.

### 3. Packaging the mod into a DAT file

Now that we have our mod files ready, we need to package them into a `.DAT` archive that Anomaly can load.

Open BrickVault, and go to `File -> Build Archive`. In the window that opens, click on `New Archive`, and select `MOD` as the archive type.

Complete **all** the fields in the window. I will be using the following values:

```
Input Folder: <D:\mods\MyFirstMod>
Output File: <D:\LegoDimensions\CUSA01176\mods\MyFirstMod.DAT> (I would recommend outputting directly to your game's mods folder, so you don't have to copy it every time you rebuild it)
Friendly Name: "My first ever mod" (This is the name that will show up listed in BrickVault, it can be anything you like)
Mod name: "Rename Vorton" (This is the internal name of the mod. Whilst it is not used at the moment, it will be in future versions of Anomaly)
Author: "connorh315"
Version: "1.0" (Again, not currently used, but will be in future versions of Anomaly)
Build HDR File: Checked (Really important that you check this!)
Archive version: "V11" (This is the version used by LEGO Dimensions)
```

> [!WARNING]
> You must ensure that `Build HDR File` is checked, as Dimensions requires both a `.DAT` and a `.HDR` file for mods (and even game archives) to be loaded correctly.

When you are ready, click on `Save settings` and then `Build`. If everything goes well, you should see a progress bar and a message saying `Done`.

### 4. Testing the mod in-game

Open the game using shadPS4 as normal. Once you get to the title screen, you should see a menu option on the left-hand side called `Anomaly (X loaded)`, where `X` is the number of mods in your `mods` folder that were successfully loaded. If this is your only mod in the folder, then it should say `Anomaly (1 loaded)`.

Load into the game, and go to Vorton, when you arrive, the text at the bottom of the screen should now say `Portal room!` instead of `Vorton`.

That's it! You have successfully created and loaded your first Anomaly mod!

> [!NOTE]
> Want to share your mod with others? Remember to share both the `.DAT` and `.HDR` files!

### 5. Next steps

Play around with copying and modifying other text entries in the `TEXT.CSV` file. Remember to rebuild your mod using BrickVault each time you make changes. You will also need to restart the game to see changes take effect.

> [!TIP]
> Notice how long it takes to get into the game with the unskippable splash screens? How about creating a mod that decreases the loading times? See the [quick startup mod example](examples/QUICKSTARTUPMOD.md) to create a mod that does just that!