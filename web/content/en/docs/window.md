---
title: The window
seoTitle: certdoctor-gui - the certificate diagnosis in a window
description: "certdoctor-gui shows the same report in a window on Windows, Linux and macOS: type the address, press Diagnose, read the report and save it."
lead: "The same diagnosis without a terminal, for anyone who would rather type an address into a box."
---

## What it does

Type the address that fails, press **Diagnose**, and read the report: the sentence naming the cause on top, the layers on the left, the evidence of each one beside them. Save the report as HTML, Markdown or JSON for a ticket.

The window runs the command line that sits next to it and shows what it reports, so it knows nothing the command line does not, and the two never disagree. The options it offers are the command line's switches.

## Where it runs

{{< downloads "certdoctor-gui" >}}

Each archive carries the command line as well. The [download page](/download/) has them all.

## Keep its files together

The window starts the `certdoctor` that sits next to it, so keep the files of the archive in one folder.

On Windows, the `opengl` folder holds a software renderer. On a machine whose graphics driver offers no OpenGL 2.1 - a virtual machine without 3D acceleration, or a Remote Desktop session - the window starts again with it, by itself.

On macOS, keep the bundle and the links next to it together. The signature and Apple's notarisation belong to the bundle, so a program copied out of it on its own is not the program Apple checked.

On Linux, the window needs a desktop session with OpenGL. It loads `libGL.so.1` and `libwayland-client.so.0`, which a desktop installation has.

## What it keeps

One setting: the folder you last saved a report to, in `preferences.json` in your user folder - `AppData\Roaming\fyne\dev.donislaw.certdoctor` on Windows, `~/.config/fyne/dev.donislaw.certdoctor` on Linux and `~/Library/Preferences/fyne/dev.donislaw.certdoctor` on macOS. Fyne, the toolkit the window is built with, creates that folder when the window starts, and an empty one of the same name in your user cache folder. Delete both when you remove the window.
