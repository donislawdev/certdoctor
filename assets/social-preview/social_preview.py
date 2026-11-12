"""Draw the picture a link to certdoctor shows when it is shared.

    python assets/social-preview/social_preview.py    social-preview.png beside this file

One picture serves both places a link is shared from. GitHub shows it for a
link to the repository, once somebody uploads it by hand under Settings,
General, Social preview - GitHub keeps a copy of its own that nothing here
writes to. The website names it in og:image through a mount in web/hugo.toml.
It is 1280 by 640, what GitHub asks for, and a 2:1 picture is also what X shows
whole. Sites that cut to 1.91:1 take about 30 pixels off each side, so nothing
sits closer than 64 pixels to an edge.

It is drawn from the program's own parts rather than from artwork: the icon
assets/icon/appicon.py draws, the Inter typeface the window ships
(internal/gui/fonts, SIL Open Font License), the monospaced face the window
keeps from Fyne (DejaVu Sans Mono, read from the module cache at the version
go.mod names), and the window's colours (internal/gui/look/palette.go). Pillow
draws it, a build tool here as it is for the icon.

What it has to say. A feed shows it about 500 pixels wide, so the headline
carries it: the situation people are in when they search for this program,
said in the website's own words. The panel beside it shows the answer.

Everything on it is real. The stores along the bottom are the program's own
list, read from web/data/facts/certdoctor.json, which cmd/sitefacts writes
and its test holds to the program. The panel is cut line for line from the
run recorded for the README GIF on 2026-11-03 (untrusted-root.badssl.com in a
Debian container whose system store holds BadSSL's root and whose two Java
runtimes do not) - only paths too long for the panel are shortened, with an
ellipsis where the cut is.

WHEN THE PROGRAM CHANGES. A new family of trust store reaches the facts file
first, and then this script refuses to draw until LABELS gives it a name, so
the picture cannot leave a store out or name one the program dropped. The
picture carries, as PNG text, the stores it names and the digest of this
script, and cmd/sitefacts' test fails when either is no longer true - an edit
here without a new picture, or a store the picture does not name. Then:

    go run ./cmd/sitefacts > web/data/facts/certdoctor.json
    python assets/social-preview/social_preview.py

look at the picture, commit it, and upload it to GitHub again.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont
from PIL.PngImagePlugin import PngInfo

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ICON = ROOT / "assets" / "icon" / "certdoctor.png"
FONTS = ROOT / "internal" / "gui" / "fonts"
FACTS = ROOT / "web" / "data" / "facts" / "certdoctor.json"
OUT = HERE / "social-preview.png"

WIDTH, HEIGHT = 1280, 640
MARGIN = 64
LEFT_WIDTH = 616
PANEL_LEFT = 716
PANEL_WIDTH = WIDTH - MARGIN - PANEL_LEFT

# The PNG text keys cmd/sitefacts' test reads.
KEY_STORES = "certdoctor:stores"
KEY_DRAWN_BY = "certdoctor:drawn-by"

# internal/gui/look/palette.go
PAGE = (0x16, 0x18, 0x1C)
SUNKEN = (0x11, 0x13, 0x17)
SURFACE = (0x1E, 0x21, 0x26)
RAISED = (0x27, 0x2B, 0x32)
EDGE = (0x2C, 0x31, 0x38)
INK = (0xE6, 0xE8, 0xEA)
INK_MUTED = (0xA0, 0xA6, 0xAD)
FOCUS = (0x8A, 0xB4, 0xF8)
SHIELD = (0x35, 0x70, 0xD6)
PASS = (0x56, 0xD3, 0x64)
FAIL = (0xFF, 0x8D, 0x8D)

TITLE = "certdoctor"
SURFACES = "GUI + CLI"
HEADLINE = [("The browser connects.", INK), ("Your program does not.", FOCUS)]
LEAD = ("One command asks every trust store on the machine and prints "
        "the command that fixes each one that refuses.")
STORES_LABEL = "The stores it asks"
# Kept as code points so the source stays ASCII.
DOT = chr(0x00B7)
ELLIPSIS = chr(0x2026)
FOOT = f"Free and open source, GPL-3.0  {DOT}  changes nothing, no telemetry"
PLATFORMS = f"Windows  {DOT}  macOS  {DOT}  Linux"
ADDRESS = "certdoctor.donislawdev.com"

# How the picture names each family the program asks. Keyed by the name a
# report gives the family, which is what the facts file lists.
LABELS = {
    "system-store": "system store",
    "git": "git",
    "java": "every JDK and JRE",
    "curl": "curl",
    "node": "Node.js",
    "python": "Python",
    "pip": "pip",
}

# The run, cut from the README GIF's recording.
COMMAND = "certdoctor https://untrusted-root.badssl.com/"
LAYER = ("FAIL", "L5  Trust matrix", "3 of 6 store(s) do not trust")
ROWS = [
    ("PASS", "system-store", "debian", "trusts"),
    ("PASS", "git", "/usr/bin/git", "trusts"),
    ("FAIL", "java", "/usr/lib/jvm/temurin-17-jre", "does NOT trust"),
    ("FAIL", "java", "/usr/lib/jvm/temurin-21-jre", "does NOT trust"),
    ("PASS", "curl", "/usr/bin/curl", "trusts"),
    ("FAIL", "python", "/usr/bin/python3", "does NOT trust"),
]
FIX = [
    f"run: '{ELLIPSIS}/temurin-17-jre/bin/keytool' -importcert",
    f"  -trustcacerts -keystore '{ELLIPSIS}/cacerts'",
    "  -storepass changeit -alias '<alias>'",
    "  -file '<certificate.pem>'",
]
CAPTION = "A real run. Every store that refuses gets its own command."


def inter(bold: bool, size: int) -> ImageFont.FreeTypeFont:
    name = "Inter-Bold.ttf" if bold else "Inter-Regular.ttf"
    return ImageFont.truetype(str(FONTS / name), size)


def mono_path() -> Path:
    """The monospaced face the window draws code in, as Fyne ships it."""
    version = re.search(r"^\s*fyne\.io/fyne/v2 (\S+)", (ROOT / "go.mod").read_text("utf-8"), re.M)
    if not version:
        raise SystemExit("go.mod no longer requires fyne.io/fyne/v2, so there is no monospaced face to draw with")
    cache = subprocess.run(["go", "env", "GOMODCACHE"], capture_output=True, text=True, check=True).stdout.strip()
    path = Path(cache) / "fyne.io" / "fyne" / f"v2@{version.group(1)}" / "theme" / "font" / "DejaVuSansMono-Powerline.ttf"
    if not path.is_file():
        raise SystemExit(f"{path} is missing - run: go mod download fyne.io/fyne/v2")
    return path


def mono(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(mono_path()), size)


def stores() -> list[str]:
    """The program's families, refused when LABELS does not name exactly them."""
    asked = json.loads(FACTS.read_text("utf-8"))["stores"]
    unnamed = [s for s in asked if s not in LABELS]
    if unnamed:
        raise SystemExit(f"the program now asks {', '.join(unnamed)} and LABELS has no name for it - add one")
    dropped = [s for s in LABELS if s not in asked]
    if dropped:
        raise SystemExit(f"LABELS names {', '.join(dropped)}, which the program no longer asks - take it out")
    return asked


def drawn_by() -> str:
    """The digest of this script, with line endings as git stores them."""
    text = Path(__file__).read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(text).hexdigest()


def glow(picture: Image.Image) -> Image.Image:
    """A faint light from the top right, in the blue of the shield."""
    mask = Image.new("L", picture.size, 0)
    ImageDraw.Draw(mask).ellipse((760, -320, 1560, 300), fill=40)
    mask = mask.filter(ImageFilter.GaussianBlur(140))
    return Image.composite(Image.new("RGB", picture.size, SHIELD), picture, mask)


def shadow(picture: Image.Image, box: tuple[int, int, int, int]) -> Image.Image:
    mask = Image.new("L", picture.size, 0)
    left, top, right, bottom = box
    ImageDraw.Draw(mask).rounded_rectangle((left + 6, top + 18, right - 6, bottom + 24), radius=18, fill=150)
    mask = mask.filter(ImageFilter.GaussianBlur(26))
    return Image.composite(Image.new("RGB", picture.size, (0, 0, 0)), picture, mask)


def wrap(pen: ImageDraw.ImageDraw, text: str, face: ImageFont.FreeTypeFont, width: int) -> list[str]:
    lines, line = [], ""
    for word in text.split():
        candidate = f"{line} {word}".strip()
        if line and pen.textlength(candidate, font=face) > width:
            lines.append(line)
            line = word
        else:
            line = candidate
    return lines + [line]


def fitting(pen: ImageDraw.ImageDraw, lines: list[str], bold: bool, largest: int, width: int) -> ImageFont.FreeTypeFont:
    """The largest size at which every line fits the width."""
    for size in range(largest, 20, -1):
        face = inter(bold, size)
        if all(pen.textlength(line, font=face) <= width for line in lines):
            return face
    raise SystemExit(f"the headline does not fit {width} pixels at any readable size")


def mark(pen: ImageDraw.ImageDraw, status: str, centre: tuple[int, int], size: int) -> None:
    """A status as the window draws it: PASS a circle, FAIL an octagon."""
    x, y = centre
    r = size / 2
    if status == "PASS":
        pen.ellipse((x - r, y - r, x + r, y + r), fill=PASS)
        return
    k = r * 0.4142
    pen.polygon([(x - k, y - r), (x + k, y - r), (x + r, y - k), (x + r, y + k),
                 (x + k, y + r), (x - k, y + r), (x - r, y + k), (x - r, y - k)], fill=FAIL)


def pill(pen: ImageDraw.ImageDraw, left: int, middle: int, text: str, face: ImageFont.FreeTypeFont,
         ink: tuple[int, int, int], fill: tuple[int, int, int], edge: tuple[int, int, int]) -> int:
    """Draw a rounded label and answer where it ends."""
    width = int(pen.textlength(text, font=face)) + 28
    height = face.size + 16
    pen.rounded_rectangle((left, middle - height // 2, left + width, middle + height // 2),
                          radius=height // 2, fill=fill, outline=edge, width=1)
    pen.text((left + 14, middle), text, font=face, fill=ink, anchor="lm")
    return left + width


def draw_brand(picture: Image.Image, pen: ImageDraw.ImageDraw) -> None:
    icon = Image.open(ICON).convert("RGBA").resize((56, 56), Image.LANCZOS)
    picture.paste(icon, (MARGIN, MARGIN), icon)
    brand = inter(True, 32)
    title_end = MARGIN + 72 + int(pen.textlength(TITLE, font=brand))
    pen.text((MARGIN + 72, MARGIN + 28), TITLE, font=brand, fill=INK, anchor="lm")
    pill(pen, title_end + 18, MARGIN + 28, SURFACES, inter(True, 17), FOCUS, (0x22, 0x2B, 0x3B), (0x3D, 0x55, 0x7E))


def draw_chips(pen: ImageDraw.ImageDraw, asked: list[str], top: int) -> int:
    """One chip per store the program asks, wrapped. Answers the last row's bottom."""
    pen.text((MARGIN, top), STORES_LABEL, font=inter(False, 16), fill=INK_MUTED, anchor="ls")
    chip = inter(False, 18)
    x, middle = MARGIN, top + 32
    for store in asked:
        label = LABELS[store]
        if x > MARGIN and x + pen.textlength(label, font=chip) + 28 > MARGIN + LEFT_WIDTH:
            x, middle = MARGIN, middle + 44
        x = pill(pen, x, middle, label, chip, INK, SURFACE, EDGE) + 8
    return middle + (chip.size + 16) // 2


def draw_left(picture: Image.Image, pen: ImageDraw.ImageDraw, asked: list[str]) -> None:
    draw_brand(picture, pen)

    headline = fitting(pen, [line for line, _ in HEADLINE], True, 64, LEFT_WIDTH)
    y = MARGIN + 88
    for line, ink in HEADLINE:
        pen.text((MARGIN - 3, y), line, font=headline, fill=ink)
        y += int(headline.size * 1.12)

    lead = inter(False, 22)
    y += 18
    for line in wrap(pen, LEAD, lead, LEFT_WIDTH - 24):
        pen.text((MARGIN, y), line, font=lead, fill=INK_MUTED)
        y += 31

    chips_bottom = draw_chips(pen, asked, y + 36)

    foot_top = HEIGHT - MARGIN - 50
    if chips_bottom > foot_top - 14:
        raise SystemExit("the stores no longer fit above the foot - shorten a label in LABELS or the lead")
    pen.text((MARGIN, HEIGHT - MARGIN - 30), FOOT, font=inter(False, 18), fill=INK_MUTED, anchor="ls")
    pen.text((MARGIN, HEIGHT - MARGIN), PLATFORMS, font=inter(True, 18), fill=INK, anchor="ls")


def shortened(pen: ImageDraw.ImageDraw, path: str, face: ImageFont.FreeTypeFont, width: int) -> str:
    """A path cut from the left, with an ellipsis where the cut is."""
    if pen.textlength(path, font=face) <= width:
        return path
    parts = path.strip("/").split("/")
    for start in range(1, len(parts)):
        candidate = ELLIPSIS + "/" + "/".join(parts[start:])
        if pen.textlength(candidate, font=face) <= width:
            return candidate
    return ELLIPSIS + "/" + parts[-1]


# The panel's rhythm, top to bottom. Its top is level with the icon's.
PANEL_TOP = MARGIN
PANEL_HEAD = 46
LAYER_HEIGHT = 50
ROW_HEIGHT = 35
FIX_LINE = 22


def panel_box() -> tuple[int, int, int, int]:
    """Where the panel stands, from the number of lines it holds."""
    fix_top = PANEL_TOP + PANEL_HEAD + LAYER_HEIGHT + ROW_HEIGHT * len(ROWS) + 12
    return PANEL_LEFT, PANEL_TOP, PANEL_LEFT + PANEL_WIDTH, fix_top + FIX_LINE * len(FIX) + 24


def draw_panel(pen: ImageDraw.ImageDraw) -> None:
    """Draw the excerpt of the run."""
    left, top, right, bottom = panel_box()
    inner = right - left - 44
    code = mono(15)
    row_code = mono(16)
    words = inter(False, 16)
    rows_top = top + PANEL_HEAD
    head = PANEL_HEAD
    layer_height = LAYER_HEIGHT
    row_height = ROW_HEIGHT
    fix_top = rows_top + layer_height + row_height * len(ROWS) + 12

    pen.rounded_rectangle((left, top, right, bottom), radius=16, fill=SURFACE, outline=EDGE, width=1)
    pen.rounded_rectangle((left + 1, top + 1, right - 1, rows_top), radius=15, fill=RAISED)
    pen.rectangle((left + 1, rows_top - 16, right - 1, rows_top), fill=RAISED)
    pen.line((left + 1, rows_top, right - 1, rows_top), fill=EDGE, width=1)
    pen.text((left + 22, top + head // 2), "$", font=code, fill=FOCUS, anchor="lm")
    pen.text((left + 22 + int(pen.textlength("$ ", font=code)), top + head // 2), COMMAND,
             font=code, fill=INK, anchor="lm")

    status, name, summary = LAYER
    middle = rows_top + layer_height // 2 + 2
    mark(pen, status, (left + 30, middle), 16)
    pen.text((left + 48, middle), status, font=inter(True, 17), fill=FAIL, anchor="lm")
    pen.text((left + 104, middle), name, font=inter(True, 17), fill=INK, anchor="lm")
    pen.text((right - 22, middle), summary, font=inter(False, 15), fill=INK_MUTED, anchor="rm")

    family_width = int(pen.textlength("system-store ", font=row_code))
    for k, (status, family, instance, verdict) in enumerate(ROWS):
        middle = rows_top + layer_height + row_height * k + row_height // 2
        verdict_width = int(pen.textlength(verdict, font=words))
        room = inner - 30 - family_width - verdict_width - 18
        mark(pen, status, (left + 30, middle), 12)
        pen.text((left + 48, middle), family, font=row_code, fill=INK, anchor="lm")
        pen.text((left + 48 + family_width, middle), shortened(pen, instance, row_code, room),
                 font=row_code, fill=INK_MUTED, anchor="lm")
        pen.text((right - 22, middle), verdict, font=words, fill=PASS if status == "PASS" else FAIL, anchor="rm")

    pen.rounded_rectangle((left + 14, fix_top, right - 14, bottom - 14), radius=10, fill=SUNKEN)
    y = fix_top + 12
    for line in FIX:
        if pen.textlength(line, font=code) > inner - 8:
            raise SystemExit(f"the fix line {line!r} is wider than the panel")
        if line.startswith("run:"):
            pen.text((left + 26, y), "run:", font=code, fill=FOCUS)
            pen.text((left + 26 + int(pen.textlength("run: ", font=code)), y), line[5:], font=code, fill=INK)
        else:
            pen.text((left + 26, y), line, font=code, fill=INK)
        y += FIX_LINE


def draw(asked: list[str]) -> Image.Image:
    box = panel_box()
    picture = shadow(glow(Image.new("RGB", (WIDTH, HEIGHT), PAGE)), box)
    pen = ImageDraw.Draw(picture)
    draw_panel(pen)
    caption = box[3] + 34
    if caption > HEIGHT - MARGIN - 40:
        raise SystemExit("the panel no longer leaves room for its caption above the address")
    pen.text((PANEL_LEFT + 4, caption), CAPTION, font=inter(False, 16), fill=INK_MUTED, anchor="ls")
    pen.text((WIDTH - MARGIN, HEIGHT - MARGIN), ADDRESS, font=inter(True, 18), fill=FOCUS, anchor="rs")
    draw_left(picture, pen, asked)
    return picture


def main() -> None:
    asked = stores()
    picture = draw(asked)
    if picture.size != (WIDTH, HEIGHT):
        raise SystemExit(f"drew {picture.size}, the picture is {WIDTH}x{HEIGHT}")
    info = PngInfo()
    info.add_text(KEY_STORES, ",".join(asked))
    info.add_text(KEY_DRAWN_BY, drawn_by())
    picture.save(OUT, optimize=True, pnginfo=info)
    print(f"{OUT}: {WIDTH}x{HEIGHT}, {OUT.stat().st_size} bytes, stores {', '.join(asked)}")


if __name__ == "__main__":
    main()
