"""Draw the picture a link to the certdoctor website shows when it is shared.

    python assets/social-preview/social_preview.py    social-preview.png beside this file

A link preview on a chat, a forum or a social site is 1200 by 630 pixels. This
draws one from the program's own parts rather than from artwork: the icon that
assets/icon/appicon.py draws, the Inter typeface the window ships
(internal/gui/fonts, under the SIL Open Font License), and the window's colours
(internal/gui/look/palette.go). Pillow draws it and is a build tool here, as it
is for the icon. The website reads the picture through a mount in
web/hugo.toml, so there is one copy of it.

The words are the program's own claim and the messages it is for, so the
picture says nothing the program does not do.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ICON = ROOT / "assets" / "icon" / "certdoctor.png"
FONTS = ROOT / "internal" / "gui" / "fonts"
OUT = HERE / "social-preview.png"

WIDTH, HEIGHT = 1200, 630
MARGIN = 72

# internal/gui/look/palette.go
PAGE = (0x16, 0x18, 0x1C)
SURFACE = (0x1E, 0x21, 0x26)
EDGE = (0x2C, 0x31, 0x38)
INK = (0xE6, 0xE8, 0xEA)
INK_MUTED = (0xA0, 0xA6, 0xAD)
ACCENT = (0x8A, 0xB4, 0xF8)
FAIL = (0xFF, 0x8D, 0x8D)

TITLE = "certdoctor"
CLAIM = ["Why this machine cannot connect", "to that URL, and what to run to fix it"]
MESSAGES = [
    ("PKIX path building failed", "Java"),
    ("unable to get local issuer certificate", "curl, git, Python"),
    ("SELF_SIGNED_CERT_IN_CHAIN", "Node.js"),
    ("x509: certificate signed by unknown authority", "Go"),
]
FOOT = "Every trust store on the machine, one command each. Free and open source."


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / name), size)


def draw() -> Image.Image:
    picture = Image.new("RGB", (WIDTH, HEIGHT), PAGE)
    pen = ImageDraw.Draw(picture)

    icon = Image.open(ICON).convert("RGBA").resize((112, 112), Image.LANCZOS)
    picture.paste(icon, (MARGIN, MARGIN), icon)
    pen.text((MARGIN + 136, MARGIN + 18), TITLE, font=font("Inter-Bold.ttf", 64), fill=INK)

    claim_font = font("Inter-Bold.ttf", 40)
    y = MARGIN + 150
    for line in CLAIM:
        pen.text((MARGIN, y), line, font=claim_font, fill=INK)
        y += 52

    box_top = y + 28
    row_height = 46
    box = (MARGIN, box_top, WIDTH - MARGIN, box_top + row_height * len(MESSAGES) + 16)
    pen.rounded_rectangle(box, radius=14, fill=SURFACE, outline=EDGE, width=2)
    message_font = font("Inter-Regular.ttf", 24)
    from_font = font("Inter-Regular.ttf", 20)
    for k, (message, source) in enumerate(MESSAGES):
        row_y = box_top + 14 + k * row_height
        pen.text((MARGIN + 24, row_y), message, font=message_font, fill=FAIL)
        right = WIDTH - MARGIN - 24 - pen.textlength(source, font=from_font)
        pen.text((right, row_y + 3), source, font=from_font, fill=INK_MUTED)

    pen.text((MARGIN, HEIGHT - MARGIN + 6), FOOT, font=font("Inter-Regular.ttf", 22), fill=ACCENT)
    return picture


def main() -> None:
    picture = draw()
    if picture.size != (WIDTH, HEIGHT):
        raise SystemExit(f"drew {picture.size}, a link preview is {WIDTH}x{HEIGHT}")
    picture.save(OUT, optimize=True)
    print(f"{OUT}: {picture.size[0]}x{picture.size[1]}")


if __name__ == "__main__":
    main()
