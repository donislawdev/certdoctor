"""Draw the certdoctor icon - a gold bean on a blue shield - from shapes.

    python assets/icon/appicon.py                  certdoctor.png, .ico and .icns beside this file
    python assets/icon/appicon.py --sheet out.png  every size on a light and a dark background

WHY A SCRIPT AND NOT A DRAWING. Made of shapes, the icon carries no artwork
anybody else made, so there is no copyright to inherit and nothing to attribute
in THIRD-PARTY-NOTICES.md. Pillow and numpy draw it and are build tools here -
neither is linked into anything we ship, and the pictures they write are ours.
Drawn with Pillow 12.3.0 (MIT-CMU) and numpy 2.5.3 (BSD-3-Clause, with the
permissive licences of the parts it bundles), both read from their installed
metadata on 2026-10-27.

WHAT USES WHICH FILE. certdoctor.ico becomes the Windows resource linked into
the executable - go-winres turns it into cmd/certdoctor/rsrc_windows_*.syso,
and CI makes those again and compares the bytes. certdoctor.icns goes into the
macOS .app bundle the release wraps the binary in. certdoctor.png is the
picture for everything else - a README, a site, a future window. A Linux
binary carries no icon at all.

    go run github.com/tc-hib/go-winres@v0.3.3 simply --icon assets/icon/certdoctor.ico \
        --manifest none --arch amd64,arm64 --out cmd/certdoctor/rsrc

WHY THIS PICTURE. The owner's other programs are legumes - a green bean, a dark
green bean, a red bean, a pea pod and chickpeas - and certdoctor joins them
without looking like any of them. A red bean was tried first and was too close
to one of them, a white bean looked wrong, so the bean went gold and onto a
shield. The shield is the one silhouette in that family that is not a legume,
and it says what the program is about: trust, certificates, TLS. Blue is a
colour none of the others use.

WHAT AN ICON HAS TO SURVIVE, read in Apple's Human Interface Guidelines (App
icons, read 2026-10-27) rather than remembered: few shapes, no thin lines and
no sharp corners, because both lose detail at small sizes. So below 48 px the
rim and the bean's hilum are left out rather than shrunk into noise, and the
bean grows to fill the space the rim gave back.

EVERY SIZE IS DRAWN, NOT SCALED FROM ONE PICTURE. The .ico and .icns writers
below are written by hand for that reason. Pillow's writers resample one image
into every size, and a 16 px icon reduced from a detailed one is a smudge.
"""

import argparse
import io
import math
import pathlib
import struct

import numpy as np
from PIL import Image, ImageDraw

HERE = pathlib.Path(__file__).resolve().parent

# Drawn at this size and reduced, never drawn at the size it ships at. Twice
# the largest shipped size, so even the 1024 px one is supersampled.
MASTER = 2048

# Below this the rim and the hilum are dropped - see the module comment.
DETAIL_FROM = 48


def colour(*rgb):
    return np.array(rgb, dtype=np.float32) / 255


SHIELD_EDGE = colour(16, 40, 96)
SHIELD_RIM_TOP = colour(122, 176, 248)
SHIELD_RIM_BOTTOM = colour(70, 128, 214)
SHIELD_TOP = colour(64, 130, 230)
SHIELD_BOTTOM = colour(26, 78, 172)
BEAN_EDGE = colour(110, 64, 6)
BEAN_TOP = colour(255, 216, 96)
BEAN_BOTTOM = colour(230, 150, 26)
HILUM = colour(252, 240, 214)
WHITE = colour(255, 255, 255)


# --------------------------------------------------------------------------- #
# geometry, in fractions of the canvas
# --------------------------------------------------------------------------- #

def turn(points, degrees, centre):
    a = math.radians(degrees)
    c, s = math.cos(a), math.sin(a)
    ox, oy = centre
    return [(ox + (x - ox) * c - (y - oy) * s, oy + (x - ox) * s + (y - oy) * c) for x, y in points]


def ellipse(cx, cy, rx, ry, n=720):
    return [(cx + rx * math.cos(2 * math.pi * i / n), cy + ry * math.sin(2 * math.pi * i / n))
            for i in range(n)]


def cubic(p0, p1, p2, p3, n=240):
    out = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        out.append((u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
                    u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1]))
    return out


# A kidney bean: an ellipse whose lower side is pushed in by a smooth bump. A
# circle bitten out of an ellipse was tried first and left two corners where
# the circle met the outline - a real bean has none.
BEAN_ANGLE = -20.0
BEAN_CENTRE = (0.5, 0.5)
BEAN_RX, BEAN_RY = 0.42, 0.235
DENT_DEPTH = 0.08
DENT_HALF = 0.30


def bean_outline(n=1440):
    cx, cy = BEAN_CENTRE
    pts = []
    for i in range(n):
        t = 2 * math.pi * i / n
        x = BEAN_RX * math.cos(t)
        y = BEAN_RY * math.sin(t)
        if y > 0 and abs(x) < DENT_HALF:
            u = x / DENT_HALF
            y -= DENT_DEPTH * (1 - u * u) ** 2
        pts.append((cx + x, cy + y))
    return turn(pts, BEAN_ANGLE, BEAN_CENTRE)


def hilum_outline():
    """The pale scar in the hollow of the bean - what tells a bean from a pebble."""
    cx, cy = BEAN_CENTRE
    return turn(ellipse(cx, cy + BEAN_RY - DENT_DEPTH - 0.04, 0.06, 0.02), BEAN_ANGLE, BEAN_CENTRE)


def shield_outline(scale=1.0):
    """Shoulders, a slight crest in the middle of the top, and sides that run
    to the point in one convex curve each. The first shield had straight sides
    with a point added under them and read as a badge."""
    left, right, top, crest, tip = 0.15, 0.85, 0.15, 0.115, 0.935
    pts = []
    pts += cubic((left, top), (0.30, top + 0.005), (0.40, crest), (0.5, crest))
    pts += cubic((0.5, crest), (0.60, crest), (0.70, top + 0.005), (right, top))
    pts += cubic((right, top), (right + 0.01, 0.52), (0.74, 0.80), (0.5, tip))
    pts += cubic((0.5, tip), (0.26, 0.80), (left - 0.01, 0.52), (left, top))
    cx, cy = 0.5, 0.53
    return [(cx + (x - cx) * scale, cy + (y - cy) * scale) for x, y in pts]


# The field is the shield inset by this much, and what lies between is the rim.
FIELD_SCALE = 0.86

# --------------------------------------------------------------------------- #
# raster helpers, all on float masks in 0..1
# --------------------------------------------------------------------------- #

def mask_of(size, polygons):
    img = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(img)
    for poly in polygons:
        draw.polygon([(x * size, y * size) for x, y in poly], fill=255)
    return np.asarray(img, dtype=np.float32) / 255


def _box(img, r, axis):
    pad = [(r + 1, r) if i == axis else (0, 0) for i in range(2)]
    c = np.cumsum(np.pad(img, pad, mode="edge"), axis=axis)
    if axis == 0:
        return (c[2 * r + 1:] - c[:-2 * r - 1]) / (2 * r + 1)
    return (c[:, 2 * r + 1:] - c[:, :-2 * r - 1]) / (2 * r + 1)


def blur(img, sigma):
    """Three box blurs, which is a Gaussian to within what an eye can see."""
    r = max(1, int(sigma * 1.2))
    for _ in range(3):
        img = _box(_box(img, r, 0), r, 1)
    return img


def grow(mask, width):
    """The mask dilated by about width pixels, corners rounded on the way.

    A Gaussian of sigma s falls to 2 percent about 2.05 s outside an edge, so a
    threshold there moves the edge out by that much."""
    return (blur(mask, width / 2.05) > 0.02).astype(np.float32)


def rounded(mask, radius):
    return (blur(mask, radius) > 0.5).astype(np.float32)


def lit(size, top, bottom):
    """A fill lit from the upper left - lighter there, darker towards the point."""
    y, x = np.mgrid[0:size, 0:size].astype(np.float32) / size
    u = np.clip(x * 0.4 + y * 0.9 - 0.15, 0, 1)[..., None]
    return top * (1 - u) + bottom * u


def over(dst, rgb, alpha):
    """Composite a flat or per pixel colour over dst, straight alpha."""
    alpha = alpha[..., None]
    out_a = alpha + dst[..., 3:] * (1 - alpha)
    out_rgb = (rgb * alpha + dst[..., :3] * dst[..., 3:] * (1 - alpha)) / np.maximum(out_a, 1e-6)
    return np.concatenate([out_rgb, out_a], axis=-1)


def sheen(size, inside, cx, cy, rx, ry, degrees, strength):
    """Soft white light. Only its ALPHA is blurred - blurring a white layer
    together with the transparent black around it turns the light grey."""
    light = blur(mask_of(size, [turn(ellipse(cx, cy, rx, ry), degrees, (cx, cy))]), size * 0.03)
    return np.clip(light, 0, 1) * inside * strength


# --------------------------------------------------------------------------- #
# the picture
# --------------------------------------------------------------------------- #

# How far the bean's outline stays from the field's edge, as a fraction of the
# canvas, and where its middle sits - in the upper, wider part of the shield.
BEAN_MARGIN = 0.035
BEAN_MIDDLE_Y = 0.47


def bean_masks(size, fraction, detail):
    """The bean and its outline, placed on a canvas of size."""
    sub = int(size * fraction)
    ox, oy = (size - sub) // 2, int(size * BEAN_MIDDLE_Y) - sub // 2
    body = mask_of(sub, [bean_outline()])
    edge = grow(body, sub * (0.05 if detail else 0.09))
    placed = np.zeros((2, size, size), dtype=np.float32)
    placed[0, oy:oy + sub, ox:ox + sub] = body
    placed[1, oy:oy + sub, ox:ox + sub] = edge
    return placed[0], placed[1], (ox / size, oy / size)


def field_mask(size, detail):
    return rounded(mask_of(size, [shield_outline(FIELD_SCALE if detail else 1.0)]), size * 0.01)


def bean_fraction(detail, probe=512):
    """The largest bean, as a fraction of the canvas, that fits the field.

    FOUND rather than chosen. The bean was placed by eye once and its ends
    reached over the rim, which the owner saw at once and no number in this
    file would have said."""
    safe = 1 - grow(1 - field_mask(probe, detail), probe * BEAN_MARGIN)
    for step in range(60, 20, -1):
        fraction = step / 100
        _, edge, _ = bean_masks(probe, fraction, detail)
        if (edge * (1 - safe)).sum() == 0:
            return fraction
    raise SystemExit("appicon: no bean size fits inside the shield")


def draw(size, detail):
    img = np.zeros((size, size, 4), dtype=np.float32)
    body = rounded(mask_of(size, [shield_outline()]), size * 0.012)
    img = over(img, SHIELD_EDGE, grow(body, size * (0.026 if detail else 0.05)))
    img = over(img, lit(size, SHIELD_RIM_TOP, SHIELD_RIM_BOTTOM), body)

    # The field, its right half a shade darker so the shield has a ridge.
    field = field_mask(size, detail)
    x = np.arange(size, dtype=np.float32)[None, :] / size
    right = np.clip((x - 0.5) * size / 2.0, 0, 1)
    fill = lit(size, SHIELD_TOP, SHIELD_BOTTOM) * (1 - 0.16 * right[..., None])
    img = over(img, fill, field)
    img = over(img, WHITE, sheen(size, field * (1 - right), 0.36, 0.30, 0.13, 0.08, -15, 0.30))

    fraction = bean_fraction(detail)
    bean, edge, (ox, oy) = bean_masks(size, fraction, detail)
    spill = edge * (1 - field)
    if spill.sum() > 0:
        raise SystemExit("appicon: the bean reaches past the shield at %d px" % size)
    img = over(img, BEAN_EDGE, edge)
    img = over(img, lit(size, BEAN_TOP, BEAN_BOTTOM), bean)
    gx = ox + (BEAN_CENTRE[0] - 0.17) * fraction
    gy = oy + (BEAN_CENTRE[1] - 0.085) * fraction
    img = over(img, WHITE, sheen(size, bean, gx, gy, 0.075, 0.032, -20, 0.5))
    if detail:
        sub = int(size * fraction)
        hilum = np.zeros((size, size), dtype=np.float32)
        px, py = int(ox * size), int(oy * size)
        hilum[py:py + sub, px:px + sub] = mask_of(sub, [hilum_outline()])
        img = over(img, HILUM, hilum)
    return Image.fromarray((np.clip(img, 0, 1) * 255 + 0.5).astype(np.uint8), "RGBA")


_MASTERS = {}


def render(size):
    detail = size >= DETAIL_FROM
    if detail not in _MASTERS:
        _MASTERS[detail] = draw(MASTER, detail)
    return _MASTERS[detail].resize((size, size), Image.LANCZOS)


def png_bytes(image):
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


# --------------------------------------------------------------------------- #
# the files
# --------------------------------------------------------------------------- #

# The sizes Windows asks an .ico for: 16, 20, 24, 32, 40 and 48 at 100 to 300
# percent scaling in Explorer and the taskbar, 64 and 256 for the large views.
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 256)


def ico(path):
    """A Windows icon, one PNG per size, each drawn at that size.

    The layout is ICONDIR (reserved 0, type 1, count) and one 16 byte entry per
    image: width and height (0 means 256), colour count, reserved, planes,
    bits per pixel, payload length, payload offset. A PNG payload is accepted
    by Windows for every size since Vista."""
    payloads = [png_bytes(render(size)) for size in ICO_SIZES]
    offset = 6 + 16 * len(payloads)
    head = struct.pack("<HHH", 0, 1, len(payloads))
    entries = b""
    for size, payload in zip(ICO_SIZES, payloads):
        side = 0 if size == 256 else size
        entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(payload), offset)
        offset += len(payload)
    path.write_bytes(head + entries + b"".join(payloads))


# What a .icns holds and the name macOS reads each size under, as iconutil
# writes them. A pixel size appears twice when it answers two questions - 32 px
# is the 32 point icon and the 16 point one on a Retina screen.
ICNS_TYPES = (
    (b"icp4", 16), (b"ic11", 32), (b"icp5", 32), (b"ic12", 64), (b"ic07", 128),
    (b"ic13", 256), (b"ic08", 256), (b"ic14", 512), (b"ic09", 512), (b"ic10", 1024),
)


# The tile macOS gets and no other system does. MEASURED on macOS 27.0.1 on
# 2026-10-27, by asking NSWorkspace for the icon of a bundle carrying each
# candidate: the bare shield on a transparent canvas is put on a GREY tile of
# the system's own, a full opaque square is clipped to the system's rounded
# shape, and this - a rounded tile 824 px wide on a 1024 px canvas, the grid
# macOS used from Big Sur on - is shown exactly like the full square. So this
# one is right on macOS 27 and is already the right shape on the releases
# before it, which do not clip anything themselves.
MAC_TILE_TOP = colour(246, 249, 253)
MAC_TILE_BOTTOM = colour(216, 226, 240)
MAC_BODY = 824 / 1024
MAC_SHIELD = 0.80


def mac_tile(size):
    body = size * MAC_BODY
    margin = (size - body) / 2
    shape = Image.new("L", (size, size), 0)
    ImageDraw.Draw(shape).rounded_rectangle(
        [margin, margin, margin + body - 1, margin + body - 1], radius=body * 0.225, fill=255)
    u = np.linspace(0, 1, size, dtype=np.float32)[:, None, None]
    rgb = np.broadcast_to(MAC_TILE_TOP * (1 - u) + MAC_TILE_BOTTOM * u, (size, size, 3))
    alpha = np.asarray(shape, dtype=np.float32)[..., None] / 255
    tile = Image.fromarray((np.concatenate([rgb, alpha], axis=-1) * 255 + 0.5).astype(np.uint8), "RGBA")
    inner = max(1, int(body * MAC_SHIELD))
    offset = (size - inner) // 2
    tile.alpha_composite(render(inner), (offset, offset))
    return tile


def icns(path):
    """A macOS icon: "icns", the total length, then chunks of a four letter
    type, a length that INCLUDES the chunk's own eight byte header, and a PNG.
    No table of contents chunk - it is optional and a summary of the file kept
    inside the file is a second copy of the truth. Apple's iconutil was asked
    on macOS 27.0.1 and read every size back out of a file written this way."""
    cache = {}
    chunks = b""
    for kind, size in ICNS_TYPES:
        if size not in cache:
            cache[size] = png_bytes(mac_tile(size))
        chunks += kind + struct.pack(">I", len(cache[size]) + 8) + cache[size]
    path.write_bytes(b"icns" + struct.pack(">I", len(chunks) + 8) + chunks)


def sheet(path):
    """Every size a person meets, on a light and a dark background."""
    shown = (256, 128, 64, 48, 32, 24, 16)
    pad, gap = 32, 24
    width = pad * 2 + sum(shown) + gap * (len(shown) - 1)
    height = (256 + pad * 2) * 2
    out = Image.new("RGB", (width, height), (245, 245, 245))
    ImageDraw.Draw(out).rectangle([0, height // 2, width, height], fill=(25, 25, 25))
    for row in range(2):
        x = pad
        y = row * (height // 2) + pad
        for size in shown:
            art = render(size)
            out.paste(art, (x, y + 256 - size), art)
            x += size + gap
    out.save(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sheet", help="write one picture with every size instead of the icon files")
    args = ap.parse_args()
    if args.sheet:
        sheet(pathlib.Path(args.sheet))
        print("wrote", args.sheet)
        return
    render(1024).save(HERE / "certdoctor.png", optimize=True)
    ico(HERE / "certdoctor.ico")
    icns(HERE / "certdoctor.icns")
    for name in ("certdoctor.png", "certdoctor.ico", "certdoctor.icns"):
        print("wrote", HERE / name, (HERE / name).stat().st_size, "bytes")


if __name__ == "__main__":
    main()
