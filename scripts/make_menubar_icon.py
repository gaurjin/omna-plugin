"""Draw the menu-bar logo from the website's own logo (#45, owner 2026-11-22).

    python scripts/make_menubar_icon.py [path/to/favicon.svg]

Reads the O's outline and its colour gradient from omna-website's
public/favicon.svg and writes src/omna_plugin/assets/menubar-icon.png: the same
O, same colours, on a clear background, 44x44 (a 22 pt menu bar at 2x), drawn
16 times larger and shrunk so the edges are smooth. Needs only Pillow.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SVG = ROOT.parent / "omna-website" / "public" / "favicon.svg"  # works from the main checkout
OUT = ROOT / "src" / "omna_plugin" / "assets" / "menubar-icon.png"
SIZE, SUPER, HEIGHT = 44, 16, 0.72   # the O fills 72% of the height, like other menu-bar icons


def outlines(d: str) -> list[list[tuple[float, float]]]:
    """The path's M/L/Q commands (all the favicon uses) as point lists."""
    tok = re.findall(r"[MLQ]|-?\d+(?:\.\d+)?", d)
    shapes, pos, i = [], (0.0, 0.0), 0
    num = lambda k: (float(tok[k]), float(tok[k + 1]))  # noqa: E731
    while i < len(tok):
        cmd = tok[i]
        if cmd == "M":
            pos = num(i + 1)
            shapes.append([pos])
            i += 3
        elif cmd == "L":
            pos = num(i + 1)
            shapes[-1].append(pos)
            i += 3
        elif cmd == "Q":
            c, end = num(i + 1), num(i + 3)
            for k in range(1, 33):
                t = k / 32
                shapes[-1].append(tuple((1 - t) ** 2 * pos[j] + 2 * (1 - t) * t * c[j] + t * t * end[j] for j in (0, 1)))
            pos = end
            i += 5
        else:
            raise ValueError(f"unexpected path command {cmd!r}")
    return shapes


def gradient(svg: str):
    """colour_at(x, y) in the SVG's own units, from its linearGradient."""
    g = re.search(r"<linearGradient[^>]*>", svg).group(0)
    x1, y1, x2, y2 = (float(re.search(rf'{a}="(-?[\d.]+)"', g).group(1)) for a in ("x1", "y1", "x2", "y2"))
    stops = [(float(o) / 100, tuple(int(h[k:k + 2], 16) for k in (0, 2, 4)))
             for o, h in re.findall(r'offset="([\d.]+)%" stop-color="#([0-9A-Fa-f]{6})"', svg)]
    dx, dy = x2 - x1, y2 - y1

    def colour_at(x: float, y: float) -> tuple[int, int, int]:
        t = min(1.0, max(0.0, ((x - x1) * dx + (y - y1) * dy) / (dx * dx + dy * dy)))
        for (o0, c0), (o1, c1) in zip(stops, stops[1:]):
            if t <= o1:
                f = (t - o0) / (o1 - o0) if o1 > o0 else 0.0
                return tuple(round(c0[j] + (c1[j] - c0[j]) * f) for j in range(3))
        return stops[-1][1]

    return colour_at


def render(svg: str) -> Image.Image:
    shapes = outlines(re.search(r'<path d="([^"]+)"', svg).group(1))
    xs = [x for s in shapes for x, _ in s]
    ys = [y for s in shapes for _, y in s]
    big = SIZE * SUPER
    scale = big * HEIGHT / (max(ys) - min(ys))
    ox = (big - (max(xs) - min(xs)) * scale) / 2 - min(xs) * scale
    oy = (big - (max(ys) - min(ys)) * scale) / 2 - min(ys) * scale
    mask = Image.new("L", (big, big), 0)
    draw = ImageDraw.Draw(mask)
    draw.polygon([(x * scale + ox, y * scale + oy) for x, y in shapes[0]], fill=255)   # outside of the O
    for hole in shapes[1:]:
        draw.polygon([(x * scale + ox, y * scale + oy) for x, y in hole], fill=0)    # its middle
    colour_at = gradient(svg)
    img = Image.new("RGBA", (SIZE, SIZE))
    for py in range(SIZE):     # colour each final pixel at its centre, in SVG units
        for px in range(SIZE):
            sx = ((px + 0.5) * SUPER - ox) / scale
            sy = ((py + 0.5) * SUPER - oy) / scale
            img.putpixel((px, py), colour_at(sx, sy) + (0,))
    img.putalpha(mask.resize((SIZE, SIZE), Image.LANCZOS))
    return img


if __name__ == "__main__":
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else SVG
    render(src.read_text()).save(OUT, optimize=True)
    print(f"wrote {OUT} from {src}")
