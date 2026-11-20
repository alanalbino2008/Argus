"""Draw Argus's app icon (an eye on a dark rounded square) as PNG, Windows .ico and macOS .icns.

python packaging/desktop/make_icons.py build/icons
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw

SIZE = 1024
BACKGROUND, ACCENT, PUPIL = (15, 23, 42, 255), (56, 189, 248, 255), (15, 23, 42, 255)


def draw(size: int = SIZE) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / SIZE
    d.rounded_rectangle((40 * s, 40 * s, 984 * s, 984 * s), radius=220 * s, fill=BACKGROUND)
    # the eye: where two large circles overlap (an almond shape), then an iris and a pupil
    upper, lower = Image.new("L", img.size, 0), Image.new("L", img.size, 0)
    ImageDraw.Draw(upper).ellipse((22 * s, 14 * s, 1002 * s, 994 * s), fill=255)
    ImageDraw.Draw(lower).ellipse((22 * s, 30 * s, 1002 * s, 1010 * s), fill=255)
    lens = ImageChops.multiply(upper.transform(img.size, Image.Transform.AFFINE, (1, 0, 0, 0, 1, 270 * s)),
                               lower.transform(img.size, Image.Transform.AFFINE, (1, 0, 0, 0, 1, -270 * s)))  # fmt: skip
    img.paste(Image.new("RGBA", img.size, ACCENT), (0, 0), lens)
    d.ellipse((322 * s, 322 * s, 702 * s, 702 * s), fill=BACKGROUND)
    d.ellipse((372 * s, 372 * s, 652 * s, 652 * s), fill=ACCENT)
    d.ellipse((447 * s, 447 * s, 577 * s, 577 * s), fill=PUPIL)
    return img


def main(out: str) -> None:
    folder = Path(out)
    folder.mkdir(parents=True, exist_ok=True)
    icon = draw()
    icon.save(folder / "argus.png")
    icon.save(folder / "argus.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    icon.save(folder / "argus.icns")
    print(f"Icons written to {folder}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "build/icons")
