"""Write the operator's settings that ship inside the installer (argus-desktop.json).

Reads ARGUS_ACCOUNT_SERVER_URL and ARGUS_LICENCE_PUBLIC_KEY from the environment (in GitHub:
repository variables). Both are public values: the address of your account service, and the key
Argus Personal uses to check licences. Never put secrets here: anyone can read an installer.

    python packaging/desktop/write_config.py build/argus-desktop.json
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

SHIPPED = ("ARGUS_ACCOUNT_SERVER_URL", "ARGUS_LICENCE_PUBLIC_KEY")


def build() -> dict[str, dict[str, str]]:
    env = {name: os.environ.get(name, "").strip() for name in SHIPPED}
    url = env["ARGUS_ACCOUNT_SERVER_URL"]
    if url and not re.match(r"^https://[A-Za-z0-9.\-]+(:\d+)?(/\S*)?$", url):
        raise SystemExit("ARGUS_ACCOUNT_SERVER_URL must be an https:// address")
    if any(word in name for name in os.environ if name.startswith("ARGUS_") for word in ("SECRET", "SIGNING")):
        print("Note: secret ARGUS_ settings in this environment are never written into the installer")
    return {"env": {k: v for k, v in env.items() if v}}


def main(out: str) -> None:
    config = build()
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    missing = [n for n in SHIPPED if n not in config["env"]]
    print(
        f"Wrote {path}"
        + (f" (not set: {', '.join(missing)}; investigators will see 'not configured')" if missing else "")
    )


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "build/argus-desktop.json")
