"""Record the built image sizes into results/, so docs can quote them rather than type them.

Docker reports two different sizes, and quoting one without saying which is how a number
becomes misleading:

* **content** - `docker image inspect .Size`: the compressed layers, roughly what a pull
  downloads;
* **disk** - `docker image ls`: the unpacked layers on disk.

Both are recorded, labelled.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
IMAGES = {"rules-only": "mcp-warden:local", "with-ml": "mcp-warden:ml"}


def content_bytes(tag: str) -> int | None:
    completed = subprocess.run(
        ["docker", "image", "inspect", tag, "--format", "{{.Size}}"],
        capture_output=True,
        text=True,
    )
    return int(completed.stdout.strip()) if completed.returncode == 0 else None


def disk_size(tag: str) -> str | None:
    """Docker's own human-readable disk usage; it does not expose a byte count for this."""
    repository, _, wanted = tag.partition(":")
    completed = subprocess.run(
        ["docker", "image", "ls", repository, "--format", "json"], capture_output=True, text=True
    )
    for line in completed.stdout.splitlines():
        row = json.loads(line)
        if row.get("Tag") == wanted:
            return str(row.get("Size"))
    return None


def main() -> int:
    images = {}
    for name, tag in IMAGES.items():
        content = content_bytes(tag)
        images[name] = {
            "tag": tag,
            "content_bytes": content,
            "content_mib": round(content / 2**20, 1) if content else None,
            "disk": disk_size(tag),
        }
    if not any(info["content_bytes"] for info in images.values()):
        print("no images found; build them first (make image, make image-ml)", file=sys.stderr)
        return 1
    payload = {"generated_at": datetime.now(UTC).isoformat(), "images": images}
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / f"images-{payload['generated_at'][:10]}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
