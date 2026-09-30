#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
python3 - "$repo_dir" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
playbook = root / "deploy" / "ansible" / "site.yml"
text = playbook.read_text(encoding="utf-8")

if 'src: "../../{{ item }}"' not in text:
    raise SystemExit("Ansible bundle source must resolve from deploy/ansible to the repository root")
if 'src: "../../../{{ item }}"' in text:
    raise SystemExit("Ansible bundle source escapes the repository root")

items = ["go.mod", "go.sum", "cmd", "internal", "config", "migrations", "deploy"]
source_dir = playbook.parent
missing = [item for item in items if not (source_dir / "../.." / item).resolve().exists()]
if missing:
    raise SystemExit(f"Ansible bundle source paths are missing: {', '.join(missing)}")

required = [
    root / "deploy" / "compose.yaml",
    root / "deploy" / "Dockerfile",
    root / "deploy" / "ansible" / "ansible.cfg",
    root / "deploy" / "ansible" / "inventory.example.ini",
    root / "deploy" / "ansible" / "templates" / "control.toml.j2",
    root / "deploy" / "ansible" / "templates" / "relay.toml.j2",
]
missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
if missing:
    raise SystemExit(f"deployment bundle files are missing: {', '.join(missing)}")

print("Ansible deployment bundle paths are valid")
PY
