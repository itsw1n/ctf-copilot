#!/usr/bin/env bash
set -euo pipefail
root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
sudo apt update
grep -vE '^\s*(#|$)' "$root_dir/requirements-system.txt" | xargs -r sudo apt install -y
python3 -m pip install --user -r "$root_dir/requirements.txt"
