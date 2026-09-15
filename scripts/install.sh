#!/usr/bin/env bash
set -euo pipefail

# Installs the required Python and Kali dependencies. It only asks for sudo
# when one or more required Kali packages are absent.
root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
venv_dir="$root_dir/.venv"

usage() {
  cat <<'EOF'
Usage: ./scripts/install.sh

Installs CTF Copilot into this repository's .venv directory. This default
action does not modify system Python. It checks every package listed in
requirements-system.txt and uses sudo apt only when required packages are
missing.
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. Install it first, then run this script again." >&2
  exit 1
fi

if [ ! -x "$venv_dir/bin/python" ]; then
  python3 -m venv "$venv_dir"
fi

"$venv_dir/bin/python" -m pip install --upgrade pip
"$venv_dir/bin/python" -m pip install -r "$root_dir/requirements.txt"
"$venv_dir/bin/python" -m pip install -e "$root_dir"

echo
echo "CTF Copilot is ready in: $venv_dir"
echo "Run it without sudo:"
echo "  $venv_dir/bin/ctf --help"
echo "Or activate this environment for the current terminal:"
echo "  source $venv_dir/bin/activate"

if ! command -v dpkg-query >/dev/null 2>&1 || ! command -v apt >/dev/null 2>&1; then
  echo
  echo "This installer requires a Debian/Kali system for required helper packages."
  echo "The local Python CLI is installed, but use Kali/WSL to install the full toolset."
  exit 1
fi

mapfile -t packages < <(grep -vE '^\s*(#|$)' "$root_dir/requirements-system.txt")
missing=()
for package in "${packages[@]}"; do
  if ! dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii '; then
    missing+=("$package")
  fi
done

echo
if ((${#missing[@]} == 0)); then
  echo "All required Kali packages are already installed. No sudo was needed."
else
  echo "Missing required Kali packages:"
  printf '  %s\n' "${missing[@]}"
  echo "Installing only these packages with Kali's apt repository..."
  sudo apt update
  sudo apt install -y "${missing[@]}"
fi

echo
echo "Checking available command-line helpers:"
"$venv_dir/bin/ctf" tools --doctor
