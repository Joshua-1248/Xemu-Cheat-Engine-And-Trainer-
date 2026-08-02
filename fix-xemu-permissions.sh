#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# fix-xemu-permissions.sh
#
# One-shot repair for files already left behind as root:root by earlier sudo
# runs -- the ones the file manager draws with a padlock. Run once; the code
# changes stop new ones appearing.
#
#   ./fix-xemu-permissions.sh                 # fix the directory it lives in
#   ./fix-xemu-permissions.sh /path/to/tree   # fix somewhere else
#   ./fix-xemu-permissions.sh --ptrace        # also set up sudo-free operation
#
# Safe to re-run. Touches ownership and mode only; never deletes anything.
# ---------------------------------------------------------------------------
set -euo pipefail

SETUP_PTRACE=0
TARGET_DIR=""

for arg in "$@"; do
    case "$arg" in
        --ptrace) SETUP_PTRACE=1 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) TARGET_DIR="$arg" ;;
    esac
done

# Who should own the files. Under sudo the invoking user is in SUDO_USER;
# otherwise it is whoever is running this.
OWNER="${SUDO_USER:-$(id -un)}"
if [ "$OWNER" = "root" ]; then
    echo "Refusing to chown to root -- run this as your normal user," >&2
    echo "or via sudo so that SUDO_USER is set." >&2
    exit 1
fi
GROUP="$(id -gn "$OWNER")"

if [ -z "$TARGET_DIR" ]; then
    TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "Not a directory: $TARGET_DIR" >&2
    exit 1
fi

echo "Tree   : $TARGET_DIR"
echo "Owner  : $OWNER:$GROUP"

BAD=$(find "$TARGET_DIR" ! -user "$OWNER" -printf . 2>/dev/null | wc -c)
echo "Wrongly owned entries: $BAD"

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

if [ "$BAD" -gt 0 ]; then
    $SUDO chown -R "$OWNER:$GROUP" "$TARGET_DIR"
    echo "Ownership fixed."
else
    echo "Ownership already correct."
fi

# Directories need the execute bit to be traversable; regular files do not,
# and blanket 755 on a data tree marks every .bin and .ini as executable.
$SUDO find "$TARGET_DIR" -type d -exec chmod 775 {} +
$SUDO find "$TARGET_DIR" -type f ! -name '*.sh' ! -name '*.py' -exec chmod 664 {} +
$SUDO find "$TARGET_DIR" -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod 775 {} +
echo "Modes fixed (dirs 775, data 664, scripts 775)."

if [ "$SETUP_PTRACE" -eq 1 ]; then
    echo
    echo "Configuring sudo-free memory access..."
    CONF=/etc/sysctl.d/10-xemu-ptrace.conf
    echo 'kernel.yama.ptrace_scope = 0' | $SUDO tee "$CONF" >/dev/null
    $SUDO sysctl -w kernel.yama.ptrace_scope=0 >/dev/null
    echo "Wrote $CONF and applied it live."
    echo "You can now run both tools WITHOUT sudo, as long as xemu is also"
    echo "started as your normal user. Nothing will be root-owned again."
fi

echo "Done."
