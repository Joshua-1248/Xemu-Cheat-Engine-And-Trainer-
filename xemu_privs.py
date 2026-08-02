"""Privilege probing and file-ownership reclamation.

Two jobs:

1.  Decide whether this process can actually read another process's memory,
    instead of assuming that means "am I root". On Linux the real requirement
    for opening /proc/<pid>/mem on a process you did not fork is
    PTRACE_MODE_ATTACH permission. Root satisfies it, but so does a same-UID
    process when the Yama LSM is set to the classic policy
    (kernel.yama.ptrace_scope = 0), and so does CAP_SYS_PTRACE. Checking the
    actual permission instead of the UID means the tools can run unelevated on
    a machine configured for it, which is the only way to stop producing
    root-owned files in the first place.

2.  When the tools *are* run under sudo, hand every file they create back to
    the invoking user. A file written by a root process lands as root:root
    0644, which the desktop file manager draws with a padlock and which the
    user cannot overwrite on the next run. reclaim() chowns it back.

Nothing here raises. Ownership fixes are best-effort by design: failing to
chown a dump is not a reason to lose the dump.
"""

import os
import platform
import sys

__all__ = [
    "IS_LINUX", "elevated", "invoking_user", "reclaim", "reclaim_tree",
    "install_umask", "ptrace_scope", "have_cap_sys_ptrace",
    "can_attach_to_foreign_process", "require_memory_access",
]

IS_LINUX = platform.system() == "Linux"

FILE_MODE = 0o664
DIR_MODE = 0o775

_CAP_SYS_PTRACE = 19


# ---------------------------------------------------------------------------
# Who is really running this
# ---------------------------------------------------------------------------
def elevated():
    """True when the process holds administrative rights."""
    if IS_LINUX:
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:                                          # noqa: BLE001
        return False


def invoking_user():
    """
    (uid, gid) of the human who launched this, or None.

    sudo and pkexec both export the original ids. If neither is present we are
    either not elevated at all, or we were started from a root shell -- in the
    latter case the owner of this source tree is the best available guess and
    is almost always right, since the tools live in the user's own directory.
    """
    if not IS_LINUX:
        return None

    for uid_var, gid_var in (("SUDO_UID", "SUDO_GID"), ("PKEXEC_UID", None)):
        raw_uid = os.environ.get(uid_var)
        if not raw_uid:
            continue
        try:
            uid = int(raw_uid)
        except ValueError:
            continue
        gid = None
        if gid_var and os.environ.get(gid_var):
            try:
                gid = int(os.environ[gid_var])
            except ValueError:
                gid = None
        if gid is None:
            try:
                import pwd
                gid = pwd.getpwuid(uid).pw_gid
            except Exception:                                  # noqa: BLE001
                gid = uid
        return uid, gid

    name = os.environ.get("SUDO_USER") or os.environ.get("LOGNAME")
    if name and name != "root":
        try:
            import pwd
            rec = pwd.getpwnam(name)
            return rec.pw_uid, rec.pw_gid
        except Exception:                                      # noqa: BLE001
            pass

    if elevated():
        try:
            st = os.stat(os.path.dirname(os.path.abspath(__file__)))
            if st.st_uid != 0:
                return st.st_uid, st.st_gid
        except OSError:
            pass

    return None


_TARGET = invoking_user() if IS_LINUX else None


# ---------------------------------------------------------------------------
# Handing files back
# ---------------------------------------------------------------------------
def _should_reclaim():
    return IS_LINUX and elevated() and _TARGET is not None


def reclaim(*paths, mode=FILE_MODE):
    """
    Give one or more freshly written paths back to the invoking user.

    A no-op when not running elevated, so call sites can invoke it
    unconditionally. Directories get the directory mode automatically.
    """
    if not _should_reclaim():
        return
    uid, gid = _TARGET
    for path in paths:
        if not path:
            continue
        try:
            os.chown(path, uid, gid)
        except OSError:
            continue
        try:
            os.chmod(path, DIR_MODE if os.path.isdir(path) else mode)
        except OSError:
            pass


def reclaim_tree(path, stop_at=None):
    """
    Reclaim a path and every parent directory up to stop_at.

    os.makedirs() under sudo creates the whole missing chain as root, so
    reclaiming only the leaf file leaves an unwritable directory above it.
    """
    if not _should_reclaim():
        return
    path = os.path.abspath(path)
    stop_at = os.path.abspath(stop_at) if stop_at else None
    reclaim(path)
    cur = os.path.dirname(path)
    while cur and cur != os.path.dirname(cur):
        if stop_at and not cur.startswith(stop_at):
            break
        try:
            if os.stat(cur).st_uid != _TARGET[0]:
                reclaim(cur)
            else:
                break
        except OSError:
            break
        if stop_at and os.path.samefile(cur, stop_at):
            break
        cur = os.path.dirname(cur)


def install_umask():
    """
    Keep group-write on anything created while elevated.

    Root's default umask of 022 strips group write, so even after a chown the
    file is only writable by the owning user. 002 leaves the group bit intact,
    which matters when the desktop session and the tool disagree about the
    primary group.
    """
    if IS_LINUX and elevated():
        os.umask(0o002)


# ---------------------------------------------------------------------------
# Can we actually read foreign process memory
# ---------------------------------------------------------------------------
def ptrace_scope():
    """The Yama ptrace_scope value, or None when Yama is not compiled in."""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def have_cap_sys_ptrace():
    """True when this process holds CAP_SYS_PTRACE in its effective set."""
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << _CAP_SYS_PTRACE))
    except (OSError, ValueError, IndexError):
        pass
    return False


def can_attach_to_foreign_process():
    """
    Whether /proc/<pid>/mem on a same-user, non-child process will open.

    Deliberately does not require root: root is one of three ways to satisfy
    the kernel here, and the other two do not create root-owned files.
    """
    if not IS_LINUX:
        return elevated()
    if elevated() or have_cap_sys_ptrace():
        return True
    scope = ptrace_scope()
    return scope is None or scope == 0


def require_memory_access(tool_name="This tool"):
    """
    Exit with an actionable message when memory access is not available.

    Called instead of a bare geteuid() check so that a correctly configured
    machine can run the tools as a normal user.
    """
    if not IS_LINUX:
        # elevated() returns False on macOS too - it probes for the Windows
        # admin API and swallows the AttributeError - so a bare "not elevated"
        # branch told Mac users to get Administrator rights on Windows. Name
        # the platform before assuming which one we are on.
        if platform.system() != "Windows":
            print(f"[-] {tool_name} does not support {platform.system()}.")
            print("    Reading another process's memory needs task_for_pid()")
            print("    and the mach_vm_* API on macOS; that backend does not")
            print("    exist yet. Linux and Windows are supported.")
            sys.exit(1)
        if not elevated():
            print(f"[-] {tool_name} needs Administrator rights on Windows.")
            print("    Right-click the launcher and choose")
            print("    'Run as administrator', or start it from an elevated")
            print("    terminal.")
            sys.exit(1)
        return

    if can_attach_to_foreign_process():
        install_umask()
        return

    scope = ptrace_scope()
    print(f"[-] {tool_name} cannot read xemu's memory as this user.")
    print()
    print(f"    Yama ptrace_scope is {scope}, which blocks reading")
    print("    /proc/<pid>/mem of a process this one did not start.")
    print()
    print("    Preferred fix (no sudo, no root-owned files ever again):")
    print("        sudo sysctl -w kernel.yama.ptrace_scope=0")
    print("    Make it persist across reboots:")
    print("        echo 'kernel.yama.ptrace_scope = 0' |"
          " sudo tee /etc/sysctl.d/10-xemu-ptrace.conf")
    print()
    print("    Alternative, scoped to this interpreter only:")
    print("        sudo setcap cap_sys_ptrace+ep $(readlink -f $(which python3))")
    print()
    print("    Or keep using sudo -- files will still be handed back to you.")
    sys.exit(1)
