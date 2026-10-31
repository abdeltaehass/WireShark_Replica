"""Who may capture: the access_bpf group, and a launch daemon that lets it.

Capturing reads ``/dev/bpf*``, which macOS makes readable by root alone, and
makes again at every boot, so a ``chmod`` doesn't last. Wireshark's answer,
which pilotfish follows, is a launch daemon that runs at boot as root and
hands the devices to a group, ``access_bpf``. Installing it takes an
administrator once. After that, anyone in the group captures without sudo,
and so do the app and its capture helper.

The daemon only lets the group read the devices. That is all capturing
needs; writing to one sends packets, which pilotfish never does.

Wireshark's installer sets up the same group. Both daemons can be installed
at once, and each only adds permissions, so neither undoes the other.
"""

import grp
import os
import plistlib
import pwd
import shlex
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

GROUP = "access_bpf"
LABEL = "io.github.abdeltaehass.pilotfish.bpf-access"
DAEMON = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
SCRIPT = Path("/Library/Application Support/pilotfish/bpf-access")
WIRESHARK_DAEMON = Path("/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist")
DEVICES = Path("/dev")

SCRIPT_TEXT = f"""#!/bin/sh
# Installed by pilotfish (pilotfish bpf-access install). launchd runs this
# as root at every boot, as {DAEMON}
# asks.
#
# macOS makes the BPF devices that capture reads from as they are first
# opened, up to debug.bpf_maxdevices of them, each readable by root alone.
# Opening each one once makes them all, then the {GROUP} group may read
# them, which is all capturing needs. Writing to one would send packets, so
# the group isn't given that.

max=$(sysctl -n debug.bpf_maxdevices)
n=0
while [ "$n" -lt "$max" ]; do
    # true, not :, since a redirection that fails on a special builtin such
    # as : ends the script, and opening a device in use fails with EBUSY.
    true 2>/dev/null < "{DEVICES}/bpf$n"
    n=$((n + 1))
done

chgrp {GROUP} {DEVICES}/bpf*
chmod g+r {DEVICES}/bpf*
"""

type Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def daemon_plist() -> bytes:
    """The launch daemon: run the script as root, once, at every boot."""
    return plistlib.dumps({"Label": LABEL, "Program": str(SCRIPT), "RunAtLoad": True})


@dataclass(frozen=True, slots=True)
class Access:
    """Whether this user can capture, and what stands in the way if not."""

    user: str
    daemon: bool
    """pilotfish's launch daemon is installed."""
    wireshark_daemon: bool
    """Wireshark's ChmodBPF daemon is installed, which does the same."""
    member: bool
    """The user is in the group."""
    effective: bool
    """This process has the group already. Joining it counts from the next login."""
    readable: bool
    """This process can read ``/dev/bpf0``."""

    def explain(self) -> list[str]:
        """What to do, in a line or two each, or nothing if capture already works."""
        if self.readable:
            return []
        lines = []
        if not (self.daemon or self.wireshark_daemon):
            lines.append(
                "Capturing reads /dev/bpf*, which only root can read until a launch "
                f"daemon gives the {GROUP} group access at boot. Install it once with: "
                "sudo pilotfish bpf-access install"
            )
        elif not self.member:
            lines.append(
                f"{self.user} isn't in the {GROUP} group. Add them with: "
                "sudo pilotfish bpf-access install"
            )
        elif not self.effective:
            lines.append(
                f"{self.user} has joined the {GROUP} group, which counts from the next "
                "login. Log out and back in, or restart."
            )
        else:
            lines.append(
                "The launch daemon hasn't run since it was installed. Restart, or run: "
                f"sudo launchctl kickstart -k system/{LABEL}"
            )
        return lines


def check(user: str | None = None, devices: Path = DEVICES) -> Access:
    """How things stand for ``user``, by default whoever runs this."""
    name = user or current_user()
    try:
        gid = grp.getgrnam(GROUP).gr_gid
    except KeyError:
        gid = None
    member = gid is not None and gid in os.getgrouplist(name, pwd.getpwnam(name).pw_gid)
    return Access(
        user=name,
        daemon=DAEMON.exists(),
        wireshark_daemon=WIRESHARK_DAEMON.exists(),
        member=member,
        effective=gid is not None and gid in os.getgroups(),
        readable=os.access(devices / "bpf0", os.R_OK),
    )


def current_user() -> str:
    """The user to give access to: whoever ran sudo, if this is running under it."""
    return os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name


def install(
    user: str,
    *,
    root: Path = Path("/"),
    run: Runner = run_command,
    system: bool | None = None,
) -> list[str]:
    """Install the daemon, make the group, add ``user`` to it, and run the daemon now.

    Needs root. ``root`` puts the files somewhere else, to see what would be
    written, and then the commands that change the system are left out
    unless ``system`` says otherwise. Returns what was done, a line each.
    """
    done = []
    script = _under(root, SCRIPT)
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(SCRIPT_TEXT)
    script.chmod(0o755)
    daemon = _under(root, DAEMON)
    daemon.parent.mkdir(parents=True, exist_ok=True)
    daemon.write_bytes(daemon_plist())
    daemon.chmod(0o644)
    if os.geteuid() == 0:
        for path in (script, daemon):
            os.chown(path, 0, 0)
    done += [f"wrote {SCRIPT}", f"wrote {DAEMON}"]
    if not (root == Path("/") if system is None else system):
        return done
    if run(["dseditgroup", "-o", "read", GROUP]).returncode != 0:
        _must(run, ["dseditgroup", "-o", "create", "-r", "Packet capture", GROUP])
        done.append(f"made the {GROUP} group")
    _must(run, ["dseditgroup", "-o", "edit", "-a", user, "-t", "user", GROUP])
    done.append(f"added {user} to {GROUP}")
    # Loaded again from the start, so a reinstall runs the new script.
    run(["launchctl", "bootout", f"system/{LABEL}"])
    _must(run, ["launchctl", "bootstrap", "system", str(DAEMON)])
    done.append("ran the daemon, so /dev/bpf* can be read now")
    return done


def uninstall(
    *, root: Path = Path("/"), run: Runner = run_command, system: bool | None = None
) -> list[str]:
    """Remove the daemon and its script. The group stays, since Wireshark's uses it too."""
    done = []
    if root == Path("/") if system is None else system:
        run(["launchctl", "bootout", f"system/{LABEL}"])
    for path in (DAEMON, SCRIPT):
        target = _under(root, path)
        if target.exists():
            target.unlink()
            done.append(f"removed {path}")
    return done


def _under(root: Path, path: Path) -> Path:
    return root / path.relative_to("/")


def _must(run: Runner, command: Sequence[str]) -> None:
    result = run(command)
    if result.returncode != 0:
        reason = (result.stderr or result.stdout).strip() or f"exit status {result.returncode}"
        raise OSError(f"{shlex.join(command)}: {reason}")
