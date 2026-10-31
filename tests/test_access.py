"""Capturing without sudo: the access_bpf group and the launch daemon that lets it."""

import grp
import os
import plistlib
import shutil
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from pilotfish.cli.main import main
from pilotfish.core.capture import access


class Recorder:
    """Stands in for running commands, and says how each one went."""

    def __init__(self, failing: Sequence[str] = ()) -> None:
        self.commands: list[list[str]] = []
        self.failing = failing

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(command))
        failed = " ".join(command) in self.failing
        return subprocess.CompletedProcess(command, 1 if failed else 0, "", "")


def test_the_files_installed(tmp_path: Path) -> None:
    done = access.install("someone", root=tmp_path, run=Recorder())
    daemon = tmp_path / access.DAEMON.relative_to("/")
    script = tmp_path / access.SCRIPT.relative_to("/")
    assert done == [f"wrote {access.SCRIPT}", f"wrote {access.DAEMON}"]
    assert plistlib.loads(daemon.read_bytes()) == {
        "Label": access.LABEL,
        "Program": str(access.SCRIPT),
        "RunAtLoad": True,
    }
    assert stat.S_IMODE(daemon.stat().st_mode) == 0o644
    assert stat.S_IMODE(script.stat().st_mode) == 0o755
    text = script.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert "chgrp access_bpf /dev/bpf*\nchmod g+r /dev/bpf*\n" in text
    # Reading is all capture needs; writing would send packets.
    assert "g+rw" not in text
    if shutil.which("plutil"):
        subprocess.run(["plutil", "-lint", str(daemon)], check=True, capture_output=True)


def test_installing_makes_the_group_adds_the_user_and_runs_the_daemon(tmp_path: Path) -> None:
    recorder = Recorder(failing=["dseditgroup -o read access_bpf"])
    done = access.install("someone", root=tmp_path, run=recorder, system=True)
    assert recorder.commands == [
        ["dseditgroup", "-o", "read", "access_bpf"],
        ["dseditgroup", "-o", "create", "-r", "Packet capture", "access_bpf"],
        ["dseditgroup", "-o", "edit", "-a", "someone", "-t", "user", "access_bpf"],
        ["launchctl", "bootout", f"system/{access.LABEL}"],
        ["launchctl", "bootstrap", "system", str(access.DAEMON)],
    ]
    assert done[2:] == [
        "made the access_bpf group",
        "added someone to access_bpf",
        "ran the daemon, so /dev/bpf* can be read now",
    ]


def test_a_group_already_there_is_left_alone(tmp_path: Path) -> None:
    recorder = Recorder()
    access.install("someone", root=tmp_path, run=recorder, system=True)
    assert ["dseditgroup", "-o", "create", "-r", "Packet capture", "access_bpf"] not in (
        recorder.commands
    )


def test_a_command_that_fails_says_why(tmp_path: Path) -> None:
    def refuse(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 64, "", "Operation not permitted\n")

    with pytest.raises(OSError, match=r"dseditgroup -o create .*: Operation not permitted"):
        access.install("someone", root=tmp_path, run=refuse, system=True)


def test_uninstalling_removes_the_files_and_unloads_the_daemon(tmp_path: Path) -> None:
    access.install("someone", root=tmp_path, run=Recorder())
    recorder = Recorder()
    done = access.uninstall(root=tmp_path, run=recorder, system=True)
    assert done == [f"removed {access.DAEMON}", f"removed {access.SCRIPT}"]
    assert recorder.commands == [["launchctl", "bootout", f"system/{access.LABEL}"]]
    assert not (tmp_path / access.DAEMON.relative_to("/")).exists()


@pytest.mark.macos
@pytest.mark.skipif(sys.platform != "darwin", reason="the script runs macOS's sysctl")
def test_the_script_lets_the_group_read_the_devices(tmp_path: Path) -> None:
    devices = tmp_path / "dev"
    devices.mkdir()
    for number in range(3):
        (devices / f"bpf{number}").touch(mode=0o600)
    # One of this user's own groups, which chgrp allows without root.
    group = grp.getgrgid(os.getgroups()[0]).gr_name
    script = tmp_path / "bpf-access"
    script.write_text(
        access.SCRIPT_TEXT.replace(f"{access.DEVICES}/bpf", f"{devices}/bpf").replace(
            access.GROUP, group
        )
    )
    subprocess.run(["/bin/sh", str(script)], check=True, capture_output=True)
    for device in devices.iterdir():
        mode = stat.S_IMODE(device.stat().st_mode)
        assert mode == 0o640, f"{device.name}: {oct(mode)}"
        assert grp.getgrgid(device.stat().st_gid).gr_name == group


def state(**changes: object) -> access.Access:
    fields: dict[str, object] = {
        "user": "someone",
        "daemon": False,
        "wireshark_daemon": False,
        "member": False,
        "effective": False,
        "readable": False,
    }
    fields.update(changes)
    return access.Access(**fields)  # type: ignore[arg-type]


def test_what_stands_in_the_way_is_said() -> None:
    assert state(readable=True).explain() == []
    assert "Install it once with: sudo pilotfish bpf-access install" in state().explain()[0]
    assert "someone isn't in the access_bpf group" in state(daemon=True).explain()[0]
    assert "counts from the next login" in state(daemon=True, member=True).explain()[0]
    waiting = state(wireshark_daemon=True, member=True, effective=True).explain()[0]
    assert "launchctl kickstart -k system/" in waiting


def test_status_says_how_things_stand(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(access, "check", lambda user=None: state(wireshark_daemon=True))
    assert main(["bpf-access"]) == 5
    out = capsys.readouterr().out
    assert "daemons     pilotfish's not installed; Wireshark's ChmodBPF installed\n" in out
    assert "/dev/bpf*   not readable\n" in out
    assert "someone isn't in the access_bpf group" in out

    monkeypatch.setattr(access, "check", lambda user=None: state(member=True, readable=True))
    assert main(["bpf-access", "status"]) == 0


def test_installing_needs_sudo(capsys: pytest.CaptureFixture[str]) -> None:
    if os.geteuid() == 0:
        pytest.skip("running as root")
    assert main(["bpf-access", "install"]) == 5
    assert "run it with sudo" in capsys.readouterr().err
