"""``pilotfish bpf-access``: capture without sudo, as Wireshark's ChmodBPF allows."""

import os

from pilotfish.cli.status import CommandError, Exit
from pilotfish.core.capture import access

ACTIONS = ("status", "install", "uninstall")


def run(action: str, user: str | None = None) -> Exit:
    if action == "status":
        return _status(access.check(user))
    if os.geteuid() != 0:
        raise CommandError(
            Exit.NO_PERMISSION,
            f"{action} changes the system, which needs an administrator; run it with sudo",
        )
    try:
        if action == "install":
            done = access.install(user or access.current_user())
        else:
            done = access.uninstall()
    except OSError as error:
        raise CommandError(Exit.CAPTURE_ERROR, str(error)) from None
    for line in done:
        print(line)
    if action == "install":
        print(f"anyone in {access.GROUP} can now capture without sudo, from their next login")
    return Exit.OK


def _status(state: access.Access) -> Exit:
    if state.member:
        group = "member" + (", in effect now" if state.effective else ", from the next login")
    else:
        group = "not a member"
    daemons = [
        f"pilotfish's {'installed' if state.daemon else 'not installed'}",
        f"Wireshark's ChmodBPF {'installed' if state.wireshark_daemon else 'not installed'}",
    ]
    print(f"user        {state.user}")
    print(f"group       {access.GROUP}: {group}")
    print(f"daemons     {'; '.join(daemons)}")
    print(f"/dev/bpf*   {'readable' if state.readable else 'not readable'}")
    for line in state.explain():
        print(f"\n{line}")
    return Exit.OK if state.readable else Exit.NO_PERMISSION
