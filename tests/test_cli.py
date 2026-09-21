import subprocess
import sys

import pytest

from pilotfish import __version__
from pilotfish.cli.main import main


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert capsys.readouterr().out == f"pilotfish {__version__}\n"


def test_runs_as_module() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pilotfish", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == f"pilotfish {__version__}\n"
