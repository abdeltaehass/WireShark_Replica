import pytest
from hypothesis import settings

from pilotfish.core.capture import CapturePermissionError, PcapSource

# Shared CI runners have noisy timing, so a per-example deadline only adds flaky failures.
settings.register_profile("pilotfish", deadline=None)
settings.load_profile("pilotfish")


@pytest.fixture
def capture_access() -> None:
    """Skip the test unless this user can open the BPF devices live capture reads."""
    try:
        PcapSource("lo0").close()
    except CapturePermissionError as error:
        pytest.skip(f"live capture needs sudo or access to /dev/bpf*: {error}")
