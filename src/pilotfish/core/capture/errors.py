class CaptureError(Exception):
    """Live capture couldn't start, or failed while running."""


class CapturePermissionError(CaptureError):
    """This user can't open the BPF devices that live capture reads from."""
