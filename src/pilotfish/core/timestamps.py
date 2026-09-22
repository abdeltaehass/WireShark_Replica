"""Timestamps held as integer nanoseconds since the Unix epoch.

Integers keep full nanosecond precision, which a float of seconds can't do
for present-day dates.
"""

from datetime import UTC, datetime, timedelta

NS_PER_SECOND = 1_000_000_000

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def format_epoch(timestamp_ns: int) -> str:
    """Seconds since the epoch with nine decimals, as tshark prints ``frame.time_epoch``."""
    sign = "-" if timestamp_ns < 0 else ""
    seconds, nanoseconds = divmod(abs(timestamp_ns), NS_PER_SECOND)
    return f"{sign}{seconds}.{nanoseconds:09d}"


def format_utc(timestamp_ns: int) -> str:
    """UTC date and time with nanoseconds, such as ``2004-05-13 10:17:07.311224000``.

    Falls back to epoch seconds for times outside the years 1 to 9999.
    """
    seconds, nanoseconds = divmod(timestamp_ns, NS_PER_SECOND)
    try:
        moment = _EPOCH + timedelta(seconds=seconds)
    except OverflowError:
        return format_epoch(timestamp_ns)
    # isoformat always pads the year to four digits; strftime("%Y") varies by platform.
    return f"{moment.replace(tzinfo=None).isoformat(sep=' ')}.{nanoseconds:09d}"
