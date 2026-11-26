"""Time zone helper functions."""

import datetime
import re

import pytz

from plaso.helpers.windows import time_zones as windows_time_zones

_EPOCH = datetime.datetime(1970, 1, 1)

_TIME_ZONE_OFFSET_REGEX = re.compile(
    r"^(?:UTC|GMT)?\s*(?P<sign>[+-])(?P<hours>\d{1,2})(?::?(?P<minutes>\d{2}))?$",
    re.IGNORECASE,
)


def GetTimeZoneFromString(time_zone_string):
    """Retrieves a time zone from a time zone string.

    Args:
      time_zone_string (str): time zone name, such as "Europe/Amsterdam", a
          Windows time zone name or an offset, such as "UTC+01:00".

    Returns:
      datetime.tzinfo: time zone or None if the time zone is not supported.
    """
    if not time_zone_string or not isinstance(time_zone_string, str):
        return None

    time_zone_string = time_zone_string.strip()
    if not time_zone_string:
        return None

    if time_zone_string.upper() in ("GMT", "UTC", "Z"):
        return pytz.UTC

    resolved_time_zone_string = windows_time_zones.WINDOWS_TIME_ZONES.get(
        time_zone_string, time_zone_string
    )

    match = _TIME_ZONE_OFFSET_REGEX.match(resolved_time_zone_string)
    if match:
        hours = int(match.group("hours"), 10)
        minutes = int(match.group("minutes") or 0, 10)
        if hours > 23 or minutes > 59:
            return None

        offset = (hours * 60) + minutes
        if match.group("sign") == "-":
            offset *= -1

        return pytz.FixedOffset(offset)

    try:
        return pytz.timezone(resolved_time_zone_string)
    except pytz.UnknownTimeZoneError:
        return None


def GetTimeZoneName(time_zone):
    """Retrieves the name of a time zone.

    Args:
      time_zone (datetime.tzinfo): time zone.

    Returns:
      str: time zone name or None if not available.
    """
    if time_zone is None:
        return None

    if isinstance(time_zone, str):
        resolved_time_zone = GetTimeZoneFromString(time_zone)
        if resolved_time_zone is None:
            return time_zone

        time_zone = resolved_time_zone

    time_zone_name = getattr(time_zone, "zone", None)
    if time_zone_name:
        return time_zone_name

    try:
        time_zone_offset = time_zone.utcoffset(None)
    except (AttributeError, TypeError):
        return None

    if time_zone_offset is None:
        return None

    return FormatTimeZoneOffset(int(time_zone_offset.total_seconds() / 60))


def FormatTimeZoneOffset(time_zone_offset):
    """Formats a time zone offset.

    Args:
      time_zone_offset (int): time zone offset in minutes from UTC.

    Returns:
      str: formatted time zone offset, such as "UTC+05:30".
    """
    if not time_zone_offset:
        return "UTC"

    if time_zone_offset < 0:
        time_zone_offset_sign = "-"
        time_zone_offset *= -1
    else:
        time_zone_offset_sign = "+"

    hours, minutes = divmod(time_zone_offset, 60)
    return f"UTC{time_zone_offset_sign:s}{hours:02d}:{minutes:02d}"


def _GetDateTimeInTimeZone(timestamp, time_zone):
    """Retrieves a UTC timestamp as date and time in a time zone.

    Args:
      timestamp (int): timestamp in microseconds since January 1, 1970 00:00:00 UTC.
      time_zone (datetime.tzinfo): time zone.

    Returns:
      datetime.datetime: date and time in the time zone or None if the timestamp
          is out of bounds.
    """
    try:
        date_time = _EPOCH + datetime.timedelta(microseconds=timestamp)
    except OverflowError:
        return None

    date_time = pytz.UTC.localize(date_time)
    return date_time.astimezone(time_zone)


def _GetTimeZoneOffsetSeconds(timestamp, time_zone):
    """Retrieves the time zone offset for a local wall clock timestamp.

    Args:
      timestamp (int): local wall clock timestamp in microseconds since
          January 1, 1970 00:00:00.
      time_zone (datetime.tzinfo): time zone.

    Returns:
      int: time zone offset in seconds from UTC or None if not available.
    """
    try:
        date_time = _EPOCH + datetime.timedelta(microseconds=timestamp)
    except OverflowError:
        return None

    if hasattr(time_zone, "localize"):
        try:
            date_time = time_zone.localize(date_time, is_dst=None)
        except (pytz.AmbiguousTimeError, pytz.NonExistentTimeError):
            date_time = time_zone.localize(date_time, is_dst=False)
    else:
        date_time = date_time.replace(tzinfo=time_zone)

    time_zone_offset = date_time.utcoffset()
    if time_zone_offset is None:
        return None

    return int(time_zone_offset.total_seconds())


def _GetTimeZoneOffsetAtTimestamp(timestamp, time_zone):
    """Retrieves the time zone offset at a UTC timestamp.

    Args:
      timestamp (int): timestamp in microseconds since January 1, 1970 00:00:00 UTC.
      time_zone (datetime.tzinfo): time zone.

    Returns:
      int: time zone offset in minutes from UTC or None if not available.
    """
    date_time = _GetDateTimeInTimeZone(timestamp, time_zone)
    if date_time is None:
        return None

    time_zone_offset = date_time.utcoffset()
    if time_zone_offset is None:
        return None

    return int(time_zone_offset.total_seconds() / 60)


def NormalizeDateTime(
    date_time, time_zone=None, timestamp=None, default_time_zone=pytz.UTC
):
    """Normalizes date and time values to UTC.

    Args:
      date_time (dfdatetime.DateTimeValues): date and time values.
      time_zone (Optional[datetime.tzinfo]): time zone to use for date and time
          values without time zone information.
      timestamp (Optional[int]): timestamp in microseconds, as determined by
          date_time.GetPlasoTimestamp(), for performance.
      default_time_zone (Optional[datetime.tzinfo]): time zone to use if no other
          time zone can be determined.

    Returns:
      tuple[int, str, int]: normalized UTC timestamp in microseconds, original
          time zone name and original time zone offset in minutes from UTC.

    Raises:
      ValueError: if the timestamp cannot be determined.
    """
    if timestamp is None:
        timestamp = date_time.GetPlasoTimestamp()

    if timestamp is None:
        return None, None, None

    time_zone_hint = getattr(date_time, "time_zone_hint", None)
    if time_zone is None:
        time_zone = GetTimeZoneFromString(time_zone_hint)

    original_time_zone_offset = getattr(date_time, "time_zone_offset", None)
    if original_time_zone_offset is not None:
        time_zone_name = GetTimeZoneName(time_zone)
        if not time_zone_name:
            time_zone_name = FormatTimeZoneOffset(original_time_zone_offset)

        return timestamp, time_zone_name, original_time_zone_offset

    if date_time.is_local_time:
        local_timestamp = timestamp

        if time_zone is None:
            time_zone = default_time_zone

        time_zone_offset_seconds = None
        if time_zone is not None:
            time_zone_offset_seconds = _GetTimeZoneOffsetSeconds(
                local_timestamp, time_zone
            )

        if time_zone_offset_seconds is None:
            return local_timestamp, GetTimeZoneName(time_zone), 0

        timestamp = local_timestamp - (time_zone_offset_seconds * 1000000)
        time_zone_offset = int(time_zone_offset_seconds / 60)

        return timestamp, GetTimeZoneName(time_zone), time_zone_offset

    time_zone_offset = None
    if time_zone is not None:
        time_zone_offset = _GetTimeZoneOffsetAtTimestamp(timestamp, time_zone)

    time_zone_name = GetTimeZoneName(time_zone)
    if not time_zone_name and time_zone_offset is not None:
        time_zone_name = FormatTimeZoneOffset(time_zone_offset)

    return timestamp, time_zone_name, time_zone_offset


def RestoreDateTime(timestamp, time_zone=None, time_zone_offset=None):
    """Restores a normalized UTC timestamp to its original time zone.

    Args:
      timestamp (int): timestamp in microseconds since January 1, 1970 00:00:00 UTC.
      time_zone (Optional[str]): original time zone name.
      time_zone_offset (Optional[int]): original time zone offset in minutes from
          UTC.

    Returns:
      datetime.datetime: date and time in the original time zone or None if the
          timestamp is not set or out of bounds.
    """
    if timestamp is None:
        return None

    resolved_time_zone = GetTimeZoneFromString(time_zone)
    if resolved_time_zone is None and time_zone_offset is not None:
        resolved_time_zone = pytz.FixedOffset(time_zone_offset)

    if resolved_time_zone is None:
        resolved_time_zone = pytz.UTC

    return _GetDateTimeInTimeZone(timestamp, resolved_time_zone)
