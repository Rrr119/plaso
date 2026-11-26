#!/usr/bin/env python3
"""Tests for the time zone helper functions."""

import datetime
import unittest

import pytz

from dfdatetime import time_elements as dfdatetime_time_elements

from plaso.lib import time_zone


class TimeZoneHelperTest(unittest.TestCase):
    """Tests for the time zone helper functions."""

    def testFormatTimeZoneOffset(self):
        """Tests the FormatTimeZoneOffset function."""
        self.assertEqual(time_zone.FormatTimeZoneOffset(0), "UTC")
        self.assertEqual(time_zone.FormatTimeZoneOffset(330), "UTC+05:30")
        self.assertEqual(time_zone.FormatTimeZoneOffset(-240), "UTC-04:00")

    def testGetTimeZoneFromString(self):
        """Tests the GetTimeZoneFromString function."""
        self.assertEqual(
            time_zone.GetTimeZoneName(time_zone.GetTimeZoneFromString("UTC")),
            "UTC",
        )
        self.assertEqual(
            time_zone.GetTimeZoneName(
                time_zone.GetTimeZoneFromString("America/New_York")
            ),
            "America/New_York",
        )
        self.assertEqual(
            time_zone.GetTimeZoneName(time_zone.GetTimeZoneFromString("UTC+05:30")),
            "UTC+05:30",
        )
        self.assertIsNone(time_zone.GetTimeZoneFromString("Bogus/TimeZone"))

    def testNormalizeDateTime(self):
        """Tests the NormalizeDateTime function."""
        test_values = [
            ("Asia/Tokyo", (2024, 7, 15, 15, 0, 0), 1721023200000000, 540),
            ("America/New_York", (2024, 7, 15, 8, 0, 0), 1721044800000000, -240),
            ("Europe/Berlin", (2024, 7, 15, 15, 30, 0), 1721050200000000, 120),
        ]

        for (
            time_zone_name,
            time_elements,
            expected_timestamp,
            expected_offset,
        ) in test_values:
            date_time = dfdatetime_time_elements.TimeElements(
                time_elements_tuple=time_elements
            )
            date_time.is_local_time = True

            timestamp, result_time_zone_name, time_zone_offset = (
                time_zone.NormalizeDateTime(
                    date_time, time_zone=pytz.timezone(time_zone_name)
                )
            )

            self.assertEqual(timestamp, expected_timestamp)
            self.assertEqual(result_time_zone_name, time_zone_name)
            self.assertEqual(time_zone_offset, expected_offset)

        date_time = dfdatetime_time_elements.TimeElements(
            time_elements_tuple=(2024, 7, 15, 15, 0, 0), time_zone_offset=330
        )
        date_time.is_local_time = True

        timestamp, result_time_zone_name, time_zone_offset = (
            time_zone.NormalizeDateTime(date_time)
        )

        self.assertEqual(timestamp, 1721035800000000)
        self.assertEqual(result_time_zone_name, "UTC+05:30")
        self.assertEqual(time_zone_offset, 330)

    def testRestoreDateTime(self):
        """Tests the RestoreDateTime function."""
        date_time = time_zone.RestoreDateTime(
            1721044800000000, "America/New_York", -240
        )

        self.assertEqual(
            date_time,
            datetime.datetime(2024, 7, 15, 8, 0, 0, tzinfo=pytz.FixedOffset(-240)),
        )
        self.assertEqual(date_time.utcoffset(), datetime.timedelta(hours=-4))


if __name__ == "__main__":
    unittest.main()
