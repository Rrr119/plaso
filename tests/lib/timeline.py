#!/usr/bin/env python3
"""Tests for the timeline helper functions."""

import unittest

from plaso.containers import events
from plaso.lib import timeline


class TimelineHelperTest(unittest.TestCase):
    """Tests for the timeline helper functions."""

    def _CreateEvent(self, timestamp, timestamp_desc, time_zone_name):
        """Creates an event for testing.

        Args:
          timestamp (int): normalized UTC timestamp in microseconds.
          timestamp_desc (str): timestamp description.
          time_zone_name (str): original time zone name.

        Returns:
          EventObject: event.
        """
        event = events.EventObject()
        event.timestamp = timestamp
        event.timestamp_desc = timestamp_desc
        event.time_zone = time_zone_name

        return event

    def testGetEventSortKey(self):
        """Tests the GetEventSortKey function."""
        event = self._CreateEvent(123, "Test Time", "Asia/Tokyo")

        sort_key = timeline.GetEventSortKey(event)

        self.assertEqual(sort_key, (123, "Test Time", "Asia/Tokyo", 0))

    def testMergeEventSources(self):
        """Tests the MergeEventSources function."""
        event1 = self._CreateEvent(300, "Test Time", "Europe/Berlin")
        event2 = self._CreateEvent(100, "Test Time", "Asia/Tokyo")
        event3 = self._CreateEvent(200, "Test Time", "America/New_York")

        events = list(timeline.MergeEventSources([[event1], [event2, event3]]))

        self.assertEqual(events, [event2, event3, event1])

    def testMergeSortedEventSources(self):
        """Tests the MergeSortedEventSources function."""
        event1 = self._CreateEvent(100, "Test Time", "Asia/Tokyo")
        event2 = self._CreateEvent(200, "Test Time", "America/New_York")
        event3 = self._CreateEvent(300, "Test Time", "Europe/Berlin")

        events = list(timeline.MergeSortedEventSources([[event1, event3], [event2]]))

        self.assertEqual(events, [event1, event2, event3])


if __name__ == "__main__":
    unittest.main()
