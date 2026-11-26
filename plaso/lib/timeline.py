"""Timeline event merging functions."""

import heapq


def GetEventSortKey(event):
    """Retrieves a chronological sort key for an event.

    Args:
      event (EventObject): event.

    Returns:
      tuple[int, str, str, int]: sort key that contains the normalized UTC
          timestamp, timestamp description, original time zone and original time
          zone offset.
    """
    date_time = getattr(event, "date_time", None)

    return (
        event.timestamp or 0,
        event.timestamp_desc or "",
        getattr(event, "time_zone", None) or "",
        getattr(date_time, "time_zone_offset", None) or 0,
    )


def MergeEventSources(event_sources):
    """Merges events from multiple sources in chronological order.

    Args:
      event_sources (list[Iterable[EventObject]]): event sources.

    Yields:
      EventObject: merged events in chronological order.
    """
    events = []

    for source_index, event_source in enumerate(event_sources):
        for event_index, event in enumerate(event_source):
            events.append((GetEventSortKey(event), source_index, event_index, event))

    events.sort(key=lambda item: item[:3])

    yield from (event for _, _, _, event in events)


def MergeSortedEventSources(event_sources):
    """Merges chronologically sorted event sources.

    Args:
      event_sources (list[Iterable[EventObject]]): chronologically sorted event
          sources.

    Yields:
      EventObject: merged events in chronological order.
    """
    event_sources_heap = []

    for source_index, event_source in enumerate(event_sources):
        event_iterator = iter(event_source)
        try:
            event = next(event_iterator)
        except StopIteration:
            continue

        heapq.heappush(
            event_sources_heap,
            (GetEventSortKey(event), source_index, 0, event, event_iterator),
        )

    while event_sources_heap:
        _, source_index, event_index, event, event_iterator = heapq.heappop(
            event_sources_heap
        )

        yield event

        try:
            next_event = next(event_iterator)
        except StopIteration:
            continue

        heapq.heappush(
            event_sources_heap,
            (
                GetEventSortKey(next_event),
                source_index,
                event_index + 1,
                next_event,
                event_iterator,
            ),
        )
