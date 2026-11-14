"""This file contains the Windows Defender Registry plugin."""

import datetime
import re

from dfdatetime import filetime as dfdatetime_filetime
from dfdatetime import posix_time as dfdatetime_posix_time

from dfwinreg import definitions as dfwinreg_definitions

from plaso.containers import events
from plaso.parsers import winreg_parser
from plaso.parsers.winreg_plugins import interface


class WindowsDefenderRegistryEventData(events.EventData):
    """Windows Defender detection or quarantine event data.

    Attributes:
      action (str): action taken on the threat, such as "Quarantined".
      action_code (int): action or threat status code, as stored.
      action_taken (str): action taken on the threat, alias of action.
      category (int): category of the threat.
      detection_time (dfdatetime.DateTimeValues): date and time the threat was
          detected.
      filename (str): path of the detected or quarantined resource, kept as an
          alias of path for compatibility with the DetectionHistory parser.
      file_path (str): path of the detected or quarantined resource.
      initial_detection_time (dfdatetime.DateTimeValues): date and time the
          threat was first detected.
      key_path (str): Windows Registry key path.
      last_threat_status_change_time (dfdatetime.DateTimeValues): date and time
          the status of the threat last changed.
      last_written_time (dfdatetime.DateTimeValues): date and time the Registry
          key was last written.
      path (str): path of the detected or quarantined resource.
      process (str): name of the process associated with the detection.
      quarantine_id (str): identifier of the quarantine entry.
      quarantine_identifier (str): identifier of the quarantine entry.
      recorded_time (dfdatetime.DateTimeValues): date and time the record was
          written.
      remediation_time (dfdatetime.DateTimeValues): date and time the threat was
          remediated.
      severity (int): severity of the threat.
      threat_identifier (int): identifier of the threat.
      threat_name (str): name of the threat.
      threat_status (int): status of the threat.
      username (str): user associated with the detection.
    """

    DATA_TYPE = "av:defender:registry"

    def __init__(self):
        """Initializes event data."""
        super().__init__(data_type=self.DATA_TYPE)
        self.action = None
        self.action_code = None
        self.action_taken = None
        self.category = None
        self.detection_time = None
        self.filename = None
        self.file_path = None
        self.initial_detection_time = None
        self.key_path = None
        self.last_threat_status_change_time = None
        self.last_written_time = None
        self.path = None
        self.process = None
        self.quarantine_id = None
        self.quarantine_identifier = None
        self.recorded_time = None
        self.remediation_time = None
        self.severity = None
        self.threat_identifier = None
        self.threat_name = None
        self.threat_status = None
        self.username = None


class WindowsDefenderRegistryPlugin(interface.WindowsRegistryPlugin):
    """Windows Registry plugin for Windows Defender detection and quarantine data.

    Windows Defender stores threat detection and quarantine metadata in the
    SOFTWARE hive. The exact value and key names changed between versions of
    Windows and Defender. This plugin accepts the common variants, including the
    "Microsoft Antimalware" product name used by some Defender versions, and
    emits one event per detection or quarantine record.
    """

    NAME = "windefender"
    DATA_FORMAT = "Windows Defender detection and quarantine Registry data"

    FILTERS = frozenset(
        [
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Defender"
                "\\Detection History"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Defender"
                "\\DetectionHistory"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Defender"
                "\\Quarantine"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Defender\\Scans"
                "\\History"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows Defender\\Threats"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Antimalware"
                "\\Detection History"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Antimalware"
                "\\DetectionHistory"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Antimalware"
                "\\Quarantine"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Antimalware"
                "\\Scans\\History"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Antimalware"
                "\\Threats"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Security Client"
                "\\Detection History"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Security Client"
                "\\DetectionHistory"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Security Client"
                "\\Quarantine"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Microsoft Security Client"
                "\\Threats"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender"
                "\\Detection History"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender"
                "\\DetectionHistory"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender"
                "\\Quarantine"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender\\Scans"
                "\\History"
            ),
            interface.WindowsRegistryKeyPathFilter(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender\\Threats"
            ),
        ]
    )

    _ACTION_NAMES = {
        1: "Cleaned",
        2: "Quarantined",
        3: "Removed",
        6: "Allowed",
        8: "User defined",
        9: "No action",
        10: "Blocked",
    }

    _THREAT_STATUS_NAMES = {
        0: "Unknown",
        1: "Detected",
        2: "Cleaned",
        3: "Quarantined",
        4: "Removed",
        5: "Allowed",
        6: "Blocked",
        102: "Clean failed",
        103: "Quarantine failed",
        104: "Remove failed",
        105: "Allow failed",
        106: "Abandoned",
        107: "Block failed",
    }

    _ACTION_ALIASES = (
        "Action",
        "ActionTaken",
        "ActionTakenID",
        "CleaningAction",
        "CleaningActionID",
        "RemediationAction",
        "RemediationActionID",
        "ThreatAction",
        "ThreatActionID",
    )

    _CATEGORY_ALIASES = ("Category", "CategoryID", "ThreatCategory")

    _DETECTION_TIME_ALIASES = (
        "DetectionTime",
        "DetectionTimestamp",
        "FirstDetectionTime",
        "InitialDetectionTime",
        "ThreatTrackingFirstDetectionTime",
    )

    _LAST_STATUS_CHANGE_TIME_ALIASES = (
        "LastStatusChangeTime",
        "LastThreatStatusChangeTime",
        "StatusChangeTime",
        "ThreatTrackingLastThreatStatusChangeTime",
    )

    _PATH_ALIASES = (
        "FilePath",
        "FileName",
        "DetectedFile",
        "Location",
        "Object",
        "OriginalFileName",
        "OriginalPath",
        "Path",
        "QuarantinedFile",
        "Resource",
        "ResourceLocation",
        "ResourceName",
        "ResourcePath",
        "Target",
        "ThreatFile",
        "ThreatPath",
    )

    _PROCESS_ALIASES = (
        "Process",
        "ProcessName",
        "ThreatTrackingProcessName",
    )

    _QUARANTINE_IDENTIFIER_ALIASES = (
        "Entry",
        "EntryID",
        "QuarantineEntry",
        "QuarantineEntryGuid",
        "QuarantineEntryID",
        "QuarantineEntryId",
        "QuarantineGuid",
        "QuarantineGUID",
        "QuarantineID",
        "QuarantineId",
        "ThreatTrackingQuarantineId",
    )

    _RECORD_TIME_ALIASES = (
        "DetectionTime",
        "EventTime",
        "RecordedTime",
        "ThreatTrackingStartTime",
        "Time",
        "Timestamp",
    )

    _REMEDIATION_TIME_ALIASES = (
        "RemediationTime",
        "ThreatTrackingRemediationTime",
    )

    _SEVERITY_ALIASES = (
        "Severity",
        "SeverityID",
        "ThreatSeverity",
    )

    _THREAT_IDENTIFIER_ALIASES = (
        "DetectionID",
        "ThreatIDValue",
        "ThreatID",
        "ThreatId",
        "ThreatIdentifier",
        "ThreatTrackingThreatId",
    )

    _THREAT_NAME_ALIASES = (
        "DetectionName",
        "MalwareName",
        "Threat",
        "ThreatDisplayName",
        "ThreatName",
        "ThreatNameText",
        "VirusName",
    )

    _THREAT_STATUS_ALIASES = (
        "Status",
        "ThreatStatus",
        "ThreatStatusID",
    )

    _USER_ALIASES = (
        "DomainUser",
        "AccountName",
        "ThreatTrackingDomainUser",
        "User",
        "UserName",
    )

    _THREAT_ID_DEFAULT_ACTION_IDS_ALIASES = (
        "ThreatIDDefaultActionIds",
        "ThreatIDDefaultAction_Ids",
        "ThreatIds",
    )

    _THREAT_ID_DEFAULT_ACTION_ACTION_ALIASES = (
        "ThreatIDDefaultActionActions",
        "ThreatIDDefaultAction_Actions",
    )

    _SPLIT_VALUE_SEPARATOR = re.compile(r"[\t,;|]")

    _UNSIGNED_INTEGER_DATA_TYPES = frozenset(
        [
            dfwinreg_definitions.REG_DWORD,
            dfwinreg_definitions.REG_DWORD_BE,
            dfwinreg_definitions.REG_DWORD_BIG_ENDIAN,
            dfwinreg_definitions.REG_DWORD_LE,
            dfwinreg_definitions.REG_DWORD_LITTLE_ENDIAN,
        ]
    )

    @classmethod
    def _GetAction(cls, registry_key, value_suffix=None):
        """Retrieves the action taken on a threat.

        Args:
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
          value_suffix (Optional[str]): numeric suffix of the value names.

        Returns:
          tuple[str, int]: action name and action code, where the action name and
              code can be None.
        """
        registry_value = cls._GetRegistryValue(
            registry_key, cls._ACTION_ALIASES, value_suffix=value_suffix
        )
        action_code = cls._GetInteger(registry_value)

        if action_code is not None:
            return cls._ACTION_NAMES.get(action_code, str(action_code)), action_code

        action = cls._GetString(registry_value)
        if action:
            action_code = cls._GetIntegerFromObject(action)
            if action_code is not None:
                return cls._ACTION_NAMES.get(action_code, action), action_code

            return action, None

        registry_value = cls._GetRegistryValue(
            registry_key, cls._THREAT_STATUS_ALIASES, value_suffix=value_suffix
        )
        threat_status = cls._GetInteger(registry_value)
        if threat_status is not None:
            return (
                cls._THREAT_STATUS_NAMES.get(threat_status, str(threat_status)),
                threat_status,
            )

        status = cls._GetString(registry_value)
        if status:
            threat_status = cls._GetIntegerFromObject(status)
            if threat_status is not None:
                return (
                    cls._THREAT_STATUS_NAMES.get(threat_status, status),
                    threat_status,
                )

            return status, None

        return None, None

    @classmethod
    def _GetArrayOfIntegers(cls, registry_value):
        """Retrieves an array of integers from a Registry value.

        Args:
          registry_value (dfwinreg.WinRegistryValue): Windows Registry value.

        Returns:
          list[int]: integer values.
        """
        if not registry_value:
            return []

        value_data = registry_value.GetDataAsObject()

        if isinstance(value_data, list):
            return [
                integer_value
                for integer_value in (
                    cls._GetIntegerFromObject(value) for value in value_data
                )
                if integer_value is not None
            ]

        if isinstance(value_data, int):
            return [value_data]

        if isinstance(value_data, str):
            value_data = value_data.strip("\x00").strip()
            if not value_data:
                return []

            values = []
            for value in cls._SPLIT_VALUE_SEPARATOR.split(value_data):
                integer_value = cls._GetIntegerFromObject(value.strip())
                if integer_value is not None:
                    values.append(integer_value)
            return values

        if isinstance(value_data, bytes):
            if len(value_data) % 8 == 0:
                return [
                    int.from_bytes(value_data[offset : offset + 8], byteorder="little")
                    for offset in range(0, len(value_data), 8)
                ]

            if len(value_data) % 4 == 0:
                return [
                    int.from_bytes(value_data[offset : offset + 4], byteorder="little")
                    for offset in range(0, len(value_data), 4)
                ]

        return []

    @classmethod
    def _GetDateTime(cls, registry_value):
        """Retrieves a date and time from a Registry value.

        Args:
          registry_value (dfwinreg.WinRegistryValue): Windows Registry value.

        Returns:
          dfdatetime.Filetime: date and time or None if not available.
        """
        timestamp = cls._GetInteger(registry_value)
        if timestamp:
            try:
                return dfdatetime_filetime.Filetime(timestamp=timestamp)
            except ValueError:
                return None

        date_time_string = cls._GetString(registry_value)
        if not date_time_string:
            return None

        try:
            date_time = datetime.datetime.fromisoformat(
                date_time_string.replace("Z", "+00:00")
            )
        except ValueError:
            return None

        if not date_time.tzinfo:
            date_time = date_time.replace(tzinfo=datetime.timezone.utc)

        timestamp = int(date_time.timestamp() * 1000000)
        return dfdatetime_posix_time.PosixTimeInMicroseconds(timestamp=timestamp)

    @classmethod
    def _GetInteger(cls, registry_value):
        """Retrieves an integer from a Registry value.

        Args:
          registry_value (dfwinreg.WinRegistryValue): Windows Registry value.

        Returns:
          int: integer value or None if not available.
        """
        if not registry_value:
            return None

        integer_value = cls._GetIntegerFromObject(registry_value.GetDataAsObject())
        if integer_value is None:
            return None

        if (
            integer_value < 0
            and registry_value.data_type in cls._UNSIGNED_INTEGER_DATA_TYPES
        ):
            integer_value &= 0xFFFFFFFF

        elif (
            integer_value < 0
            and registry_value.data_type == dfwinreg_definitions.REG_QWORD
        ):
            integer_value &= 0xFFFFFFFFFFFFFFFF

        return integer_value

    @classmethod
    def _GetIntegerFromObject(cls, value):
        """Retrieves an integer from a Registry value data object.

        Args:
          value (object): Registry value data object.

        Returns:
          int: integer value or None if not available.
        """
        if isinstance(value, int):
            return value

        if isinstance(value, list):
            if len(value) == 1:
                return cls._GetIntegerFromObject(value[0])
            return None

        if isinstance(value, bytes):
            if len(value) in (1, 2, 4, 8):
                return int.from_bytes(value, byteorder="little")
            return None

        if isinstance(value, str):
            value = value.strip("\x00").strip()
            if not value:
                return None

            try:
                return int(value, 0)
            except ValueError:
                try:
                    return int(value, 10)
                except ValueError:
                    return None

        return None

    @classmethod
    def _GetRegistryValue(cls, registry_key, value_names, value_suffix=None):
        """Retrieves a Registry value by one of its aliases.

        The lookup is case-insensitive and ignores spaces, underscores and
        hyphens, so that values such as "Threat Name", "ThreatName" and
        "Threat_Name" are treated as the same value. A numeric suffix is also
        accepted to support records that store multiple values in one key.

        Args:
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
          value_names (tuple[str]): value name aliases.
          value_suffix (Optional[str]): numeric suffix of the value names.

        Returns:
          dfwinreg.WinRegistryValue: Windows Registry value or None if not
              available.
        """
        normalized_names = [
            cls._NormalizeValueName(value_name) for value_name in value_names
        ]

        registry_values = list(registry_key.GetValues())
        normalized_registry_values = [
            (cls._NormalizeValueName(registry_value.name), registry_value)
            for registry_value in registry_values
        ]

        for normalized_name in normalized_names:
            for registry_value_name, registry_value in normalized_registry_values:
                if value_suffix:
                    if registry_value_name == f"{normalized_name:s}{value_suffix:s}":
                        return registry_value

                elif registry_value_name == normalized_name:
                    return registry_value

        if value_suffix:
            return None

        for normalized_name in normalized_names:
            for registry_value_name, registry_value in normalized_registry_values:
                if not registry_value_name.startswith(normalized_name):
                    continue

                suffix = registry_value_name[len(normalized_name) :]
                if suffix and suffix.isdigit():
                    return registry_value

        return None

    @classmethod
    def _GetValueSuffixes(cls, registry_key):
        """Retrieves numeric suffixes of values in a Registry key.

        Args:
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.

        Returns:
          list[str]: numeric value name suffixes.
        """
        all_aliases = (
            cls._ACTION_ALIASES
            + cls._CATEGORY_ALIASES
            + cls._DETECTION_TIME_ALIASES
            + cls._LAST_STATUS_CHANGE_TIME_ALIASES
            + cls._PATH_ALIASES
            + cls._PROCESS_ALIASES
            + cls._QUARANTINE_IDENTIFIER_ALIASES
            + cls._RECORD_TIME_ALIASES
            + cls._REMEDIATION_TIME_ALIASES
            + cls._SEVERITY_ALIASES
            + cls._THREAT_IDENTIFIER_ALIASES
            + cls._THREAT_NAME_ALIASES
            + cls._THREAT_STATUS_ALIASES
            + cls._USER_ALIASES
        )
        normalized_aliases = {cls._NormalizeValueName(alias) for alias in all_aliases}

        suffixes = set()
        for registry_value in registry_key.GetValues():
            normalized_name = cls._NormalizeValueName(registry_value.name)
            for normalized_alias in normalized_aliases:
                if not normalized_name.startswith(normalized_alias):
                    continue

                suffix = normalized_name[len(normalized_alias) :]
                if suffix and suffix.isdigit():
                    suffixes.add(suffix)

        return sorted(suffixes, key=int)

    @classmethod
    def _GetString(cls, registry_value):
        """Retrieves a string from a Registry value.

        Args:
          registry_value (dfwinreg.WinRegistryValue): Windows Registry value.

        Returns:
          str: string value or None if not available.
        """
        if not registry_value:
            return None

        value_data = registry_value.GetDataAsObject()

        if isinstance(value_data, list):
            value_data = "; ".join(
                str(value).strip("\x00").strip() for value in value_data if value
            )

        elif isinstance(value_data, bytes):
            value_data = cls._GetStringFromBytes(value_data)

        elif isinstance(value_data, int):
            value_data = str(value_data)

        if not isinstance(value_data, str):
            return None

        value_data = value_data.strip("\x00").strip()
        return value_data or None

    @classmethod
    def _GetStringFromBytes(cls, value_data):
        """Retrieves a string from binary Registry value data.

        Args:
          value_data (bytes): binary value data.

        Returns:
          str: string value or None if not available.
        """
        if not value_data:
            return None

        encodings = ["utf-8", "utf-16-le"]
        if value_data.count(b"\x00") > len(value_data) // 4:
            encodings = ["utf-16-le", "utf-8"]

        for encoding in encodings:
            try:
                decoded_data = value_data.decode(encoding)
            except (UnicodeDecodeError, ValueError):
                continue

            decoded_data = decoded_data.strip("\x00").strip()
            if not decoded_data:
                continue

            printable_characters = sum(
                1 for character in decoded_data if character.isprintable()
            )
            if printable_characters >= len(decoded_data) * 0.8:
                return decoded_data

        return None

    @classmethod
    def _NormalizeValueName(cls, value_name):
        """Normalizes a Registry value name for comparison.

        Args:
          value_name (str): Registry value name.

        Returns:
          str: normalized value name.
        """
        if not value_name:
            return ""

        return re.sub(r"[^a-z0-9]", "", value_name.lower())

    def _ExtractEventFromKey(self, parser_mediator, registry_key, value_suffix=None):
        """Extracts an event from a Registry key that contains a record.

        Args:
          parser_mediator (ParserMediator): mediates interactions between parsers
              and other components, such as storage and dfVFS.
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
          value_suffix (Optional[str]): numeric suffix of the value names.
        """
        action, action_code = self._GetAction(registry_key, value_suffix=value_suffix)

        registry_value = self._GetRegistryValue(
            registry_key, self._CATEGORY_ALIASES, value_suffix=value_suffix
        )
        category = self._GetInteger(registry_value)

        detection_time = self._GetDateTime(
            self._GetRegistryValue(
                registry_key,
                self._DETECTION_TIME_ALIASES,
                value_suffix=value_suffix,
            )
        )
        last_threat_status_change_time = self._GetDateTime(
            self._GetRegistryValue(
                registry_key,
                self._LAST_STATUS_CHANGE_TIME_ALIASES,
                value_suffix=value_suffix,
            )
        )
        recorded_time = self._GetDateTime(
            self._GetRegistryValue(
                registry_key, self._RECORD_TIME_ALIASES, value_suffix=value_suffix
            )
        )
        remediation_time = self._GetDateTime(
            self._GetRegistryValue(
                registry_key,
                self._REMEDIATION_TIME_ALIASES,
                value_suffix=value_suffix,
            )
        )

        path = self._GetString(
            self._GetRegistryValue(
                registry_key, self._PATH_ALIASES, value_suffix=value_suffix
            )
        )
        process = self._GetString(
            self._GetRegistryValue(
                registry_key, self._PROCESS_ALIASES, value_suffix=value_suffix
            )
        )
        quarantine_identifier = self._GetString(
            self._GetRegistryValue(
                registry_key,
                self._QUARANTINE_IDENTIFIER_ALIASES,
                value_suffix=value_suffix,
            )
        )
        if (
            not quarantine_identifier
            and "\\quarantine" in registry_key.path.lower()
            and registry_key.name.startswith("{")
            and registry_key.name.endswith("}")
        ):
            quarantine_identifier = registry_key.name

        registry_value = self._GetRegistryValue(
            registry_key, self._SEVERITY_ALIASES, value_suffix=value_suffix
        )
        severity = self._GetInteger(registry_value)

        registry_value = self._GetRegistryValue(
            registry_key,
            self._THREAT_IDENTIFIER_ALIASES,
            value_suffix=value_suffix,
        )
        threat_identifier = self._GetInteger(registry_value)
        if threat_identifier is None:
            threat_identifier = self._GetString(registry_value)

        threat_name = self._GetString(
            self._GetRegistryValue(
                registry_key, self._THREAT_NAME_ALIASES, value_suffix=value_suffix
            )
        )

        registry_value = self._GetRegistryValue(
            registry_key, self._THREAT_STATUS_ALIASES, value_suffix=value_suffix
        )
        threat_status = self._GetInteger(registry_value)
        if threat_status is None:
            threat_status = self._GetString(registry_value)

        username = self._GetString(
            self._GetRegistryValue(
                registry_key, self._USER_ALIASES, value_suffix=value_suffix
            )
        )

        if not any(
            [
                action,
                path,
                quarantine_identifier,
                threat_identifier,
                threat_name,
            ]
        ):
            return

        event_data = WindowsDefenderRegistryEventData()
        event_data.action = action
        event_data.action_code = action_code
        event_data.action_taken = action
        event_data.category = category
        event_data.detection_time = detection_time
        event_data.filename = path
        event_data.file_path = path
        event_data.initial_detection_time = detection_time
        event_data.key_path = registry_key.path
        event_data.last_threat_status_change_time = last_threat_status_change_time
        event_data.last_written_time = registry_key.last_written_time
        event_data.path = path
        event_data.process = process
        event_data.quarantine_id = quarantine_identifier
        event_data.quarantine_identifier = quarantine_identifier
        event_data.recorded_time = recorded_time or registry_key.last_written_time
        event_data.remediation_time = remediation_time
        event_data.severity = severity
        event_data.threat_identifier = threat_identifier
        event_data.threat_name = threat_name
        event_data.threat_status = threat_status
        event_data.username = username

        parser_mediator.ProduceEventData(event_data)

    def _ExtractEventsFromKey(self, parser_mediator, registry_key):
        """Extracts events from a Windows Registry key and its subkeys.

        Args:
          parser_mediator (ParserMediator): mediates interactions between parsers
              and other components, such as storage and dfVFS.
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
        """
        self._ExtractEventsFromThreatIDDefaultAction(parser_mediator, registry_key)

        value_suffixes = self._GetValueSuffixes(registry_key)
        if value_suffixes:
            for value_suffix in value_suffixes:
                self._ExtractEventFromKey(
                    parser_mediator, registry_key, value_suffix=value_suffix
                )

        else:
            self._ExtractEventFromKey(parser_mediator, registry_key)

        for subkey in registry_key.GetSubkeys():
            self._ExtractEventsFromKey(parser_mediator, subkey)

    def _ExtractEventsFromThreatIDDefaultAction(self, parser_mediator, registry_key):
        """Extracts events from a ThreatIDDefaultAction Registry key.

        Args:
          parser_mediator (ParserMediator): mediates interactions between parsers
              and other components, such as storage and dfVFS.
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
        """
        threat_ids_value = self._GetRegistryValue(
            registry_key, self._THREAT_ID_DEFAULT_ACTION_IDS_ALIASES
        )
        actions_value = self._GetRegistryValue(
            registry_key, self._THREAT_ID_DEFAULT_ACTION_ACTION_ALIASES
        )
        if not threat_ids_value or not actions_value:
            return

        threat_identifiers = self._GetArrayOfIntegers(threat_ids_value)
        action_codes = self._GetArrayOfIntegers(actions_value)
        if not threat_identifiers or not action_codes:
            return

        for index, threat_identifier in enumerate(threat_identifiers):
            if index >= len(action_codes):
                break

            action_code = action_codes[index]
            event_data = WindowsDefenderRegistryEventData()
            event_data.action = self._ACTION_NAMES.get(action_code, str(action_code))
            event_data.action_code = action_code
            event_data.key_path = registry_key.path
            event_data.last_written_time = registry_key.last_written_time
            event_data.recorded_time = registry_key.last_written_time
            event_data.threat_identifier = threat_identifier

            parser_mediator.ProduceEventData(event_data)

    # pylint: disable=arguments-differ
    def ExtractEvents(self, parser_mediator, registry_key, **kwargs):
        """Extracts events from a Windows Registry key.

        Args:
          parser_mediator (ParserMediator): mediates interactions between parsers
              and other components, such as storage and dfVFS.
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
        """
        self._ExtractEventsFromKey(parser_mediator, registry_key)


WinDefenderRegistryPlugin = WindowsDefenderRegistryPlugin

DefenderWindowsRegistryPlugin = WindowsDefenderRegistryPlugin
WinDefenderEventData = WindowsDefenderRegistryEventData
WinDefenderRegistryParser = WindowsDefenderRegistryPlugin
WindowsDefenderPlugin = WindowsDefenderRegistryPlugin
WinDefenderPlugin = WindowsDefenderRegistryPlugin
WindowsDefenderEventData = WindowsDefenderRegistryEventData
WindowsDefenderRegistryParser = WindowsDefenderRegistryPlugin

winreg_parser.WinRegistryParser.RegisterPlugin(WindowsDefenderRegistryPlugin)
