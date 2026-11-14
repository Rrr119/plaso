"""Parser for Windows Defender scan DetectionHistory files."""

import os

from dfdatetime import filetime as dfdatetime_filetime

from dtfabric.runtime import data_maps as dtfabric_data_maps

from plaso.containers import events
from plaso.lib import dtfabric_helper
from plaso.lib import specification
from plaso.parsers import interface
from plaso.parsers import manager


class WindowsDefenderHistoryEventData(events.EventData):
    """Windows Defender scan DetectionHistory event data.

    Attributes:
      action (str): action taken on the threat, such as "Quarantined".
      action_code (int): threat status code that describes the action.
      action_taken (str): action taken on the threat, alias of action.
      additional_filenames (list[str]): locations of additional detected files.
      category (int): category of the threat.
      container_filenames (list[str]): location of files detected inside a
          container.
      filename (str): name of the file that the threat was detected in.
      file_path (str): path of the file that the threat was detected in.
      host_and_user (str): name of the host and user in "DOMAIN\\USER" format.
      initial_detection_time (dfdatetime.DateTimeValues): date and time the
          threat was first detected.
      last_threat_status_change_time (dfdatetime.DateTimeValues): date and time
          the status of the threat last changed.
      process (str): name of the process that caused the detection.
      quarantine_id (str): identifier of the quarantine entry.
      quarantine_identifier (str): identifier of the quarantine entry.
      recorded_time (dfdatetime.DateTimeValues): date and time the log entry
          was recorded.
      remediation_account (str): name of the account under which the threat was
          remediated in "DOMAIN\\USER" format.
      remediation_time (dfdatetime.DateTimeValues): date and time the threat
          was remediated.
      severity (int): severity of the threat.
      sha256 (str): SHA-256 hash of the file.
      threat_identifier (int): identifier of the threat.
      threat_name (str): name of the threat that was detected.
      threat_status (int): status of the threat.
      web_filenames (list[str]): URI of files detected as downloaded from the web.
    """

    DATA_TYPE = "av:defender:detection_history"

    def __init__(self):
        """Initializes event data."""
        super().__init__(data_type=self.DATA_TYPE)
        self.action = None
        self.action_code = None
        self.action_taken = None
        self.additional_filenames = None
        self.category = None
        self.container_filenames = None
        self.filename = None
        self.file_path = None
        self.host_and_user = None
        self.initial_detection_time = None
        self.last_threat_status_change_time = None
        self.process = None
        self.quarantine_id = None
        self.quarantine_identifier = None
        self.recorded_time = None
        self.remediation_account = None
        self.remediation_time = None
        self.severity = None
        self.sha256 = None
        self.threat_identifier = None
        self.threat_name = None
        self.threat_status = None
        self.web_filenames = None


class WinDefenderHistoryParser(
    interface.FileObjectParser, dtfabric_helper.DtFabricHelper
):
    """Parses a Windows Defender scan DetectionHistory file."""

    NAME = "windefender_history"
    DATA_FORMAT = "Windows Defender scan DetectionHistory file"

    _FILE_SIGNATURE = "Magic.Version:1.2"

    _VALUE_DESCRIPTIONS = [
        {0: "Threat identifier", 1: "Identifier"},
        {
            0: "UnknownMagic1",
            1: "Threat name",
            3: "Severity",
            4: "Category",
            7: "Threat status",
        },
        {
            0: "UnknownMagic2",
            1: "Resource type",
            2: "Resource location",
            4: "Threat tracking data size",
            5: "Threat tracking data",
            6: "Last threat status change time",
            9: "Quarantine identifier",
            12: "Domain user1",
            14: "Process name",
            18: "Initial detection time",
            20: "Remediation time",
            24: "Domain user2",
        },
    ]

    _DEFINITION_FILE = os.path.join(
        os.path.dirname(__file__), "windefender_history.yaml"
    )

    _VALUE_DATA_TYPE_BINARY_DATA = 0x00000028
    _VALUE_DATA_TYPE_FILETIME = 0x0000000A
    _VALUE_DATA_TYPE_GUID = 0x0000001E
    _VALUE_DATA_TYPE_STRING = 0x00000015

    _VALUE_DATA_TYPES_INTEGER = frozenset(
        [0x00000000, 0x00000005, 0x00000006, 0x00000008]
    )

    _THREAT_ATTRIBUTE_ALIASES = {
        "Category": ("Category", "CategoryID", "ThreatCategory"),
        "Domain user1": (
            "DomainUser",
            "Domain user1",
            "ThreatTrackingDomainUser",
        ),
        "Domain user2": (
            "Domain user2",
            "RemediationUser",
            "ThreatTrackingRemediationUser",
        ),
        "Initial detection time": (
            "Initial detection time",
            "InitialDetectionTime",
            "ThreatTrackingInitialDetectionTime",
        ),
        "Last threat status change time": (
            "Last threat status change time",
            "LastThreatStatusChangeTime",
            "ThreatTrackingLastThreatStatusChangeTime",
        ),
        "Process name": (
            "ProcessName",
            "Process name",
            "ThreatTrackingProcessName",
        ),
        "Quarantine identifier": (
            "Quarantine identifier",
            "QuarantineEntry",
            "QuarantineEntryID",
            "QuarantineGuid",
            "QuarantineGUID",
            "QuarantineID",
            "QuarantineId",
            "ThreatTrackingQuarantineId",
        ),
        "Remediation time": (
            "RemediationTime",
            "Remediation time",
            "ThreatTrackingRemediationTime",
        ),
        "Severity": ("Severity", "SeverityID", "ThreatSeverity"),
        "Threat identifier": (
            "Threat identifier",
            "ThreatID",
            "ThreatId",
            "ThreatTrackingThreatId",
        ),
        "Threat name": (
            "Threat name",
            "ThreatName",
            "ThreatTrackingThreatName",
        ),
        "Threat status": ("Threat status", "ThreatStatus", "ThreatStatusID"),
        "ThreatTrackingSha256": (
            "SHA256",
            "ThreatTrackingSha256",
            "ThreatTrackingSHA256",
        ),
        "ThreatTrackingStartTime": (
            "RecordedTime",
            "ThreatTrackingStartTime",
            "ThreatTrackingStartTimeUtc",
        ),
    }

    _THREAT_STATUS_ACTIONS = {
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

    @classmethod
    def GetFormatSpecification(cls):
        """Retrieves the format specification.

        Returns:
          FormatSpecification: format specification.
        """
        format_specification = specification.FormatSpecification(cls.NAME)
        format_specification.AddNewSignature(
            cls._FILE_SIGNATURE.encode("utf-16-le"), offset=0x30
        )
        return format_specification

    def _GetDateTime(self, filetime):
        """Retrieves the date and time from a FILETIME timestamp.

        Args:
          filetime (int): FILETIME timestamp.

        Returns:
          dfdatetime.DateTimeValues: date and time or None if not set.
        """
        if not filetime:
            return None

        return dfdatetime_filetime.Filetime(timestamp=filetime)

    @classmethod
    def _GetThreatAttribute(cls, threat_attributes, attribute_name):
        """Retrieves a threat attribute by one of its known aliases.

        Args:
          threat_attributes (dict[str, object]): threat attributes by name.
          attribute_name (str): canonical name of the attribute.

        Returns:
          object: attribute value or None if not available.
        """
        aliases = cls._THREAT_ATTRIBUTE_ALIASES.get(attribute_name, (attribute_name,))

        for alias in aliases:
            if alias in threat_attributes:
                return threat_attributes[alias]

        normalized_aliases = {cls._NormalizeAttributeName(alias) for alias in aliases}
        for name, value in threat_attributes.items():
            if cls._NormalizeAttributeName(name) in normalized_aliases:
                return value

        return None

    @classmethod
    def _NormalizeAttributeName(cls, attribute_name):
        """Normalizes a threat attribute name for comparison.

        Args:
          attribute_name (str): threat attribute name.

        Returns:
          str: normalized attribute name.
        """
        return "".join(
            character for character in attribute_name.lower() if character.isalnum()
        )

    def _ReadThreatTrackingData(self, threat_tracking_data, file_offset):
        """Reads the threat tracking data.

        Args:
          threat_tracking_data (bytes): threat tracking data.
          file_offset (int): offset of the threat tracking data relative to
              the start of the file.

        Returns:
          dict[str, str]: Mapping of threat tracking keys to values.

        Raises:
          OSError: if the threat tracking data cannot be read.
        """
        threat_tracking = {}
        data_type_map = self._GetDataTypeMap("uint32le")

        values_data_size = self._ReadStructureFromByteStream(
            threat_tracking_data, 0, data_type_map
        )
        if values_data_size != 1:
            values_data_offset = 4
            values_data_end_offset = values_data_size
        else:
            header = self._ReadThreatTrackingHeader(threat_tracking_data)

            values_data_offset = header.header_size + 4
            values_data_end_offset = header.total_data_size

        while values_data_offset < values_data_end_offset:
            threat_value, data_size = self._ReadThreatTrackingValue(
                threat_tracking_data[values_data_offset:],
                file_offset + values_data_offset,
            )
            if hasattr(threat_value, "value_string"):
                threat_tracking[threat_value.key_string] = threat_value.value_string
            if hasattr(threat_value, "value_integer"):
                threat_tracking[threat_value.key_string] = threat_value.value_integer
            values_data_offset += data_size

        return threat_tracking

    def _ReadThreatTrackingHeader(self, threat_tracking_data):
        """Reads the threat tracking header.

        Args:
          threat_tracking_data (bytes): threat tracking data.

        Returns:
          threat_tracking_header: threat tracking header.

        Raises:
          OSError: if the threat tracking header cannot be read.
        """
        data_type_map = self._GetDataTypeMap("threat_tracking_header")

        return self._ReadStructureFromByteStream(threat_tracking_data, 0, data_type_map)

    def _ReadThreatTrackingValue(self, threat_tracking_data, file_offset):
        """Reads the threat tracking value.

        Args:
          threat_tracking_data (bytes): threat tracking data.
          file_offset (int): offset of the threat tracking data relative to
              the start of the file.

        Returns:
          tuple[threat_tracking_value, int]: threat tracking value and
              data size.

        Raises:
          OSError: if the threat tracking value cannot be read.
        """
        data_type_map = self._GetDataTypeMap("threat_tracking_value")

        context = dtfabric_data_maps.DataTypeMapContext()

        threat_tracking_value = self._ReadStructureFromByteStream(
            threat_tracking_data, file_offset, data_type_map, context=context
        )
        return threat_tracking_value, context.byte_size

    def _ReadValue(self, file_object, file_offset, parser_mediator):
        """Reads the value.

        Args:
          file_object (file): file-like object.
          file_offset (int): offset of the value relative to the start of the file.
          parser_mediator (ParserMediator): mediates interactions between parsers and
              other components, such as storage and dfVFS.

        Returns:
          object: value.

        Raises:
          OSError: if the value cannot be read.
          ParseError: when the value data type is unknown.
        """
        data_type_map = self._GetDataTypeMap("detection_history_value")

        value, _ = self._ReadStructureFromFileObject(
            file_object, file_offset, data_type_map
        )
        value_object = None

        if value.data_type in self._VALUE_DATA_TYPES_INTEGER:
            value_object = value.value_integer
        elif value.data_type == self._VALUE_DATA_TYPE_FILETIME:
            value_object = value.value_filetime
        elif value.data_type == self._VALUE_DATA_TYPE_STRING:
            value_object = value.value_string
        elif value.data_type == self._VALUE_DATA_TYPE_GUID:
            value_object = value.value_guid
        elif value.data_type == self._VALUE_DATA_TYPE_BINARY_DATA:
            value_object = value.data
        else:
            parser_mediator.ProduceWarning(
                f"unknown value data type: {value.data_type!s}"
            )
            value_object = value.data

        return value_object

    def ParseFileObject(self, parser_mediator, file_object):
        """Parses a Windows Defender History file-like object.

        Args:
          parser_mediator (ParserMediator): mediates interactions between parsers and
              other components, such as storage and dfVFS.
          file_object (dfvfs.FileIO): file-like object.

        Raises:
          WrongParser: when the file cannot be parsed.
        """
        value_tuples = []

        file_offset = 0
        file_size = file_object.get_size()

        while file_offset < file_size:
            value_object = self._ReadValue(file_object, file_offset, parser_mediator)
            value_tuples.append((file_offset, value_object))
            file_offset = file_object.tell()

        resource_name = ""
        threat_attributes = {"Resources": []}
        value_index_set = 0
        value_index = 0

        for file_offset, value_object in value_tuples:
            if value_object == self._FILE_SIGNATURE:
                if value_index_set < 2:
                    value_index_set += 1
                value_index = 0

            if (value_index_set, value_index) == (2, 5):
                threat_attributes.update(
                    self._ReadThreatTrackingData(value_object, file_offset + 8)
                )
            else:
                description = self._VALUE_DESCRIPTIONS[value_index_set].get(
                    value_index, f"UNKNOWN_{value_index_set:d}_{value_index:d}"
                )
                value_string = f"{value_object!s}"

                if description == "Resource type":
                    resource_name = value_string

                elif description == "Resource location" and resource_name is not None:
                    threat_attributes["Resources"].append(
                        {"Type": resource_name, "Location": value_string}
                    )
                    resource_name = None

                else:
                    threat_attributes[description] = value_object

            value_index += 1

        filenames = [
            threat_attribute["Location"]
            for threat_attribute in threat_attributes["Resources"]
            if threat_attribute["Type"] == "file"
        ]
        if not filenames:
            filename = threat_attributes.get("CONTEXT_DATA_FILENAME")
            process_ppid = threat_attributes.get("CONTEXT_DATA_PROCESS_PPID")

            filenames = [",".join(list(filter(None, [filename, process_ppid])))]

        web_files = [
            threat_attribute["Location"]
            for threat_attribute in threat_attributes["Resources"]
            if threat_attribute["Type"] == "webfile"
        ]
        container_files = [
            threat_attribute["Location"]
            for threat_attribute in threat_attributes["Resources"]
            if threat_attribute["Type"] == "containerfile"
        ]
        additional_filenames = [
            threat_attribute["Location"]
            for threat_attribute in threat_attributes["Resources"]
            if "file" not in threat_attribute["Type"]
        ]
        event_data = WindowsDefenderHistoryEventData()
        event_data.additional_filenames = additional_filenames or None
        event_data.category = self._GetThreatAttribute(threat_attributes, "Category")
        event_data.container_filenames = container_files or None
        event_data.filename = filenames[0] or None
        event_data.file_path = event_data.filename
        event_data.host_and_user = (
            self._GetThreatAttribute(threat_attributes, "Domain user1") or None
        )
        event_data.initial_detection_time = self._GetDateTime(
            self._GetThreatAttribute(threat_attributes, "Initial detection time")
        )
        event_data.last_threat_status_change_time = self._GetDateTime(
            self._GetThreatAttribute(
                threat_attributes, "Last threat status change time"
            )
        )
        event_data.process = (
            self._GetThreatAttribute(threat_attributes, "Process name") or None
        )
        quarantine_identifier = self._GetThreatAttribute(
            threat_attributes, "Quarantine identifier"
        )
        if quarantine_identifier:
            quarantine_identifier = str(quarantine_identifier).strip("{}")
            if quarantine_identifier == "00000000-0000-0000-0000-000000000000":
                quarantine_identifier = None

        event_data.quarantine_identifier = quarantine_identifier or None
        event_data.quarantine_id = event_data.quarantine_identifier
        event_data.recorded_time = self._GetDateTime(
            self._GetThreatAttribute(threat_attributes, "ThreatTrackingStartTime")
        )
        event_data.remediation_account = (
            self._GetThreatAttribute(threat_attributes, "Domain user2") or None
        )
        event_data.remediation_time = self._GetDateTime(
            self._GetThreatAttribute(threat_attributes, "Remediation time")
        )
        event_data.severity = self._GetThreatAttribute(threat_attributes, "Severity")
        event_data.sha256 = (
            self._GetThreatAttribute(threat_attributes, "ThreatTrackingSha256") or None
        )
        event_data.threat_identifier = self._GetThreatAttribute(
            threat_attributes, "Threat identifier"
        )
        event_data.threat_name = (
            self._GetThreatAttribute(threat_attributes, "Threat name") or None
        )
        event_data.threat_status = self._GetThreatAttribute(
            threat_attributes, "Threat status"
        )
        if isinstance(event_data.threat_status, int):
            event_data.action_code = event_data.threat_status
            event_data.action = self._THREAT_STATUS_ACTIONS.get(
                event_data.threat_status, str(event_data.threat_status)
            )
            event_data.action_taken = event_data.action

        event_data.web_filenames = web_files or None

        parser_mediator.ProduceEventData(event_data)


manager.ParsersManager.RegisterParser(WinDefenderHistoryParser)
