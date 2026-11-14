#!/usr/bin/env python3
"""Tests for the Windows Defender Registry plugin."""

import unittest

from dfdatetime import filetime as dfdatetime_filetime
from dfwinreg import definitions as dfwinreg_definitions
from dfwinreg import fake as dfwinreg_fake

from plaso.parsers.winreg_plugins import windefender

from tests.parsers.winreg_plugins import test_lib


class WindowsDefenderRegistryPluginTest(test_lib.RegistryPluginTestCase):
    """Tests for the Windows Defender Registry plugin."""

    def _CreateFiletime(self, date_time_string):
        """Creates a FILETIME timestamp.

        Args:
          date_time_string (str): date and time value in UTC.

        Returns:
          int: FILETIME timestamp.
        """
        filetime = dfdatetime_filetime.Filetime()
        filetime.CopyFromDateTimeString(date_time_string)
        return filetime.timestamp

    def _CreateRegistryKey(self, relative_key_path, last_written_time):
        """Creates a Registry key for testing.

        Args:
          relative_key_path (str): relative Windows Registry key path.
          last_written_time (int): FILETIME timestamp.

        Returns:
          dfwinreg.WinRegistryKey: a Windows Registry key.
        """
        _, _, key_name = relative_key_path.rpartition("\\")
        return dfwinreg_fake.FakeWinRegistryKey(
            key_name,
            key_path_prefix="HKEY_LOCAL_MACHINE\\SOFTWARE",
            last_written_time=last_written_time,
            relative_key_path=relative_key_path,
        )

    def _AddBinaryValue(self, registry_key, name, value_data):
        """Adds a binary Registry value.

        Args:
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
          name (str): name of the value.
          value_data (bytes): value data.
        """
        registry_value = dfwinreg_fake.FakeWinRegistryValue(
            name,
            data=value_data,
            data_type=dfwinreg_definitions.REG_BINARY,
        )
        registry_key.AddValue(registry_value)

    def _AddDwordValue(self, registry_key, name, value):
        """Adds a DWORD Registry value.

        Args:
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
          name (str): name of the value.
          value (int): value data.
        """
        registry_value = dfwinreg_fake.FakeWinRegistryValue(
            name,
            data=value.to_bytes(4, byteorder="little"),
            data_type=dfwinreg_definitions.REG_DWORD,
        )
        registry_key.AddValue(registry_value)

    def _AddStringValue(self, registry_key, name, value):
        """Adds a string Registry value.

        Args:
          registry_key (dfwinreg.WinRegistryKey): Windows Registry key.
          name (str): name of the value.
          value (str): value data.
        """
        registry_value = dfwinreg_fake.FakeWinRegistryValue(
            name,
            data=value.encode("utf-16-le"),
            data_type=dfwinreg_definitions.REG_SZ,
        )
        registry_key.AddValue(registry_value)

    def testFilters(self):
        """Tests the FILTERS class attribute."""
        plugin = windefender.WindowsDefenderRegistryPlugin()

        self._AssertFiltersOnKeyPath(
            plugin,
            "HKEY_LOCAL_MACHINE\\SOFTWARE",
            "Microsoft\\Windows Defender\\DetectionHistory",
        )
        self._AssertFiltersOnKeyPath(
            plugin,
            "HKEY_LOCAL_MACHINE\\SOFTWARE",
            "Microsoft\\Windows Defender\\Quarantine",
        )
        self._AssertFiltersOnKeyPath(
            plugin,
            "HKEY_LOCAL_MACHINE\\SOFTWARE",
            "Microsoft\\Microsoft Antimalware\\Threats",
        )
        self._AssertFiltersOnKeyPath(
            plugin,
            "HKEY_CURRENT_USER\\SOFTWARE",
            "Microsoft\\Windows Defender\\Scans\\History",
        )
        self._AssertNotFiltersOnKeyPath(
            plugin, "HKEY_LOCAL_MACHINE\\SOFTWARE", "Microsoft\\Windows Defender"
        )

    def testProcessDetectionHistory(self):
        """Tests parsing a Windows 10 or 11 detection history record."""
        last_written_time = self._CreateFiletime("2022-07-22 05:32:28")
        registry_key = self._CreateRegistryKey(
            "Microsoft\\Windows Defender\\DetectionHistory", last_written_time
        )

        record_key = dfwinreg_fake.FakeWinRegistryKey(
            "{9C66C39C-49DD-42D7-9822-4039C98CC246}",
            last_written_time=last_written_time,
        )
        registry_key.AddSubkey(record_key.name, record_key)

        self._AddStringValue(record_key, "ThreatName", "Virus:DOS/EICAR_Test_File")
        self._AddDwordValue(record_key, "ThreatID", 2147519003)
        self._AddStringValue(
            record_key, "Path", "C:\\Users\\testuser\\Downloads\\eicar.com"
        )
        self._AddDwordValue(record_key, "Action", 2)
        self._AddDwordValue(record_key, "ThreatStatus", 3)
        self._AddDwordValue(record_key, "Severity", 5)
        self._AddDwordValue(record_key, "Category", 42)
        self._AddStringValue(record_key, "DomainUser", "FRYPTOP\\testuser")
        self._AddStringValue(
            record_key,
            "ProcessName",
            "C:\\Windows\\explorer.exe",
        )
        self._AddStringValue(
            record_key,
            "QuarantineGuid",
            "{7C66C39C-49DD-42D7-9822-4039C98CC246}",
        )

        filetime_data = self._CreateFiletime("2022-07-22 05:32:27").to_bytes(
            8, byteorder="little"
        )
        self._AddBinaryValue(record_key, "InitialDetectionTime", filetime_data)

        filetime_data = self._CreateFiletime("2022-07-22 05:32:28").to_bytes(
            8, byteorder="little"
        )
        self._AddBinaryValue(record_key, "LastThreatStatusChangeTime", filetime_data)

        filetime_data = self._CreateFiletime("2022-07-22 05:32:30").to_bytes(
            8, byteorder="little"
        )
        self._AddBinaryValue(record_key, "RemediationTime", filetime_data)

        plugin = windefender.WindowsDefenderRegistryPlugin()
        storage_writer = self._ParseKeyWithPlugin(registry_key, plugin)

        number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
            "event_data"
        )
        self.assertEqual(number_of_event_data, 1)

        expected_event_values = {
            "action": "Quarantined",
            "action_code": 2,
            "category": 42,
            "data_type": "av:defender:registry",
            "detection_time": "2022-07-22T05:32:27.0000000+00:00",
            "filename": "C:\\Users\\testuser\\Downloads\\eicar.com",
            "initial_detection_time": "2022-07-22T05:32:27.0000000+00:00",
            "last_threat_status_change_time": "2022-07-22T05:32:28.0000000+00:00",
            "last_written_time": "2022-07-22T05:32:28.0000000+00:00",
            "path": "C:\\Users\\testuser\\Downloads\\eicar.com",
            "process": "C:\\Windows\\explorer.exe",
            "quarantine_identifier": ("{7C66C39C-49DD-42D7-9822-4039C98CC246}"),
            "recorded_time": "2022-07-22T05:32:28.0000000+00:00",
            "remediation_time": "2022-07-22T05:32:30.0000000+00:00",
            "severity": 5,
            "threat_identifier": 2147519003,
            "threat_name": "Virus:DOS/EICAR_Test_File",
            "threat_status": 3,
            "username": "FRYPTOP\\testuser",
        }

        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 0)
        self.CheckEventData(event_data, expected_event_values)

    def testProcessLegacyQuarantineRecord(self):
        """Tests parsing a legacy quarantine record with alternate names."""
        last_written_time = self._CreateFiletime("2014-03-06 12:15:42")
        registry_key = self._CreateRegistryKey(
            "Microsoft\\Microsoft Antimalware\\Quarantine", last_written_time
        )

        record_key = dfwinreg_fake.FakeWinRegistryKey(
            "{B535B2BF-6E31-9A41-A914-FDF71F7509D4}",
            last_written_time=last_written_time,
        )
        registry_key.AddSubkey(record_key.name, record_key)

        self._AddStringValue(record_key, "Threat Name", "Trojan:Win32/Downloader")
        self._AddStringValue(record_key, "Threat Id", "0x80000001")
        self._AddStringValue(
            record_key, "Resource Path", "C:\\Windows\\Temp\\payload.exe"
        )
        self._AddDwordValue(record_key, "Cleaning Action", 3)
        self._AddStringValue(record_key, "Quarantine Entry ID", "42")
        self._AddStringValue(record_key, "DetectionTime", "2014-03-06T12:15:42Z")

        plugin = windefender.WindowsDefenderRegistryPlugin()
        storage_writer = self._ParseKeyWithPlugin(registry_key, plugin)

        number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
            "event_data"
        )
        self.assertEqual(number_of_event_data, 1)

        expected_event_values = {
            "action": "Removed",
            "action_code": 3,
            "data_type": "av:defender:registry",
            "detection_time": "2014-03-06T12:15:42.000000+00:00",
            "initial_detection_time": "2014-03-06T12:15:42.000000+00:00",
            "key_path": (
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft Antimalware"
                "\\Quarantine\\{B535B2BF-6E31-9A41-A914-FDF71F7509D4}"
            ),
            "path": "C:\\Windows\\Temp\\payload.exe",
            "quarantine_identifier": "42",
            "recorded_time": "2014-03-06T12:15:42.000000+00:00",
            "threat_name": "Trojan:Win32/Downloader",
        }

        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 0)
        self.CheckEventData(event_data, expected_event_values)

    def testProcessThreatIDDefaultAction(self):
        """Tests parsing ThreatIDDefaultAction Registry values."""
        last_written_time = self._CreateFiletime("2021-09-08 10:30:00")
        registry_key = self._CreateRegistryKey(
            "Microsoft\\Windows Defender\\Threats", last_written_time
        )

        action_key = dfwinreg_fake.FakeWinRegistryKey("ThreatIDDefaultAction")
        registry_key.AddSubkey(action_key.name, action_key)

        threat_identifiers = b"".join(
            [
                (1234).to_bytes(8, byteorder="little"),
                (5678).to_bytes(8, byteorder="little"),
            ]
        )
        self._AddBinaryValue(
            action_key, "ThreatIDDefaultAction_Ids", threat_identifiers
        )

        action_codes = b"".join(
            [
                (3).to_bytes(8, byteorder="little"),
                (6).to_bytes(8, byteorder="little"),
            ]
        )
        self._AddBinaryValue(action_key, "ThreatIDDefaultAction_Actions", action_codes)

        plugin = windefender.WindowsDefenderRegistryPlugin()
        storage_writer = self._ParseKeyWithPlugin(registry_key, plugin)

        number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
            "event_data"
        )
        self.assertEqual(number_of_event_data, 2)

        expected_event_values = {
            "action": "Removed",
            "action_code": 3,
            "threat_identifier": 1234,
        }
        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 0)
        self.CheckEventData(event_data, expected_event_values)

        expected_event_values = {
            "action": "Allowed",
            "action_code": 6,
            "threat_identifier": 5678,
        }
        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 1)
        self.CheckEventData(event_data, expected_event_values)

    def testProcessNumberedValues(self):
        """Tests parsing records stored in numbered Registry values."""
        last_written_time = self._CreateFiletime("2018-02-06 08:30:00")
        registry_key = self._CreateRegistryKey(
            "Microsoft\\Windows Defender\\Detection History", last_written_time
        )

        self._AddStringValue(registry_key, "ThreatName0", "Adware:Win32/InstallCore")
        self._AddStringValue(
            registry_key, "Path0", "C:\\Users\\testuser\\Downloads\\setup.exe"
        )
        self._AddDwordValue(registry_key, "Action0", 2)

        self._AddStringValue(registry_key, "ThreatName1", "Virus:DOS/EICAR_Test_File")
        self._AddStringValue(
            registry_key, "Path1", "C:\\Users\\testuser\\Downloads\\eicar.com"
        )
        self._AddDwordValue(registry_key, "Action1", 3)

        plugin = windefender.WindowsDefenderRegistryPlugin()
        storage_writer = self._ParseKeyWithPlugin(registry_key, plugin)

        number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
            "event_data"
        )
        self.assertEqual(number_of_event_data, 2)

        expected_event_values = {
            "action": "Quarantined",
            "action_code": 2,
            "path": "C:\\Users\\testuser\\Downloads\\setup.exe",
            "threat_name": "Adware:Win32/InstallCore",
        }
        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 0)
        self.CheckEventData(event_data, expected_event_values)

        expected_event_values = {
            "action": "Removed",
            "action_code": 3,
            "path": "C:\\Users\\testuser\\Downloads\\eicar.com",
            "threat_name": "Virus:DOS/EICAR_Test_File",
        }
        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 1)
        self.CheckEventData(event_data, expected_event_values)


if __name__ == "__main__":
    unittest.main()
