"""Exercise scan and detection reports with synthetic Windows event XML."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "Microsoft-Windows-Windows Defender"
CHANNEL = PROVIDER + "/Operational"
SCAN = "10000000-0000-4000-a000-000000000001"
OTHER_SCAN = "10000000-0000-4000-a000-000000000002"
DETECTION = "20000000-0000-4000-a000-000000000001"
OTHER_DETECTION = "20000000-0000-4000-a000-000000000002"


class ScanEvidenceTests(unittest.TestCase):
    dll = Path(os.environ.get("HEXSUTURE_DLL", ROOT / "src/HexSuture/bin/Debug/net10.0/HexSuture.dll"))

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.case = self.root / "case.db"

    def cli(self, command, *args):
        result = subprocess.run(["dotnet", str(self.dll), command, str(self.case), *map(str, args)],
                                capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def event(self, event_id, record_id, fields, device="LAB-PC"):
        root = ET.Element("Event", xmlns="http://schemas.microsoft.com/win/2004/08/events/event")
        system = ET.SubElement(root, "System")
        ET.SubElement(system, "Provider", Name=PROVIDER)
        ET.SubElement(system, "TimeCreated", SystemTime=f"2026-11-20T08:10:{record_id:02d}Z")
        for name, value in (("EventID", event_id), ("EventRecordID", record_id), ("Computer", device),
                            ("Channel", CHANNEL)):
            ET.SubElement(system, name).text = str(value)
        payload = ET.SubElement(root, "EventData")
        for name, value in fields.items():
            ET.SubElement(payload, "Data", Name=name).text = value
        source = self.root / f"event-{record_id}.xml"
        ET.ElementTree(root).write(source, encoding="utf-8", xml_declaration=True)
        self.cli("import", source)

    def test_overlapping_scans_with_different_terminal_events(self):
        self.event(1000, 1, {"Scan ID": "{" + SCAN.upper() + "}", "Scan Parameters": "%%807"})
        self.event(1000, 2, {"Scan ID": OTHER_SCAN, "Scan Parameters": "Quick Scan"})
        self.event(1002, 3, {"Scan ID": OTHER_SCAN})
        self.event(1001, 4, {"Scan ID": SCAN})
        scans = {scan["scanId"]: scan for scan in json.loads(self.cli("show"))["scans"]}
        self.assertEqual((scans[SCAN]["kind"], scans[SCAN]["status"]), ("custom", "completed"))
        self.assertEqual((scans[OTHER_SCAN]["kind"], scans[OTHER_SCAN]["status"]), ("quick", "stopped"))
        self.assertEqual(scans[SCAN]["recordIds"], [1, 4])
        self.assertEqual(scans[OTHER_SCAN]["recordIds"], [2, 3])

    def test_real_time_eicar_detection_precedes_scan(self):
        fields = {"Detection ID": DETECTION, "Threat Name": "Virus:DOS/EICAR_Test_File",
                  "Threat ID": "2147519003", "Source ID": "3", "Source Name": "%%818",
                  "Security intelligence Version": "AV: 1.2.3.4, AS: 1.2.3.4",
                  "Engine Version": "AM: 1.2.3.4, NIS: 1.2.3.4"}
        self.event(1116, 1, fields)
        self.event(1117, 2, {"Detection ID": DETECTION, "Action ID": "2", "Error Code": "0x00000000"})
        self.event(1000, 3, {"Scan ID": SCAN, "Scan Parameters": "Full Scan"})
        self.event(1001, 4, {"Scan ID": SCAN})
        report = json.loads(self.cli("show"))
        detection, = report["detections"]
        scan, = report["scans"]
        self.assertEqual((detection["source"], detection["threatName"]), ("real-time", fields["Threat Name"]))
        self.assertLess(detection["detectedUtc"], scan["startedUtc"])
        self.assertEqual((detection["action"], detection["actionStatus"]), ("quarantine", "remediated"))
        self.assertEqual(detection["signatureVersion"], fields["Security intelligence Version"])
        self.assertEqual(detection["engineVersion"], fields["Engine Version"])
        self.assertEqual(scan["kind"], "full")

    def test_missing_ids_and_distinct_devices_cannot_link_actions(self):
        self.event(1116, 1, {"Detection ID": DETECTION, "Source ID": "1"})
        self.event(1117, 2, {"Detection ID": DETECTION, "Action Name": "Clean"}, "SECOND-PC")
        self.event(1117, 3, {"Detection ID": OTHER_DETECTION, "Action Name": "Remove"})
        self.event(1116, 4, {})
        self.event(1117, 5, {"Action Name": "Quarantine"})
        evidence = json.loads(self.cli("show"))["detections"]
        self.assertEqual(len(evidence), 5)
        detected = [row for row in evidence if row["detectedUtc"] is not None]
        self.assertCountEqual([row["source"] for row in detected], ["user-initiated", "unknown"])
        self.assertTrue(all(row["action"] is None for row in detected))
        self.assertTrue(all(len(row["recordIds"]) == 1 for row in evidence))

    def test_equal_ids_from_live_and_replay_stay_separate(self):
        self.event(1116, 1, {"Detection ID": DETECTION})
        self.event(1117, 2, {"Detection ID": DETECTION, "Action ID": "2"})
        # Simulate the provenance assigned by the live collector without scanning the host.
        with closing(sqlite3.connect(self.case)) as connection:
            connection.execute("UPDATE observations SET origin = 'live' WHERE event_id = 1117")
            connection.commit()
        evidence = {row["mode"]: row for row in json.loads(self.cli("show"))["detections"]}
        self.assertIsNone(evidence["replay"]["action"])
        self.assertIsNone(evidence["live"]["detectedUtc"])

    def test_actions_distinguish_allow_block_and_failure(self):
        self.event(1116, 1, {"Detection ID": DETECTION})
        self.event(1117, 2, {"Detection ID": DETECTION, "Action ID": "6"})
        self.event(1117, 3, {"Detection ID": DETECTION, "Action Name": "Block"})
        self.event(1118, 4, {"Detection ID": DETECTION, "Action ID": "2"})
        self.event(1119, 5, {"Detection ID": DETECTION, "Action Name": "Clean"})
        detection, = json.loads(self.cli("show"))["detections"]
        self.assertEqual(detection["actionStatus"], "failed")
        self.assertEqual([item["actionStatus"] for item in detection["actions"]],
                         ["unremediated", "blocked", "failed", "failed"])

    def test_remediation_uses_defender_threat_status(self):
        self.event(1116, 1, {"Detection ID": DETECTION})
        for record, status, additional in [(2, "103", "0"), (3, "3", "8"), (4, "3", "0"), (5, "1", "0")]:
            self.event(1117, record, {"Detection ID": DETECTION, "Action ID": "2", "Status Code": status,
                                      "Error Code": "0x00000000", "Additional Actions ID": additional})
        detection, = json.loads(self.cli("show"))["detections"]
        self.assertEqual([item["actionStatus"] for item in detection["actions"]],
                         ["failed", "follow-up-required", "remediated", "unknown"])

    def test_sensitive_field_values_stay_out_of_report(self):
        marker = r"C:\Users\private-fixture\name.txt"
        self.event(1116, 1, {"Detection ID": DETECTION, "Threat Name": marker, "Path": marker,
                             "Source Name": marker, "Engine Version": marker, "Signature Version": marker})
        self.event(1117, 2, {"Detection ID": DETECTION, "Action Name": marker})
        report = self.cli("show")
        self.assertNotIn("private-fixture", report)
        detection, = json.loads(report)["detections"]
        self.assertIsNone(detection.get("resources"))
        detailed, = json.loads(self.cli("show", "--paths"))["detections"]
        self.assertEqual(detailed["resources"], [marker])
        self.assertIsNone(detection["threatName"])
        self.assertEqual(detection["source"], "unknown")
        self.assertEqual(detection["actionStatus"], "unknown")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path, nargs="?", default=ScanEvidenceTests.dll)
    args = parser.parse_args()
    if not args.dll.is_file():
        parser.error(f"Build HexSuture first or pass the path to its DLL: {args.dll}")
    ScanEvidenceTests.dll = args.dll.resolve()
    unittest.main(argv=[__file__], verbosity=2)
