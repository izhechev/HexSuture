"""Exercise scan and detection reports with synthetic Windows event XML."""

import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
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


    def test_review_hash_detects_replacement_and_preserves_export_evidence(self):
        file = (self.root.resolve() / "private-benign.txt")
        original = b"ordinary document"
        file.write_bytes(original)
        fields = {"Detection ID": DETECTION, "Threat Name": "Test:Win32/BenignFixture",
                  "Path": f"file:_{file}", "Private Field": "original source evidence"}
        self.event(1116, 1, fields)
        report = json.loads(self.cli("show"))
        finding_id = report["detections"][0]["findingId"]
        self.assertEqual(report["reviewQueue"][0]["status"], "open")

        until = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.cli("review", finding_id, "benign", "--file", file, "--until", until,
                 "--reviewer", "lab-reviewer", "--reason", "known benign text")
        pending = json.loads(self.cli("show"))["reviewQueue"][0]
        self.assertEqual(pending["status"], "verification-required")
        checked = json.loads(self.cli("show", "--check-file", file))
        self.assertEqual(checked["reviewQueue"][0]["status"], "reviewed")
        self.assertEqual(checked["reviews"][0]["artifactSha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(checked["reviews"][0]["reviewer"], "lab-reviewer")
        self.assertEqual(checked["reviews"][0]["reason"], "known benign text")

        file.write_bytes(b"replacement text")
        changed = json.loads(self.cli("show", "--check-file", file))["reviewQueue"][0]
        self.assertEqual(changed["status"], "file-changed")
        self.assertTrue(changed["needsReview"])
        file.unlink()
        absent = json.loads(self.cli("show", "--check-file", file))["reviewQueue"][0]
        self.assertEqual(absent["status"], "file-unavailable")

        redacted = self.cli("export")
        self.assertNotIn("private-benign.txt", redacted)
        self.assertNotIn("lab-reviewer", redacted)
        self.assertNotIn("original source evidence", redacted)
        evidence = json.loads(self.cli("export", "--include-evidence"))
        self.assertEqual(evidence["observations"][0]["facts"], fields)
        self.assertEqual(evidence["reviews"][0]["findingId"], finding_id)
        self.assertEqual(evidence["reviewQueue"][0]["recordId"], 1)

    def test_expiry_reopens_review_and_new_occurrence_stays_open(self):
        self.event(1116, 1, {"Detection ID": DETECTION})
        finding_id = json.loads(self.cli("show"))["reviewQueue"][0]["findingId"]
        deadline = datetime.now(timezone.utc) + timedelta(seconds=5)
        self.cli("review", finding_id, "benign", "--until", deadline.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "--reviewer", "test", "--reason", "Known fixture")
        self.assertEqual(json.loads(self.cli("show"))["reviewQueue"][0]["status"], "reviewed")
        self.event(1116, 2, {"Detection ID": OTHER_DETECTION})
        time.sleep(max(0, (deadline - datetime.now(timezone.utc)).total_seconds()))
        queue = json.loads(self.cli("show"))["reviewQueue"]
        self.assertEqual([row["status"] for row in queue], ["expired", "open"])

    def test_occurrence_decisions_and_invalid_requests(self):
        self.event(1116, 1, {})
        self.event(1117, 2, {"Detection ID": OTHER_DETECTION})
        queue = json.loads(self.cli("show"))["reviewQueue"]
        self.assertEqual(len(queue), 1)
        finding_id = queue[0]["findingId"]
        for decision in ("malicious", "uncertain"):
            self.cli("review", finding_id, decision, "--reviewer", "test", "--reason", "Manual review")
        report = json.loads(self.cli("show"))
        self.assertEqual(report["reviewQueue"][0]["status"], "uncertain")
        self.assertEqual([row["decision"] for row in report["reviews"]], ["malicious", "uncertain"])
        for extras in (["--file", "test.txt"], ["--until", "2020-01-01T00:00:00Z"]):
            result = subprocess.run(["dotnet", str(self.dll), "review", str(self.case), finding_id,
                                     "benign", "--reviewer", "test", "--reason", "test", *extras],
                                    capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(json.loads(self.cli("show"))["reviews"]), 2)


    def test_fileless_timeline_requires_matched_success(self):
        evidence = {"Detection ID": DETECTION, "Source ID": "2", "Source Name": "System",
                    "Threat ID": "2147694217", "Threat Name": "Virus:Win32/MpTest!amsi",
                    "Process Name": r"C:\Users\lab-user\powershell.exe",
                    "Path": "amsi:_private-resource", "ScriptBlockText": "private script text"}
        action = {"Detection ID": DETECTION, "Threat ID": "2147694217", "Action ID": "2"}

        def finding():
            report = json.loads(self.cli("show"))
            self.assertEqual(report["filelessMemoryCoverage"], "unknown")
            item, = report["fileless"]
            self.assertEqual((item["mode"], item["source"], item["kind"]), ("replay", "system-initiated", "amsi"))
            self.assertEqual(item["processName"], "powershell.exe")
            self.assertIsNone(item["processPath"])
            self.assertNotIn("private script text", json.dumps(item))
            return item

        self.event(1117, 1, action)
        self.event(1116, 2, evidence)
        self.assertEqual(finding()["status"], "open")
        self.event(1117, 3, {**action, "Action ID": "6"})
        self.assertEqual((finding()["remediation"], finding()["status"]), ("unremediated", "open"))
        self.event(1118, 4, action)
        self.assertEqual((finding()["remediation"], finding()["status"]), ("failed", "open"))
        self.event(1117, 5, action, device="OTHER-PC")
        self.event(1117, 6, {**action, "Detection ID": OTHER_DETECTION})
        self.event(1117, 7, {**action, "Threat ID": "42"})
        self.assertEqual(finding()["status"], "open")
        self.event(1117, 8, {**action, "Status Code": "3", "Error Code": "0x00000000"})
        self.assertEqual((finding()["remediation"], finding()["status"]), ("remediated", "closed"))
        self.assertEqual([row["recordId"] for row in finding()["timeline"]], [2, 3, 4, 8])
        self.event(1116, 9, evidence)
        self.assertEqual((finding()["remediation"], finding()["status"]), ("unknown", "open"))

    def test_behavior_evidence_and_ordinary_powershell(self):
        self.event(1116, 1, {"Process Name": "powershell.exe", "Threat Name": "Virus:Win32/Generic"})
        self.event(1015, 2, {"Detection ID": DETECTION, "Process Name": "powershell.exe",
                             "Threat Name": "Behavior:Win32/SyntheticFixture"})
        self.event(1117, 3, {"Detection ID": DETECTION, "Action ID": "10"})
        finding, = json.loads(self.cli("show"))["fileless"]
        self.assertEqual((finding["kind"], finding["remediation"], finding["status"]),
                         ("behavior", "blocked", "open"))
        self.assertEqual([row["eventId"] for row in finding["timeline"]], [1015, 1117])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path, nargs="?", default=ScanEvidenceTests.dll)
    args = parser.parse_args()
    if not args.dll.is_file():
        parser.error(f"Build HexSuture first or pass the path to its DLL: {args.dll}")
    ScanEvidenceTests.dll = args.dll.resolve()
    unittest.main(argv=[__file__], verbosity=2)
