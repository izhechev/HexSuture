"""Check ransomware evidence and hash-verified recovery with harmless files."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


PROVIDER = "Microsoft-Windows-Windows Defender"


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.case = self.root / "case.db"

    def cli(self, *args, success=True):
        result = subprocess.run(["dotnet", str(self.dll), *map(str, args)],
                                capture_output=True, text=True, encoding="utf-8", timeout=40)
        self.assertEqual(result.returncode == 0, success, result.stderr or result.stdout)
        return json.loads(result.stdout) if result.stdout.lstrip().startswith("{") else result.stderr

    def manifest(self, files):
        path = self.root / "trusted-manifest.json"
        path.write_text(json.dumps({"backupVersion": "before-incident", "files": files}), encoding="utf-8")
        return path

    def create_backup(self, count=20):
        backup = self.root / "backup"
        backup.mkdir()
        files = []
        originals = {}
        for number in range(count):
            name = f"documents/file-{number:02}.txt"
            content = f"Ordinary document {number}\n".encode()
            path = backup / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
            originals[name] = content
            files.append({"path": name, "sha256": hashlib.sha256(content).hexdigest()})
        return backup, originals, self.manifest(files)

    def event(self, record_id, event_id, fields, seconds=None, device="LAB-PC"):
        root = ET.Element("Event", xmlns="http://schemas.microsoft.com/win/2004/08/events/event")
        system = ET.SubElement(root, "System")
        ET.SubElement(system, "Provider", Name=PROVIDER)
        stamp = datetime(2026, 11, 20, 10, tzinfo=timezone.utc) + timedelta(
            seconds=record_id if seconds is None else seconds)
        ET.SubElement(system, "TimeCreated", SystemTime=stamp.strftime("%Y-%m-%dT%H:%M:%SZ"))
        for name, value in (("EventID", event_id), ("EventRecordID", record_id),
                            ("Computer", device), ("Channel", PROVIDER + "/Operational")):
            ET.SubElement(system, name).text = str(value)
        payload = ET.SubElement(root, "EventData")
        for name, value in fields.items():
            ET.SubElement(payload, "Data", Name=name).text = value
        file = self.root / f"record-{record_id}.xml"
        ET.ElementTree(root).write(file, encoding="utf-8", xml_declaration=True)
        self.cli("import", self.case, file)

    def test_cfa_reports_attempts_and_only_links_related_defender_evidence(self):
        self.event(111, 1001, {"Scan Parameters": "Full Scan"})
        for number in range(20):
            (self.root / f"ordinary-{number}.txt").write_text("Ordinary edit", encoding="utf-8")
        benign = self.cli("show", self.case)["ransomware"]
        self.assertEqual(benign["suspiciousBursts"], [])
        self.assertEqual(benign["coverage"], "unknown")

        process = r"C:\Users\private-lab\editor.exe"
        for number in range(1, 10):
            self.event(number, 1124, {"Process Name": process, "Path": f"C:\\Docs\\{number}.txt"})
        self.event(10, 1123, {"Process Name": process, "Path": r"C:\DOCS\1.TXT"})
        self.event(11, 1123, {"Process Name": r"C:\other.exe", "Path": r"C:\Docs\11.txt"})
        self.event(12, 1124, {"Process Name": process, "Path": r"C:\Docs\11.txt"}, seconds=90)
        self.assertEqual(self.cli("show", self.case)["ransomware"]["suspiciousBursts"], [])

        self.event(13, 1123, {"Process Name": process, "Path": r"C:\Docs\10.txt"}, seconds=30)
        ransomware = {"Process Name": process, "Threat Name": "Ransom:Win32/SyntheticFixture"}
        self.event(14, 1116, ransomware, seconds=31)
        self.event(15, 1116, ransomware, seconds=31, device="OTHER-PC")
        self.event(16, 1116, {**ransomware, "Process Name": r"D:\Unrelated\editor.exe"}, seconds=31)
        report = self.cli("show", self.case)["ransomware"]
        self.assertEqual(len(report["writeAttempts"]), 13)
        burst, = report["suspiciousBursts"]
        self.assertEqual((burst["status"], burst["distinctPaths"]), ("suspicious-writes", 10))
        self.assertEqual((burst["audited"], burst["blocked"]), (9, 2))
        self.assertEqual(burst["relatedRansomwareRecordIds"], [14])
        self.assertNotIn("private-lab", json.dumps(report))
        shown = self.cli("show", self.case, "--paths")["ransomware"]
        self.assertEqual(shown["writeAttempts"][0]["processPath"], process)

    def test_twenty_files_then_corrupt_backup_copy(self):
        backup, originals, manifest = self.create_backup()
        restored = self.root / "restored"
        result = self.cli("recover", self.case, backup, manifest, restored)
        self.assertEqual((result["matched"], result["requested"], result["status"]), (20, 20, "verified"))
        self.assertIsInstance(result["elapsedMilliseconds"], int)
        for path, expected in originals.items():
            self.assertEqual((backup / path).read_bytes(), expected)
            self.assertEqual((restored / path).read_bytes(), expected)

        damaged = "documents/file-04.txt"
        (backup / damaged).write_bytes(b"Altered backup copy")
        different = self.root / "second-restore"
        result = self.cli("recover", self.case, backup, manifest, different, success=False)
        self.assertEqual((result["matched"], result["mismatches"], result["status"]), (19, 1, "incomplete"))
        self.assertFalse((different / damaged).exists())
        self.assertEqual((restored / damaged).read_bytes(), originals[damaged])
        self.assertEqual((backup / damaged).read_bytes(), b"Altered backup copy")
        mismatch, = [item for item in result["items"] if item["status"] == "hash-mismatch"]
        self.assertEqual(mismatch["path"], damaged)
        self.assertNotEqual(mismatch["actualSha256"], mismatch["expectedSha256"])
        redacted = self.cli("export", self.case)["recoveryRuns"]
        self.assertEqual([run["matched"] for run in redacted], [20, 19])
        self.assertIsNone(redacted[1]["destination"])
        self.assertTrue(all(item["path"] is None for item in redacted[1]["items"]))

    def test_missing_backup_and_destination_conflicts(self):
        backup, originals, manifest = self.create_backup(2)
        existing = self.root / "existing"
        existing.mkdir()
        marker = existing / "file-00.txt"
        marker.write_bytes(b"keep existing content")
        self.assertIn("existing path was preserved",
                      self.cli("recover", self.case, backup, manifest, existing, success=False))
        self.assertEqual(marker.read_bytes(), b"keep existing content")

        unavailable = self.root / "unavailable"
        result = self.cli("recover", self.case, self.root / "missing", manifest, unavailable, success=False)
        self.assertEqual(result["unavailable"], 2)
        self.assertFalse(unavailable.exists())

        missing = "documents/file-00.txt"
        (backup / missing).unlink()
        target = self.root / "retry-target"
        partial = self.cli("recover", self.case, backup, manifest, target, success=False)
        self.assertEqual((partial["missing"], partial["matched"]), (1, 1))
        self.assertFalse((target / missing).exists())

        (backup / missing).write_bytes(originals[missing])
        occupied = target / missing
        occupied.write_bytes(b"leave this alone")
        resumed = self.cli("recover", self.case, backup, manifest, target, success=False)
        self.assertEqual(resumed["id"], partial["id"])
        self.assertEqual(resumed["destinationConflicts"], 1)
        self.assertEqual(occupied.read_bytes(), b"leave this alone")

    def test_traversal_and_symlink_copies_are_refused(self):
        backup, _, _ = self.create_backup(1)
        destination = self.root / "restore"
        manifest = self.manifest([{"path": "../escape.txt", "sha256": "0" * 64}])
        self.assertIn("unsafe relative path",
                      self.cli("recover", self.case, backup, manifest, destination, success=False))
        self.assertFalse(destination.exists())
        self.assertFalse((self.root / "escape.txt").exists())

        outside = self.root / "outside.txt"
        outside.write_bytes(b"outside backup")
        link = backup / "linked.txt"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("This Windows account cannot create a symbolic link.")
        manifest = self.manifest([{"path": "linked.txt", "sha256": hashlib.sha256(outside.read_bytes()).hexdigest()}])
        rejected = self.cli("recover", self.case, backup, manifest, destination, success=False)
        self.assertEqual(rejected["unsafePaths"], 1)
        self.assertFalse((destination / "linked.txt").exists())
        self.assertEqual(outside.read_bytes(), b"outside backup")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    args = parser.parse_args()
    RecoveryTests.dll = args.dll.resolve()
    unittest.main(argv=[__file__], verbosity=2)
