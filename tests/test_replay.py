"""Run the replay acceptance tests against a built HexSuture DLL."""

import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "scan-completed.xml"


class ReplayTests(unittest.TestCase):
    dll = Path(os.environ.get("HEXSUTURE_DLL", ROOT / "src/HexSuture/bin/Debug/net10.0/HexSuture.dll"))

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.case = self.folder / "case.db"

    def cli(self, *args, success=True):
        result = subprocess.run(
            ["dotnet", str(self.dll.resolve()), *map(str, args)],
            cwd=self.folder,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def show(self):
        return json.loads(self.cli("show", self.case).stdout)

    def test_reimport_after_restart_and_rename(self):
        self.cli("import", self.case, SAMPLE)
        self.cli("import", self.case, SAMPLE)
        renamed = self.folder / "renamed.xml"
        shutil.copyfile(SAMPLE, renamed)
        self.cli("import", self.case, renamed)
        renamed.unlink()

        report = self.show()
        self.assertEqual(report["sourceGaps"], [])
        self.assertEqual(len(report["observations"]), 1)
        event = report["observations"][0]
        self.assertEqual(event["mode"], "replay")
        self.assertEqual(event["eventId"], 1001)
        self.assertEqual(event["recordId"], 42)
        self.assertEqual(event["device"], "LAB-PC")
        self.assertRegex(event["occurredUtc"], r"^2026-11-20T09:10:11\.1250*(Z|\+00:00)$")
        self.assertEqual(event["facts"]["Scan Parameters"], "Custom Scan")

    def test_missing_unreadable_and_malformed_sources(self):
        missing = self.folder / "missing.xml"
        unreadable = self.folder / "directory.xml"
        unreadable.mkdir()
        malformed = self.folder / "malformed.xml"
        malformed.write_text("<Event>", encoding="utf-8")

        for source in (missing, unreadable, malformed):
            with self.subTest(source=source.name):
                self.cli("import", self.case, source, success=False)

        report = self.show()
        self.assertEqual(report["observations"], [])
        gaps = {Path(gap["sourceName"]).name: gap["reason"] for gap in report["sourceGaps"]}
        self.assertEqual(set(gaps), {missing.name, unreadable.name, malformed.name})
        for reason in gaps.values():
            self.assertTrue(reason.strip())

    def test_conflicting_evidence_keeps_the_original(self):
        self.cli("import", self.case, SAMPLE)
        original = self.show()["observations"]
        changed = ET.parse(SAMPLE)
        changed.find(".//{*}Data[@Name='Scan Time']").text = "00:00:59"
        edited = self.folder / "edited.xml"
        changed.write(edited, encoding="utf-8", xml_declaration=True)
        self.cli("import", self.case, edited, success=False)
        self.assertEqual(self.show()["observations"], original)

    def test_report_omits_private_event_data(self):
        changed = ET.parse(SAMPLE)
        payload = changed.find(".//{*}EventData")
        field_tag = payload.find("{*}Data").tag
        private = {
            "User": r"EXAMPLE\test-reviewer",
            "ScriptBlockText": "Write-Output 'synthetic-script-mark'",
            "Scan Resources": r"C:\Users\test-reviewer\private-report.txt",
            "Unrecognized detail": "synthetic-private-mark",
        }
        for name, value in private.items():
            ET.SubElement(payload, field_tag, Name=name).text = value
        source = self.folder / "private-fields.xml"
        changed.write(source, encoding="utf-8", xml_declaration=True)
        self.cli("import", self.case, source)

        report = self.show()
        facts = report["observations"][0]["facts"]
        self.assertEqual(facts["Scan Parameters"], "Custom Scan")
        output = json.dumps(report)
        for name, value in private.items():
            with self.subTest(name=name):
                self.assertNotIn(name, facts)
                self.assertNotIn(json.dumps(value), output)

    def test_unrelated_sqlite_database_stays_unchanged(self):
        connection = sqlite3.connect(self.case)
        try:
            connection.execute("CREATE TABLE notes (body TEXT)")
            connection.execute("INSERT INTO notes VALUES ('synthetic note')")
            connection.commit()
        finally:
            connection.close()
        before = self.case.read_bytes()
        self.cli("import", self.case, SAMPLE, success=False)
        self.cli("show", self.case, success=False)
        self.assertEqual(self.case.read_bytes(), before)

    def test_dtd_is_rejected(self):
        source = self.folder / "doctype.xml"
        original = SAMPLE.read_text(encoding="utf-8")
        source.write_text(original.replace("<Event ", "<!DOCTYPE Event>\n<Event ", 1), encoding="utf-8")
        self.cli("import", self.case, source, success=False)
        report = self.show()
        self.assertEqual(report["observations"], [])
        self.assertEqual(len(report["sourceGaps"]), 1)
        self.assertEqual(Path(report["sourceGaps"][0]["sourceName"]).name, source.name)

    def test_show_missing_case_does_not_create_it(self):
        self.cli("show", self.case, success=False)
        self.assertFalse(self.case.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path, nargs="?", default=ReplayTests.dll)
    args = parser.parse_args()
    if not args.dll.is_file():
        parser.error(f"Build HexSuture first or pass the path to its DLL: {args.dll}")
    ReplayTests.dll = args.dll.resolve()
    unittest.main(argv=[__file__], verbosity=2)
