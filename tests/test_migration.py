"""Verify that milestone 1 case files survive the upgrade to live scans."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from test_replay import ROOT, SAMPLE


V1_SCHEMA = """
PRAGMA application_id = 0x48585355;
PRAGMA user_version = 1;
CREATE TABLE observations (
    device TEXT NOT NULL COLLATE NOCASE,
    channel TEXT NOT NULL COLLATE NOCASE,
    provider TEXT NOT NULL COLLATE NOCASE,
    record_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    occurred_utc TEXT NOT NULL,
    facts_json TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'replay' CHECK (origin = 'replay'),
    PRIMARY KEY (device, channel, provider, record_id, occurred_utc)
);
CREATE TABLE source_gaps (
    source_name TEXT NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (source_name, reason)
);
INSERT INTO observations VALUES (
    'OLD-PC', 'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-Windows Defender', 7, 1000, '2026-11-18T08:00:00.0000000Z',
    '{}', 'replay'
);
INSERT INTO source_gaps VALUES ('old.xml', 'Source is missing.');
"""


class MigrationTests(unittest.TestCase):
    dll = ROOT / "src/HexSuture/bin/Debug/net10.0/HexSuture.dll"

    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.case = Path(workspace.name) / "case.db"
        with closing(sqlite3.connect(self.case)) as db:
            db.executescript(V1_SCHEMA)

    def cli(self, *args):
        return subprocess.run(
            ["dotnet", str(self.dll), *map(str, args)],
            capture_output=True, text=True, encoding="utf-8", check=True, timeout=45,
        ).stdout

    def test_read_v1_without_migration(self):
        original = self.case.read_bytes()
        report = json.loads(self.cli("show", self.case))
        self.assertEqual(self.case.read_bytes(), original)
        self.assertEqual(report["scanRequests"], [])
        self.assertEqual([event["mode"] for event in report["observations"]], ["replay"])
        self.assertEqual(report["sourceGaps"][0]["sourceName"], "old.xml")

    def test_concurrent_migration_and_distinct_origins(self):
        def import_sample():
            self.cli("import", self.case, SAMPLE)

        with ThreadPoolExecutor(max_workers=3) as workers:
            jobs = [workers.submit(import_sample) for _ in range(3)]
            for job in jobs:
                job.result()

        with closing(sqlite3.connect(self.case)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 5)
            self.assertEqual(db.execute("SELECT count(*) FROM observations").fetchone()[0], 2)
            # Seed a synthetic live record so this compatibility test works without Defender.
            db.execute("UPDATE observations SET origin = 'live' WHERE record_id = 42")
            db.commit()

        import_sample()
        import_sample()
        report = json.loads(self.cli("show", self.case))
        identities = sorted((event["recordId"], event["mode"]) for event in report["observations"])
        self.assertEqual(identities, [(7, "replay"), (42, "live"), (42, "replay")])
        self.assertEqual(report["sourceGaps"], [{"sourceName": "old.xml", "reason": "Source is missing."}])


    def test_v2_scan_requests_survive_review_upgrade(self):
        self.cli("import", self.case, SAMPLE)
        with closing(sqlite3.connect(self.case)) as db:
            db.executescript("""
                DROP TABLE reviews;
                DROP TABLE startup_snapshots;
                DROP TABLE task_reviews;
                DROP TABLE fileless_followups;
                PRAGMA user_version = 2;
                INSERT INTO scan_requests (id, device, kind, requested_utc)
                VALUES ('sample-request', 'LAB-PC', 'quick', '2026-11-20T12:00:00Z');
            """)
        original = self.case.read_bytes()
        report = json.loads(self.cli("show", self.case))
        self.assertEqual(self.case.read_bytes(), original)
        self.assertEqual(report["scanRequests"][0]["requestId"], "sample-request")
        self.assertEqual(report["reviews"], [])
        self.cli("import", self.case, SAMPLE)
        updated = json.loads(self.cli("show", self.case))
        self.assertEqual(updated["scanRequests"], report["scanRequests"])
        self.assertEqual(updated["observations"], report["observations"])
        with closing(sqlite3.connect(self.case)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 5)


    def test_startup_inventory_diff_keeps_legitimate_and_unfamiliar_entries(self):
        baseline = self.case.parent / "baseline.csv"
        current = self.case.parent / "current.csv"
        common = ["Task Scheduler", "enabled", "Scheduled Tasks", "FixtureUser"]

        def write_snapshot(path, rows):
            with path.open("w", encoding="utf-16", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["Time", "Entry Location", "Entry", "Enabled", "Category",
                                 "Profile", "Signer", "Launch String"])
                for stamp, name, signer, command in rows:
                    writer.writerow([stamp, common[0], name, *common[1:], signer, command])

        write_snapshot(baseline, [("day 1", "Updater", "Example Vendor", "update.exe /old"),
                                  ("day 1", "Removed", "", "old.exe"),
                                  ("day 1", "Stable", "", "stable.exe")])
        write_snapshot(current, [("day 2", "Updater", "Example Vendor", 'update.exe "new, version"'),
                                 ("day 2", "Harmless test task", "", "fixture.exe"),
                                 ("day 2", "Stable", "", "stable.exe")])

        for slot, path in (("baseline", baseline), ("current", current)):
            subprocess.run(["dotnet", str(self.dll), "startup", "import", str(self.case), slot,
                            str(path), "--device", "LAB-PC", "--scope", "user-tasks"],
                           check=True, capture_output=True, timeout=30)
        command = ["dotnet", str(self.dll), "startup", "diff", str(self.case)]
        report = json.loads(subprocess.check_output(command, encoding="utf-8", timeout=30))
        changes = {(row["after"] or row["before"])["name"]: row for row in report["changes"]}
        self.assertEqual({name: row["status"] for name, row in changes.items()},
                         {"Updater": "changed", "Removed": "removed", "Harmless test task": "added"})
        self.assertEqual(changes["Updater"]["after"]["facts"]["signer"], "Example Vendor")
        self.assertEqual(changes["Updater"]["after"]["facts"]["launch string"], 'update.exe "new, version"')
        subprocess.run(["dotnet", str(self.dll), "startup", "import", str(self.case), "current",
                        str(current), "--device", "OTHER-PC", "--scope", "user-tasks"],
                       check=True, capture_output=True, timeout=30)
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same device", result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", nargs="?", type=Path, default=MigrationTests.dll)
    args = parser.parse_args()
    if not args.dll.is_file():
        parser.error(f"Could not find the built HexSuture DLL at {args.dll}")
    MigrationTests.dll = args.dll.resolve()
    unittest.main(argv=[__file__], verbosity=2)
