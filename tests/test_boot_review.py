"""Check boot evidence, scheduling and post-restart outcome labels."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SAMPLES = Path(__file__).resolve().parents[1] / "samples"


class BootReviewTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.case = self.root / "boot.db"

    def cli(self, *args, success=True):
        completed = subprocess.run(["dotnet", str(self.dll), *map(str, args)],
                                   capture_output=True, text=True, encoding="utf-8", timeout=35)
        self.assertEqual(completed.returncode == 0, success, completed.stderr or completed.stdout)
        return json.loads(completed.stdout) if completed.stdout.lstrip().startswith("{") else completed.stderr

    def show(self):
        return self.cli("show", self.case)["boot"]

    def test_scheduled_scan_requires_a_restart_and_explicit_result(self):
        baseline = SAMPLES / "boot-baseline.json"
        self.cli("boot", "import-state", self.case, baseline, "--baseline")
        self.cli("boot", "import-state", self.case, baseline)
        self.cli("import", self.case, SAMPLES / "boot-finding.xml")
        self.cli("import", self.case, SAMPLES / "offline-scheduled.xml")
        report = self.show()
        self.assertEqual(report["firmwareIntegrity"], "unverified")
        self.assertEqual(report["devices"][0]["configurationStatus"], "matches-baseline")
        self.assertEqual(report["findings"][0]["kind"], "rootkit")
        self.assertEqual(report["findings"][0]["source"], "elam")
        scheduled, = report["offlineScans"]
        self.assertEqual((scheduled["mode"], scheduled["status"], scheduled["needsReview"]),
                         ("replay", "scheduled", True))
        schedule_id = scheduled["scheduleId"]
        result = ["boot", "result", self.case, schedule_id, "completed-no-detections",
                  "--note", "Fictional Protection History result observed after reboot"]
        self.assertIn("after the scheduling event", self.cli(*result, success=False))

        self.cli("boot", "import-state", self.case, SAMPLES / "boot-after-restart.json")
        self.cli("import", self.case, SAMPLES / "scan-completed.xml")
        report = self.show()
        self.assertEqual(report["devices"][0]["configurationStatus"], "changed")
        self.assertEqual(report["offlineScans"][0]["status"], "outcome-unknown")
        self.assertTrue(report["offlineScans"][0]["needsReview"])
        self.cli(*result)
        final = self.show()
        scan = final["offlineScans"][0]
        self.assertEqual((scan["status"], scan["outcomeSource"], scan["needsReview"]),
                         ("completed-no-detections", "operator-supplied", False))
        self.assertEqual(final["firmwareIntegrity"], "unverified")
        self.assertTrue(final["findings"][0]["needsReview"])
        self.assertIn("already has", self.cli(*result, success=False))
        self.assertIsNone(self.cli("export", self.case)["boot"]["offlineScans"][0]["note"])
        self.assertIn("Fictional", self.cli("export", self.case, "--include-evidence")
                      ["boot"]["offlineScans"][0]["note"])

    def test_disabled_winre_and_failed_schedule_stay_open(self):
        path = self.root / "blocked.json"
        state = json.loads((SAMPLES / "boot-baseline.json").read_text())
        path.write_text(json.dumps({**state, "winRe": "disabled", "bitLocker": "protected"}))
        self.cli("boot", "import-state", self.case, path)
        failure = self.root / "schedule-failed.xml"
        failure.write_text((SAMPLES / "offline-scheduled.xml").read_text().replace(">2030<", ">2031<"))
        self.cli("import", self.case, failure)
        report = self.show()
        self.assertIn("Windows Recovery Environment is disabled.", report["devices"][0]["offlinePreflight"])
        self.assertTrue(any("BitLocker" in gap for gap in report["devices"][0]["offlinePreflight"]))
        self.assertEqual(report["offlineScans"], [])
        self.assertEqual(report["schedulingFailures"][0]["status"], "schedule-failed")
        self.assertTrue(report["schedulingFailures"][0]["needsReview"])

        self.cli("import", self.case, self.root / "unreadable.xml", success=False)
        self.assertTrue(self.cli("show", self.case)["sourceGaps"])

    def test_replayed_schedule_needs_matching_device(self):
        self.cli("import", self.case, SAMPLES / "offline-scheduled.xml")
        path = self.root / "different-device.json"
        state = json.loads((SAMPLES / "boot-after-restart.json").read_text())
        path.write_text(json.dumps({**state, "device": "OTHER-LAB"}))
        self.cli("boot", "import-state", self.case, path)
        scan, = self.show()["offlineScans"]
        self.assertEqual(scan["schedulingStatus"], "scheduled")
        self.assertEqual(scan["status"], "outcome-unknown")
        self.assertIn("after the scheduling event",
                      self.cli("boot", "result", self.case, scan["scheduleId"], "completed-detected",
                               "--note", "Wrong device", success=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    args = parser.parse_args()
    BootReviewTests.dll = args.dll.resolve()
    unittest.main(argv=[__file__], verbosity=2)
