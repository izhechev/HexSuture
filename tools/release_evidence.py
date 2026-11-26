"""Build the HexSuture release evidence bundle from harmless fixtures."""

import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "Microsoft-Windows-Windows Defender"
DEVICE = "LAB-PC"
PRIVATE = "hexsuture-private-fixture"
PATH = rf"C:\Users\{PRIVATE}\Documents"
SCRIPT_DETECTION = "f173c0ac-40f0-44a1-8c50-8c75b4153211"
OPEN_DETECTION = "f173c0ac-40f0-44a1-8c50-8c75b4153212"
RUNNER_JOBS = {"windows-replay": "Windows Server 2025 x64", "live-defender": "Windows 11 Arm"}
LIMITS = [
    "Live capture of Microsoft's AMSI demonstration remains pending on a supported Defender for Endpoint machine.",
    "Full Defender Offline and restart verification remain pending on a supported Windows 11 x64 client.",
    "The post-restart scheduled-task removal test uses a simulated reboot.",
    "The ransomware write sequence uses replayed events; live coverage checks the Windows folder-protection setting.",
    "The case contains synthetic observations and cannot establish the health of a real device.",
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class EvidenceCase:
    def __init__(self, dll, directory):
        self.dll = dll
        self.directory = directory
        self.database = directory / "case.db"

    def run(self, *arguments, expected=0):
        result = subprocess.run(["dotnet", str(self.dll), *map(str, arguments)],
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        require(result.returncode == expected,
                f"Unexpected exit for {arguments[0]}: {result.returncode}. {result.stderr.strip()}")
        return result.stdout

    def event(self, record, event_id, fields):
        root = ET.Element("Event", xmlns="http://schemas.microsoft.com/win/2004/08/events/event")
        system = ET.SubElement(root, "System")
        ET.SubElement(system, "Provider", Name=PROVIDER)
        ET.SubElement(system, "TimeCreated", SystemTime=f"2026-11-20T10:00:{record - 100:02}Z")
        values = {"EventID": event_id, "EventRecordID": record, "Computer": DEVICE,
                  "Channel": f"{PROVIDER}/Operational"}
        for name, value in values.items():
            ET.SubElement(system, name).text = str(value)
        payload = ET.SubElement(root, "EventData")
        for name, value in fields.items():
            ET.SubElement(payload, "Data", Name=name).text = value
        file = self.directory / f"event-{record}.xml"
        ET.ElementTree(root).write(file, encoding="utf-8", xml_declaration=True)
        self.run("import", self.database, file)

    def review_fixture(self):
        samples = ROOT / "samples"
        self.run("import", self.database, samples / "scan-completed.xml")
        self.run("import", self.database, samples / "scan-completed.xml")
        self.run("import", self.database, samples / "benign-detection.xml")
        case = json.loads(self.run("show", self.database))
        finding, = case["reviewQueue"]
        expiry = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.run("review", self.database, finding["findingId"], "benign",
                 "--reviewer", PRIVATE, "--reason", f"Verified ordinary document in {PRIVATE}",
                 "--until", expiry, "--file", samples / "benign-note.txt")

    def replay_incident(self):
        for index, (detection_id, action) in enumerate(((SCRIPT_DETECTION, "2"), (OPEN_DETECTION, "6"))):
            fields = {"Detection ID": detection_id, "Source ID": "10",
                      "Threat Name": f"Trojan:Win32/ScriptFixture{index}",
                      "Process Name": rf"{PATH}\powershell.exe", "ScriptBlockText": f"{PRIVATE} sample marker"}
            self.event(101 + 2 * index, 1116, fields)
            self.event(102 + 2 * index, 1117, {"Detection ID": detection_id, "Action ID": action})
        for index in range(10):
            self.event(110 + index, 1124 if index < 6 else 1123,
                       {"Process Name": rf"{PATH}\writer.exe", "Path": rf"{PATH}\doc-{index:02}.txt"})
        self.event(120, 1116, {"Process Name": rf"{PATH}\writer.exe",
                              "Threat Name": "Ransom:Win32/WriteFixture", "Threat ID": "100"})
        samples = ROOT / "samples"
        self.run("boot", "import-state", self.database, samples / "boot-baseline.json", "--baseline")
        self.run("boot", "import-state", self.database, samples / "boot-after-restart.json")
        self.run("import", self.database, samples / "boot-finding.xml")
        self.run("import", self.database, samples / "offline-scheduled.xml")

    def startup_diff(self):
        header = ["Entry Location", "Entry", "Enabled", "Category", "Profile", "Signer", "Version"]
        updater = ["Task Scheduler", "Document Updater", "true", "Scheduled Tasks",
                   "Lab account", "Example Vendor", "1.0"]
        fixture = ["Task Scheduler", "Review Fixture", "true", "Scheduled Tasks", "Lab account", "", "1.0"]
        captures = {"baseline": [updater], "current": [[*updater[:-1], "1.1"], fixture]}
        for slot, rows in captures.items():
            file = self.directory / f"{slot}.csv"
            with file.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(header)
                writer.writerows(rows)
            self.run("startup", "import", self.database, slot, file, "--device", DEVICE, "--scope", "user-tasks")
        return json.loads(self.run("startup", "diff", self.database))

    def verify_recovery(self):
        backup = self.directory / "backup"
        (backup / "documents").mkdir(parents=True)
        originals = {}
        for index in range(20):
            path = f"documents/report-{index:02}.txt"
            originals[path] = f"HexSuture ordinary report {index:02}\n".encode("ascii")
            (backup / path).write_bytes(originals[path])
        manifest = {"backupVersion": "synthetic-pre-incident-v1",
                    "files": [{"path": name, "sha256": sha256(data)} for name, data in originals.items()]}
        manifest_path = self.directory / "restore-manifest.json"
        dump(manifest_path, manifest)
        first = self.directory / "verified-restore"
        self.run("recover", self.database, backup, manifest_path, first)
        damaged = "documents/report-04.txt"
        altered = b"Harmless altered backup copy\n"
        (backup / damaged).write_bytes(altered)
        second = self.directory / "partial-restore"
        self.run("recover", self.database, backup, manifest_path, second, expected=1)
        for path, data in originals.items():
            require((first / path).read_bytes() == data, "The verified restore changed.")
            require((backup / path).read_bytes() == (altered if path == damaged else data),
                    "Recovery changed the source backup.")
            if path != damaged:
                require((second / path).read_bytes() == data, "The partial restore contains a changed file.")
        require(not (second / damaged).exists(), "The altered copy was published.")
        return manifest

    def export(self):
        text = self.run("export", self.database, "--check-file", ROOT / "samples" / "benign-note.txt")
        report = json.loads(text)
        require(PRIVATE not in text, "A private fixture marker escaped redaction.")
        require(all(review["reviewer"] is None and review["reason"] is None and review["artifactPath"] is None
                    for review in report["reviews"]), "Private review details escaped redaction.")
        require(all(run["backup"] is None and run["destination"] is None and
                    all(item["path"] is None for item in run["items"])
                    for run in report["recoveryRuns"]), "Private recovery paths escaped redaction.")
        require(all(row["mode"] == "replay" for row in report["observations"]), "Replay data was mislabeled.")
        require(len(report["scans"]) == 1 and report["scans"][0]["status"] == "completed", "Scan replay failed.")
        require(any(row["decision"] == "benign" and row["status"] == "reviewed" for row in report["reviewQueue"]),
                "The benign review could not be verified.")
        require({(row["remediation"], row["status"]) for row in report["fileless"]}
                == {("remediated", "closed"), ("unremediated", "open")}, "Fileless action outcomes were mislabeled.")
        burst, = report["ransomware"]["suspiciousBursts"]
        require((burst["audited"], burst["blocked"], burst["relatedRansomwareRecordIds"]) == (6, 4, [120]),
                "Protected-folder evidence did not link to the matching Defender finding.")
        boot = report["boot"]
        require(boot["devices"][0]["configurationStatus"] == "changed" and
                boot["findings"][0]["source"] == "elam" and
                boot["offlineScans"][0]["status"] == "outcome-unknown" and
                boot["firmwareIntegrity"] == "unverified", "Boot evidence was mislabeled.")
        require([(row["matched"], row["mismatches"]) for row in report["recoveryRuns"]] == [(20, 0), (19, 1)],
                "Unexpected restore results.")
        return report


def workflow_results(job_file, commit):
    if job_file is None:
        return {"status": "local-evidence-only", "jobs": []}
    completed = json.loads(job_file.read_text(encoding="utf-8-sig"))["jobs"]
    jobs = []
    for name, image in RUNNER_JOBS.items():
        matching = [job for job in completed if job["name"] == name]
        require(len(matching) == 1 and matching[0]["conclusion"] == "success", f"Missing successful {name} job.")
        require(commit and matching[0]["head_sha"] == commit, f"The {name} run belongs to a different commit.")
        job = matching[0]
        jobs.append({"name": name, "image": image, "status": job["conclusion"], "url": job["html_url"],
                     "steps": [{"name": step["name"], "status": step["conclusion"]} for step in job["steps"]]})
    return {"status": "verified", "jobs": jobs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dll", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--jobs", type=Path, help="Optional GitHub Actions job response for the same commit.")
    parser.add_argument("--commit", help="Commit SHA for the built DLL.")
    args = parser.parse_args()
    if not args.dll.is_file() or args.output.exists():
        parser.error("Supply a built HexSuture DLL and a new output directory.")
    results = workflow_results(args.jobs, args.commit)
    with tempfile.TemporaryDirectory(prefix="hexsuture-evidence-") as temporary:
        case = EvidenceCase(args.dll.resolve(), Path(temporary).resolve())
        case.review_fixture()
        case.replay_incident()
        diff = case.startup_diff()
        require({row["status"] for row in diff["changes"]} == {"added", "changed"}, "Unexpected inventory diff.")
        manifest = case.verify_recovery()
        report = case.export()

    results.update({"commit": args.commit, "generatedUtc": datetime.now(timezone.utc).isoformat(),
                    "evidenceHost": {"os": platform.system(), "architecture": platform.machine()},
                    "syntheticCaseChecks": "passed", "verificationLimits": LIMITS})
    args.output.mkdir()
    dump(args.output / "case.redacted.json", report)
    dump(args.output / "restore-manifest.json", manifest)
    dump(args.output / "startup-diff.json", diff)
    dump(args.output / "test-results.json", results)
    guide = ROOT / "docs" / "release-evidence.md"
    (args.output / "README.md").write_text(guide.read_text(encoding="utf-8"), encoding="utf-8")
    print("Release evidence verified: redaction, boot outcomes, startup changes, and 20/20 then 19/20 restores.")


if __name__ == "__main__":
    main()
