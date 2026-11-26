# HexSuture release evidence

This bundle follows a synthetic Windows case from a scan and review through file recovery. Open `case.redacted.json` for the recorded evidence, then use `test-results.json` to see what ran on Windows.

## What was detected

The replay contains a completed Defender scan and one benign fixture reviewed by its file hash. Two script detections have different outcomes. Defender’s recorded quarantine closes one finding and an Allow action leaves the other open. The folder-protection replay shows six audited and four blocked attempts linked to a Defender ransomware detection. The boot section records a rootkit fixture attributed to Early Launch Anti-Malware.

## What changed

The synthetic startup inventory shows an updater moving from version 1.0 to 1.1 and a task added for review. The boot baseline changes from Secure Boot enabled to disabled. The first backup restore verifies 20 of 20 files. The second verifies 19 and withholds the altered `documents/report-04.txt` copy. Match the affected file’s expected SHA-256 in the redacted case to the entry in `restore-manifest.json`.

## What still needs review

The human review queue still has four open findings. They are the two script detections, the ransomware detection and the rootkit detection. The quarantined script shows closed in the fileless timeline because Defender recorded remediation. Its human review is still open. The added startup task and Secure Boot change also need review. The replay shows a Defender Offline schedule and a restart with the scan outcome unknown. The altered backup copy needs a known-good replacement.

## Test coverage

The hosted `test-results.json` records the source commit, the host that generated the bundle and links to the completed verification jobs. A local bundle records only its own checks. The Windows jobs cover live scanning, Task Scheduler disable and rollback, local event collection, folder-protection settings and Secure Boot collection. The release case, ransomware activity and post-restart task cleanup use synthetic or replayed evidence. Live AMSI capture and a full Defender Offline restart still need their supported Windows setups.

## Reproduce

Install the .NET 10 SDK and Python 3. Run these commands from the repository root and use a new output directory.

```sh
dotnet build src/HexSuture --configuration Release --warnaserror
python tools/release_evidence.py src/HexSuture/bin/Release/net10.0/HexSuture.dll release-evidence
```

The command runs the normal HexSuture CLI against ordinary files and saved Defender records. The output directory contains the public evidence files. A local run records its own checks and leaves GitHub Actions job results to the hosted run.
