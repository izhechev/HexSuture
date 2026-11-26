# HexSuture

HexSuture is a Windows project for investigating malware and checking whether cleanup and file recovery worked. It runs Microsoft Defender scans and keeps scan results, detections and actions in a local case. Saved Defender events can also be replayed on another computer.

## Run a live scan

On Windows with Microsoft Defender Antivirus active, open a terminal as administrator. Run these commands from the repository root. Replace the example directory with one that exists.

```powershell
dotnet run --project src/HexSuture -- scan case.db folder "C:\Scan samples"
dotnet run --project src/HexSuture -- scan case.db quick
dotnet run --project src/HexSuture -- scan case.db full
dotnet run --project src/HexSuture -- show case.db
```

Before scanning a folder, HexSuture asks Defender whether that folder is excluded. An excluded or unverifiable folder produces a coverage gap. Quick and full scans use Defender’s built-in scopes. Defender applies the response configured on the PC. Use `dotnet run --project src/HexSuture -- history` to open Protection History and review quarantined items. [Defender scan options](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus) · [Microsoft Protection History](https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app)

| Report field | What it tells you |
| --- | --- |
| `scanRequests` | What HexSuture asked Defender to do. Each request records scope, engine and signature versions when available, and the process exit code. Add `--paths` to `show` to see the selected folder and detection resources. |
| `scans` | What Defender observed. Events 1000, 1001 and 1002 describe a start, finish or stop. HexSuture matches them by device, evidence origin and scan ID. |
| `detections` | Which source identified an item and what action Defender recorded. Real-time protection can catch an item before the folder scan begins. A completed scan or zero process exit code cannot establish a clean result. |

HexSuture reads the local Defender Operational log around the request. For folder scans it also looks back ten minutes for detections concerning that folder. Other Defender activity can overlap the request, so the report keeps scan IDs and detection IDs separate. Collection stops at 4,096 events per window and records a gap if more exist. Ctrl+C stops the CLI from waiting. Only a Defender stop event supports the `stopped` result. [Defender event definitions](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

## Try case replay

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) and run these commands from the repository root. The sample is a synthetic scan-completion event for a fictional PC named LAB-PC. The commands only read the sample and write a local SQLite database.

```sh
dotnet run --project src/HexSuture -- import example.db samples/scan-completed.xml
dotnet run --project src/HexSuture -- import example.db samples/scan-completed.xml
dotnet run --project src/HexSuture -- show example.db
```

The first import adds one observation. The second reports that the event is already recorded. The JSON report contains one observation with mode `replay`, event ID `1001`, record ID `42` and a scan time of four seconds. Event 1001 records that a scan finished. A finding or cleanup result needs its own evidence. [Microsoft Defender event reference](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

## Import a saved event

In Windows Event Viewer, open an event from **Microsoft → Windows → Windows Defender → Operational**, select **Details → XML View**, and save the event XML as a text file. Pass its path in place of the sample. The importer accepts one Windows event per XML file, including a one-event wrapper. It supports named text fields in EventData and a maximum of 1,048,576 XML characters. Binary EVTX files and multi-event exports need a different importer. [Windows event schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventtype-complextype)

Each database represents one case. Event identity uses the source device, channel, provider, record ID and time in UTC. Renaming the XML file has no effect on the identity. If two records share an identity but contain different evidence, HexSuture keeps the first and records the conflict. A missing, unreadable or invalid input also leaves a source gap and returns a nonzero exit code. Source gaps are a history of failed imports.

Use a private folder for real cases. The database holds the original named event fields, which can include usernames, paths or script text. The default report shows the device, event identity and selected facts. The optional paths view includes recorded resource paths. On Windows, new case files inherit the folder’s access permissions.

## Review a possible false positive

Use the `findingId` shown in `detections` or `reviewQueue` to record a decision. The sample below deliberately pairs a synthetic detection with ordinary text. Replace `<finding-id>` with the ID from the report and use a future UTC expiry.

```sh
dotnet run --project src/HexSuture -- import review.db samples/benign-detection.xml
dotnet run --project src/HexSuture -- show review.db
dotnet run --project src/HexSuture -- review review.db "<finding-id>" benign --reviewer lab --reason "Known test document" --until 2027-01-01T12:00:00Z --file samples/benign-note.txt
dotnet run --project src/HexSuture -- show review.db --check-file samples/benign-note.txt
```

Each decision adds a history entry with the reviewer, reason, rule version and time. Use `malicious` or `uncertain` for other outcomes. An uncertain decision keeps the finding open. A decision without a file applies only to that occurrence. A new occurrence always gets its own review.

A file-bound benign decision applies while its expiry is in the future and the selected file still matches the recorded SHA-256. Use `--check-file` to verify that file when viewing the queue. A replacement, unavailable file or expired decision returns the finding to the queue. A live finding can be bound to its single recorded file on the originating PC. For replay, the reviewer supplies the copy to check. The review changes HexSuture’s case only. Defender continues applying its own policy. [Microsoft’s false-positive workflow](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-false-positives-negatives)

`export review.db` writes a redacted JSON case to standard output. It keeps detection IDs, decision history and links to the underlying event records. Use `export review.db --include-evidence` for a private copy with the stored event facts, resource paths and review notes. Cases from milestones 1 and 2 remain readable and upgrade on the next write.

## Review startup changes

Save matching CSV snapshots from Autorunsc on the same computer. Use the same account and options for both captures. For example, run the scheduled-task capture with `autorunsc.exe -a t -c -h -s` and save its output to a local CSV file. Keep the baseline from a known-good point. The comparison shows added, changed and removed rows with their original capture fields. A legitimate updater can appear in the same report as a suspicious task. [Sysinternals Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)

```sh
dotnet run --project src/HexSuture -- startup import case.db baseline clean.csv --device LAB-PC --scope user-tasks
dotnet run --project src/HexSuture -- startup import case.db current recent.csv --device LAB-PC --scope user-tasks
dotnet run --project src/HexSuture -- startup diff case.db
```

The device and scope labels come from the reviewer. Importing again replaces that slot in the case. Keep the CSV and case in a private folder because inventory fields can include local paths and command lines.

## Disable or remove a reviewed scheduled task

Use the exact path from Windows Task Scheduler. The task must be idle, enabled at review, owned by the current Windows user and configured to run with that user's interactive token at least privilege. Windows must let that user change the task. System tasks, service accounts and tasks that use saved credentials require manual review.

```powershell
dotnet run --project src/HexSuture -- task review case.db "\MyTasks\Example" --reason "Confirmed unwanted startup task"
dotnet run --project src/HexSuture -- task status case.db "<review-id>" --details
dotnet run --project src/HexSuture -- task disable case.db "<review-id>" --approve
```

The review stores the definition, owner and permissions. HexSuture rechecks them before writing and checks the task afterward. If you interrupt a change, retry the same command and review ID. The case retains both the pending request and the observed result.

After disabling, choose rollback to restore the previous enabled state or restart Windows to verify the task stayed disabled.

```powershell
dotnet run --project src/HexSuture -- task rollback case.db "<review-id>" --approve
dotnet run --project src/HexSuture -- task verify case.db "<review-id>"
dotnet run --project src/HexSuture -- task remove case.db "<review-id>" --approve
```

Use a fresh review for the removal path if you already rolled back. After a restart, `verify` checks the live task and records the boot time. `remove` permanently deletes only that verified task registration. Treat removal as a separate approval. To check whether a removed task has returned, run `task verify` again. [Task Scheduler enabled state](https://learn.microsoft.com/en-us/windows/win32/taskschd/registeredtask-enabled) · [Task Scheduler deletion](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-deletetask)

The hosted Windows test uses a disposable task with no triggers. The task workflow tests use simulated restarts to exercise post-restart verification, removal and interrupted requests. To verify the full sequence with Windows itself, use a dedicated test PC or VM and run the verification and removal commands after an actual restart.

## Follow a fileless detection through cleanup

Collect recent Defender detections and actions on the affected Windows computer. Use `import` for saved Defender event XML. The report marks saved events as replay and local collection as live evidence.

```powershell
dotnet run --project src/HexSuture -- fileless collect case.db --minutes 60
dotnet run --project src/HexSuture -- show case.db
```

Look under `fileless` for the reported detection source, process name when available, and the detection and action timeline. A Defender AMSI resource or the Microsoft AMSI test signature can identify the kind of detection even when Defender reports the source as system-initiated. Defender can also report behavior evidence through event 1015 or a behavior signature. Running PowerShell alone does not produce a fileless finding. Full process paths are available with `show --paths`. The report keeps memory coverage as unknown. [Microsoft AMSI demonstration](https://learn.microsoft.com/en-us/defender-endpoint/mde-demonstration-amsi) · [Defender event definitions](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

If Defender asks you to respond, use `history` to open Windows Security and follow the actions it offers for that detection. Collect again to check the result. A successful clean, quarantine or removal closes the affected finding when the action matches the detection and the related task checks are clear. Allow, failed cleanup, a missing action or a fresh detection keeps it open. [Windows Security Protection History](https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app)

If you confirmed a related scheduled task, review it with `task review` and record a live follow-up. Use the fileless finding ID and the task review ID from the same case.

```powershell
dotnet run --project src/HexSuture -- fileless check-task case.db "<finding-id>" "<task-review-id>"
```

An active task keeps the finding open. After using the task workflow to verify disablement after a restart or to remove the registration, run the follow-up again. HexSuture records the observed state and timestamp. A later task journal change requires a fresh follow-up.

The Windows CI replay covers successful, allowed and failed cleanup. Its live collector test uses the Defender event generated by the EICAR check. For live AMSI verification, run `tests/live_amsi.ps1` with the built DLL and a disposable, Defender-covered test directory on a machine that meets Microsoft's Defender for Endpoint demonstration requirements. The hosted Windows runner did not emit an AMSI event during the demonstration. [Microsoft AMSI prerequisites](https://learn.microsoft.com/en-us/defender-endpoint/mde-demonstration-amsi)

## Run the acceptance tests

The tests use Python 3 and start a fresh copy of the CLI for each command. They use temporary case files and the synthetic XML sample.

```sh
dotnet build src/HexSuture --configuration Release --warnaserror
python tests/test_replay.py src/HexSuture/bin/Release/net10.0/HexSuture.dll
```

On macOS or Linux, use `python3` if that is the name of your Python executable. GitHub Actions runs the portable tests on Windows x64. Pushes to main also run the live check on an isolated volume on a disposable Windows 11 Arm runner.

## Check the scanner on a test PC

The portable tests cover stopped and completed scans, old case files, and a replayed EICAR detection that preceded a folder scan.

```sh
python tests/test_scan_evidence.py src/HexSuture/bin/Release/net10.0/HexSuture.dll
python tests/test_migration.py src/HexSuture/bin/Release/net10.0/HexSuture.dll
```

On a disposable Windows PC with Defender active, the live check creates 100 text files, saves their SHA-256 manifest, requests a folder scan and checks the files afterward. Use `--parent` to choose a covered test directory. Add `--eicar` to create and read the harmless EICAR test file in a separate folder. The check prints the detection source, whether detection preceded the request, and the recorded action. It removes the temporary cases and test folders afterward. [Microsoft’s EICAR validation guide](https://learn.microsoft.com/en-us/defender-endpoint/validate-antimalware)

```powershell
python tests/live_scan.py src/HexSuture/bin/Release/net10.0/HexSuture.dll --eicar
```

For a live stopped-scan example, start a scan on a dedicated test PC and stop that scan in Windows Security. Open the case report and look for event 1002 and its scan ID.
