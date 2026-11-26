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
