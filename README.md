# HexSuture

HexSuture is a Windows project for investigating malware and checking whether cleanup and file recovery worked. The first milestone saves a recorded Microsoft Defender event in a local case. You can close the app, import the same event again and see one observation in the case report.

## Try case replay

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) and run these commands from the repository root. The sample is a synthetic scan-completion event for a fictional PC named LAB-PC. The commands only read the sample and write a local SQLite database.

```sh
dotnet run --project src/HexSuture -- import example.db samples/scan-completed.xml
dotnet run --project src/HexSuture -- import example.db samples/scan-completed.xml
dotnet run --project src/HexSuture -- show example.db
```

The first import adds one observation. The second reports that the event is already recorded. The JSON report contains one observation with mode `replay`, event ID `1001`, record ID `42` and a scan time of four seconds. Event 1001 records that a scan finished. A finding or cleanup result needs its own evidence. [Microsoft Defender event reference](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

## Import a saved event

In Windows Event Viewer, open an event from **Microsoft → Windows → Windows Defender → Operational**, select **Details → XML View**, and save the event XML as a text file. Pass its path in place of the sample. This milestone accepts one Windows event per XML file, including a one-event wrapper. It supports named text fields in EventData and a maximum of 1,048,576 XML characters. Binary EVTX files and multi-event exports need a different importer. [Windows event schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventtype-complextype)

Each database represents one case. Event identity uses the source device, channel, provider, record ID and time in UTC. Renaming the XML file has no effect on the identity. If two records share an identity but contain different evidence, HexSuture keeps the first and records the conflict. A missing, unreadable or invalid input also leaves a source gap and returns a nonzero exit code. Source gaps are a history of failed imports.

Use a private folder for real cases. The database holds the original named event fields, which can include usernames, paths or script text. The report shows the device, event identity and recognized scan facts. It omits free-text event fields. On Windows, new case files inherit the folder’s access permissions.

## Run the acceptance tests

The tests use Python 3 and start a fresh copy of the CLI for each command. They use temporary case files and the synthetic XML sample.

```sh
dotnet build src/HexSuture --configuration Release --warnaserror
python tests/test_replay.py src/HexSuture/bin/Release/net10.0/HexSuture.dll
```

On macOS or Linux, use `python3` if that is the name of your Python executable. GitHub Actions runs the same checks on a Windows x64 runner.
