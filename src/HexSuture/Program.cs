using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using HexSuture;
using Microsoft.Data.Sqlite;

const string usage = """
    Run a Defender scan, review a case, or replay a saved Defender event.

      HexSuture import <case.db> <event.xml>
      HexSuture show <case.db> [--paths]
      HexSuture scan <case.db> folder <directory>
      HexSuture scan <case.db> quick
      HexSuture scan <case.db> full
      HexSuture history
    """;

try
{
    switch (args)
    {
        case ["import", var database, var source]:
            return Import(database, source);
        case ["scan", var database, "folder", var folder]:
            return RunScan(database, "folder", folder);
        case ["scan", var database, var kind] when kind is "quick" or "full":
            return RunScan(database, kind, null);
        case ["history"]:
            if (!OperatingSystem.IsWindows())
            {
                Console.Error.WriteLine("Protection History is available in Windows Security.");
                return 1;
            }
            Process.Start(new ProcessStartInfo("windowsdefender://history") { UseShellExecute = true })?.Dispose();
            return 0;
        case ["show", _]:
        case ["show", _, "--paths"]:
            using (var store = new CaseStore(args[1], create: false))
            {
                WriteReport(store, includePaths: args.Length == 3);
            }
            return 0;
        case ["--help"] or ["-h"]:
            Console.WriteLine(usage);
            return 0;
        default:
            Console.Error.WriteLine(usage);
            return 2;
    }
}
catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or SqliteException or ArgumentException or JsonException or Win32Exception)
{
    Console.Error.WriteLine($"Case error: {ex.Message}");
    return 1;
}

static int RunScan(string database, string kind, string? folder)
{
    if (!OperatingSystem.IsWindows())
    {
        Console.Error.WriteLine("Live scans require Microsoft Defender Antivirus on Windows. Use import to replay a saved event.");
        return 1;
    }
    if (folder is not null)
    {
        folder = Path.GetFullPath(folder);
        if (!Directory.Exists(folder))
        {
            Console.Error.WriteLine("Choose an existing folder to scan.");
            return 2;
        }
    }
    using var store = new CaseStore(database, create: true);
    return DefenderScanner.Run(store, kind, folder);
}

static int Import(string database, string source)
{
    var pathComparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;
    if (string.Equals(Path.GetFullPath(database), Path.GetFullPath(source), pathComparison))
    {
        Console.Error.WriteLine("Choose separate files for the case and the event.");
        return 2;
    }

    using var store = new CaseStore(database, create: true);
    ReplayEvent item;
    try
    {
        item = ReplayEvent.Read(source);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
    {
        var reason = ex switch
        {
            FileNotFoundException or DirectoryNotFoundException => "Source is missing.",
            InvalidDataException => $"Invalid event: {ex.Message}",
            _ => "Source could not be read."
        };
        return ReportSourceGap(store, source, reason);
    }

    try
    {
        bool added = store.Add(item);
        Console.WriteLine(added ? "Imported one replay observation." : "Observation already recorded.");
        return 0;
    }
    catch (InvalidDataException ex)
    {
        return ReportSourceGap(store, source, ex.Message);
    }
}

static int ReportSourceGap(CaseStore store, string source, string reason)
{
    var name = Path.GetFileName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(source)));
    store.FlagSource(name, reason);
    Console.Error.WriteLine($"Source gap: {reason}");
    return 1;
}

static void WriteReport(CaseStore store, bool includePaths)
{
    var events = store.ObservedEvents().ToList();
    var report = new
    {
        scanRequests = store.ScanRequests().Select(request => new
        {
            requestId = request.Id,
            device = request.Device,
            kind = request.Kind,
            folder = includePaths ? request.Folder : null,
            requestedUtc = request.RequestedUtc,
            endedUtc = request.EndedUtc,
            engineVersion = request.EngineVersion,
            signatureVersion = request.SignatureVersion,
            processExitCode = request.ExitCode,
            error = request.Error
        }),
        scans = ScanEvidence.Scans(events),
        detections = ScanEvidence.Detections(events, includePaths),
        observations = events.Select(observed => new
        {
            mode = observed.Mode,
            device = observed.Item.Device,
            occurredUtc = observed.Item.OccurredUtc,
            channel = observed.Item.Channel,
            provider = observed.Item.Provider,
            recordId = observed.Item.RecordId,
            eventId = observed.Item.EventId,
            facts = ReportFacts(observed.Item)
        }),
        sourceGaps = store.SourceGaps().Select(gap => new
        {
            sourceName = gap.SourceName,
            reason = gap.Reason
        })
    };
    Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
}

static Dictionary<string, string> ReportFacts(ReplayEvent item)
{
    var visible = new Dictionary<string, string>();
    if (item.EventId is not (1000 or 1001 or 1002))
        return visible;

    var facts = JsonSerializer.Deserialize<Dictionary<string, string>>(item.FactsJson)!;
    if (facts.TryGetValue("Scan ID", out var id) && Guid.TryParse(id, out var scan))
        visible["Scan ID"] = scan.ToString("B");
    if (facts.TryGetValue("Scan Parameters", out var scope) &&
        scope is "Quick Scan" or "Full Scan" or "Custom Scan")
        visible["Scan Parameters"] = scope;
    if (facts.TryGetValue("Scan Time", out var time) &&
        TimeSpan.TryParse(time, CultureInfo.InvariantCulture, out var duration) && duration >= TimeSpan.Zero)
        visible["Scan Time"] = duration.ToString("c", CultureInfo.InvariantCulture);
    return visible;
}
