using System.Globalization;
using System.Text.Json;
using HexSuture;
using Microsoft.Data.Sqlite;

const string usage = """
    Import one saved Defender event XML into a local case, or read the case report.

      HexSuture import <case.db> <event.xml>
      HexSuture show <case.db>
    """;

try
{
    switch (args)
    {
        case ["import", var database, var source]:
            return Import(database, source);
        case ["show", var database]:
            using (var store = new CaseStore(database, create: false))
            {
                WriteReport(store);
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
catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or SqliteException or ArgumentException or JsonException)
{
    Console.Error.WriteLine($"Case error: {ex.Message}");
    return 1;
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

static void WriteReport(CaseStore store)
{
    var report = new
    {
        observations = store.Observations().Select(item => new
        {
            mode = "replay",
            device = item.Device,
            occurredUtc = item.OccurredUtc,
            channel = item.Channel,
            provider = item.Provider,
            recordId = item.RecordId,
            eventId = item.EventId,
            facts = ReportFacts(item)
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
