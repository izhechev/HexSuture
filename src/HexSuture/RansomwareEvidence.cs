using System.Globalization;
using System.Text.Json;

namespace HexSuture;

internal sealed record CfaCoverage(string Device, DateTimeOffset ObservedUtc, string Mode);

internal static class RansomwareEvidence
{
    private const int PathThreshold = 10;
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    private sealed record Write(string Mode, ReplayEvent Event, string? Process, string? Path, DateTimeOffset Time);
    private sealed record Threat(string Mode, ReplayEvent Event, string? Process, string Name, DateTimeOffset Time);

    internal static object Report(IReadOnlyList<(string Mode, ReplayEvent Item)> events,
        IEnumerable<CfaCoverage> coverage, bool includePaths)
    {
        var writes = new List<Write>();
        var threats = new List<Threat>();
        foreach (var (mode, item) in events)
        {
            if (item.EventId is not (1123 or 1124 or 1116))
                continue;

            var facts = JsonSerializer.Deserialize<Dictionary<string, string>>(item.FactsJson)!;
            string? process = Field(facts, "Process Name");
            var time = DateTimeOffset.Parse(item.OccurredUtc, CultureInfo.InvariantCulture);
            if (item.EventId is 1123 or 1124)
                writes.Add(new Write(mode, item, process,
                    Field(facts, "Path") ?? Field(facts, "Target File Name"), time));
            else if (Field(facts, "Threat Name") is { } name && name.StartsWith("Ransom:", StringComparison.OrdinalIgnoreCase))
                threats.Add(new Threat(mode, item, process, name, time));
        }

        var threatGroups = threats.Where(entry => IsProcessPath(entry.Process))
            .ToLookup(entry => Key(entry.Mode, entry.Event.Device, entry.Process!));
        var bursts = new List<object>();
        foreach (var group in writes.Where(write => IsProcessPath(write.Process) && write.Path is not null)
            .GroupBy(write => Key(write.Mode, write.Event.Device, write.Process!)))
        {
            var entries = new Queue<Write>();
            var paths = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var write in group.OrderBy(write => write.Time).ThenBy(write => write.Event.RecordId))
            {
                while (entries.Count > 0 && write.Time - entries.Peek().Time > Window)
                {
                    string path = Normalize(entries.Dequeue().Path!);
                    if (--paths[path] == 0)
                        paths.Remove(path);
                }
                entries.Enqueue(write);
                string current = Normalize(write.Path!);
                paths[current] = paths.GetValueOrDefault(current) + 1;
                if (paths.Count < PathThreshold)
                    continue;

                var first = entries.Peek();
                var related = threatGroups[group.Key]
                    .Where(threat => threat.Time >= first.Time - Window && threat.Time <= write.Time + Window)
                    .Select(threat => threat.Event.RecordId).ToArray();
                bursts.Add(new
                {
                    first.Mode, first.Event.Device, startedUtc = first.Time, endedUtc = write.Time,
                    status = "suspicious-writes", distinctPaths = paths.Count,
                    audited = entries.Count(entry => entry.Event.EventId == 1124),
                    blocked = entries.Count(entry => entry.Event.EventId == 1123),
                    recordIds = entries.Select(entry => entry.Event.RecordId).ToArray(),
                    relatedRansomwareRecordIds = related
                });
                entries.Clear();
                paths.Clear();
            }
        }

        var liveCoverage = coverage.ToArray();
        var modes = liveCoverage.Select(setting => setting.Mode).Distinct().ToArray();
        return new
        {
            coverage = modes.Length > 1 ? "mixed" : modes.FirstOrDefault() ?? "unknown",
            deviceSettings = liveCoverage,
            writeAttempts = writes.Select(write => new
            {
                write.Mode, write.Event.Device, write.Event.RecordId, write.Event.OccurredUtc,
                status = write.Event.EventId == 1123 ? "blocked" : "audited",
                processName = SafeProcessName(write.Process),
                processPath = includePaths ? write.Process : null,
                affectedPath = includePaths ? write.Path : null
            }),
            suspiciousBursts = bursts,
            defenderDetections = threats.Select(threat => new
            {
                threat.Mode, threat.Event.Device, threat.Event.RecordId, threat.Event.OccurredUtc,
                threatName = threat.Name.Length <= 160 && threat.Name.All(IsNameCharacter) ? threat.Name : null,
                processName = SafeProcessName(threat.Process)
            })
        };
    }

    private static (string Mode, string Device, string Process) Key(string mode, string device, string process) =>
        (mode, device.ToUpperInvariant(), Normalize(process).ToUpperInvariant());

    private static string Normalize(string path) => path.Replace('/', '\\');

    private static string? Field(Dictionary<string, string> facts, string name) =>
        facts.TryGetValue(name, out string? value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;

    private static bool IsProcessPath(string? path)
    {
        if (path is null)
            return false;
        string normalized = Normalize(path);
        return normalized.StartsWith('\\') ||
            (normalized.Length > 3 && char.IsAsciiLetter(normalized[0]) && normalized[1] == ':' && normalized[2] == '\\');
    }

    private static string? SafeProcessName(string? path)
    {
        if (path is null)
            return null;
        var name = path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
        return name.Length <= 100 && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            name.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ' ') ? name : null;
    }

    private static bool IsNameCharacter(char character) =>
        char.IsAsciiLetterOrDigit(character) || character is ':' or '/' or '_' or '.' or '!' or '-' or '+' or '@';
}
