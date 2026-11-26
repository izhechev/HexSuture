using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace HexSuture;

internal static class ScanEvidence
{
    private sealed record Entry(string Mode, ReplayEvent Item, Dictionary<string, string> Facts)
    {
        public string? Field(string key) => Facts.GetValueOrDefault(key)?.Trim();
    }

    public static IEnumerable<object> Scans(IReadOnlyList<(string Mode, ReplayEvent Item)> events)
    {
        var entries = Read(events.Where(row => row.Item.EventId is 1000 or 1001 or 1002));
        foreach (var group in entries.GroupBy(entry => Key(entry, "Scan ID")))
        {
            var first = group.First();
            var start = group.FirstOrDefault(entry => entry.Item.EventId == 1000);
            var ends = group.Where(entry => entry.Item.EventId != 1000).ToList();
            var end = ends.LastOrDefault();
            string? kind = group.Select(e => e.Field("Scan Parameters")?.ToLowerInvariant() switch
            {
                "custom scan" or "customer scan" or "%%807" => "custom",
                "quick scan" or "%%806" => "quick",
                "full scan" or "%%805" => "full",
                _ => null
            }).FirstOrDefault(value => value != null);
            var status = end?.Item.EventId switch
            {
                1001 => "completed",
                1002 => "stopped",
                _ => "started"
            };
            if (ends.Select(entry => entry.Item.EventId).Distinct().Count() > 1 ||
                (end != null && group.Last().Item.EventId == 1000))
                status = "unknown";

            yield return new
            {
                mode = first.Mode, device = first.Item.Device, scanId = group.Key.Id,
                kind = kind ?? "unknown", status, startedUtc = start?.Item.OccurredUtc,
                endedUtc = end?.Item.OccurredUtc, recordIds = group.Select(e => e.Item.RecordId)
            };
        }
    }

    private static IEnumerable<IGrouping<(string Mode, string Device, string? Id, long Record, string? Time), Entry>>
        DetectionGroups(IReadOnlyList<(string Mode, ReplayEvent Item)> events) =>
        Read(events.Where(row => row.Item.EventId is >= 1116 and <= 1119))
            .GroupBy(entry => Key(entry, "Detection ID"));

    public static IEnumerable<ReviewFinding> ReviewFindings(IReadOnlyList<(string Mode, ReplayEvent Item)> events)
    {
        foreach (var group in DetectionGroups(events))
        {
            var detection = group.FirstOrDefault(entry => entry.Item.EventId == 1116);
            if (detection is not null)
                yield return new ReviewFinding(detection.Mode, detection.Item, group.Key.Id, detection.Field("Path"));
        }
    }

    public static IEnumerable<object> Detections(IReadOnlyList<(string Mode, ReplayEvent Item)> events, bool includePaths = false)
    {
        foreach (var group in DetectionGroups(events))
        {
            var first = group.First();
            var detection = group.FirstOrDefault(e => e.Item.EventId == 1116);
            var identity = detection ?? first;
            var actions = group.Where(e => e.Item.EventId != 1116).Select(e =>
            {
                var action = ActionName(e);
                return new
                {
                    occurredUtc = e.Item.OccurredUtc, recordId = e.Item.RecordId,
                    eventId = e.Item.EventId, action, actionStatus = ActionStatus(e, action)
                };
            }).ToList();
            var latest = actions.LastOrDefault();
            yield return new
            {
                mode = first.Mode, device = first.Item.Device, detectionId = group.Key.Id,
                findingId = detection is null ? null : ReviewFinding.Identifier(detection.Mode, detection.Item),
                detectedUtc = detection?.Item.OccurredUtc, source = SourceName(identity),
                threatId = ulong.TryParse(identity.Field("Threat ID"), NumberStyles.None,
                    CultureInfo.InvariantCulture, out var threat) ? threat.ToString(CultureInfo.InvariantCulture) : null,
                threatName = Validated(identity.Field("Threat Name"),
                    @"[A-Za-z][A-Za-z0-9]{1,31}:[A-Za-z0-9_-]{1,24}/[A-Za-z0-9][A-Za-z0-9_.!@+-]{0,100}"),
                engineVersion = VersionText(identity.Field("Engine Version")),
                signatureVersion = VersionText(identity.Field("Security intelligence Version") ?? identity.Field("Signature Version")),
                action = latest?.action, actionStatus = latest?.actionStatus ?? "unknown",
                resources = includePaths
                    ? group.Select(e => e.Facts.GetValueOrDefault("Path"))
                        .Where(path => !string.IsNullOrWhiteSpace(path)).Distinct(StringComparer.Ordinal).ToArray()
                    : null,
                actions, recordIds = group.Select(e => e.Item.RecordId)
            };
        }
    }

    private static IEnumerable<Entry> Read(IEnumerable<(string Mode, ReplayEvent Item)> events) =>
        events.OrderBy(row => row.Item.OccurredUtc, StringComparer.Ordinal).ThenBy(row => row.Item.RecordId)
            .Select(row => new Entry(row.Mode, row.Item,
                JsonSerializer.Deserialize<Dictionary<string, string>>(row.Item.FactsJson)!));

    private static (string Mode, string Device, string? Id, long Record, string? Time) Key(Entry entry, string field)
    {
        // Without a valid ID, keep each observation separate.
        var device = entry.Item.Device.ToUpperInvariant();
        if (Guid.TryParse(entry.Field(field), out var id) && id != Guid.Empty)
            return (entry.Mode, device, id.ToString("D"), 0, null);
        return (entry.Mode, device, null, entry.Item.RecordId, entry.Item.OccurredUtc);
    }

    private static string SourceName(Entry entry)
    {
        var number = entry.Field("Source ID") switch
        {
            "1" => "user-initiated", "2" => "system-initiated", "3" => "real-time",
            "4" => "ioav", "5" => "nis", "6" => "ieprotect", "7" => "elam",
            "8" => "local-attestation", "9" => "remote-attestation", "10" => "amsi", _ => null
        };
        var name = (entry.Field("Source Name") ?? entry.Field("Detection Source"))?.ToLowerInvariant() switch
        {
            "user" or "user initiated" or "on-demand" => "user-initiated",
            "system" or "system initiated" => "system-initiated",
            "real-time" or "real-time protection" or "realtime" => "real-time",
            "ioav" => "ioav", "nis" => "nis", "ieprotect" => "ieprotect", "elam" => "elam",
            "local attestation" => "local-attestation", "remote attestation" => "remote-attestation",
            "amsi" or "antimalware scan interface" => "amsi", _ => null
        };
        return Resolve(number, name);
    }

    private static string ActionName(Entry entry)
    {
        var number = entry.Field("Action ID") switch
        {
            "1" => "clean", "2" => "quarantine", "3" => "remove", "6" => "allow",
            "8" => "user-defined", "9" => "no-action", "10" => "block", _ => null
        };
        var name = (entry.Field("Action Name") ?? entry.Field("Action"))?.ToLowerInvariant() switch
        {
            "clean" => "clean", "quarantine" => "quarantine", "remove" => "remove", "allow" => "allow",
            "user defined" or "user-defined" => "user-defined", "no action" or "none" => "no-action",
            "block" => "block", _ => null
        };
        return Resolve(number, name);
    }

    private static string Resolve(string? number, string? name) =>
        number != null && name != null && name != number ? "unknown" : number ?? name ?? "unknown";

    private static string ActionStatus(Entry entry, string action)
    {
        if (entry.Item.EventId is 1118 or 1119)
            return "failed";
        var error = entry.Field("Error Code");
        if (!string.IsNullOrEmpty(error))
        {
            var hex = error.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            if (!uint.TryParse(hex ? error[2..] : error, hex ? NumberStyles.HexNumber : NumberStyles.None,
                    CultureInfo.InvariantCulture, out var code))
                return "unknown";
            if (code != 0)
                return "failed";
        }
        // Defender threat status codes describe states. Their successful values are nonzero.
        var status = entry.Field("Status Code");
        if (status is "102" or "103" or "104" or "105" or "106" or "107")
            return "failed";
        if (!string.IsNullOrEmpty(status))
        {
            var expected = status switch
            {
                "2" => "clean", "3" => "quarantine", "4" => "remove",
                "5" => "allow", "6" => "block", _ => null
            };
            if (expected != action)
                return "unknown";
        }
        return action switch
        {
            "clean" or "quarantine" or "remove" when entry.Field("Additional Actions ID") is not (null or "" or "0") => "follow-up-required",
            "clean" or "quarantine" or "remove" => "remediated",
            "allow" or "no-action" => "unremediated",
            "block" => "blocked",
            _ => "unknown"
        };
    }

    private static string? VersionText(string? value) => Validated(value,
        @"(?:(?:AM|AV|AS|NIS):\s*)?[0-9]+(?:\.[0-9]+){1,3}(?:,\s*(?:AM|AV|AS|NIS):\s*[0-9]+(?:\.[0-9]+){1,3})*");

    private static string? Validated(string? value, string pattern) =>
        value is { Length: <= 160 } && Regex.IsMatch(value, @"\A" + pattern + @"\z",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking) ? value : null;
}
