using System.Text;
using System.Text.Json.Serialization;
using Microsoft.VisualBasic.FileIO;

namespace HexSuture;

internal sealed record StartupSnapshot(string Device, string Scope, DateTimeOffset ImportedUtc, StartupEntry[] Entries);
internal sealed record StartupEntry(string Location, string Name, string Profile, SortedDictionary<string, string> Facts)
{
    [JsonIgnore]
    public (string, string, string) Key =>
        (Location.ToUpperInvariant(), Name.ToUpperInvariant(), Profile.ToUpperInvariant());
}

internal static class StartupInventory
{
    private const int MaxBytes = 16 * 1024 * 1024;
    private static readonly string[] Required = ["Entry Location", "Entry", "Enabled", "Category", "Profile"];

    internal static StartupSnapshot Read(string path, string device, string scope)
    {
        if (string.IsNullOrWhiteSpace(device) || string.IsNullOrWhiteSpace(scope))
            throw new ArgumentException("Supply the device and capture scope.");
        using var stream = File.OpenRead(path);
        if (stream.Length > MaxBytes)
            throw new InvalidDataException("Choose an Autorunsc CSV smaller than 16 MB.");

        using var parser = new TextFieldParser(stream, new UTF8Encoding(false, true), detectEncoding: true)
        {
            TextFieldType = FieldType.Delimited,
            HasFieldsEnclosedInQuotes = true
        };
        parser.SetDelimiters(",");
        try
        {
            var headers = parser.ReadFields()?.Select(name => name.Trim().ToLowerInvariant()).ToArray() ?? [];
            if (headers.Distinct().Count() != headers.Length ||
                Required.Any(name => !headers.Contains(name.ToLowerInvariant())))
                throw new InvalidDataException("The CSV must contain the standard Autorunsc inventory columns.");

            var entries = new Dictionary<(string, string, string), StartupEntry>();
            while (!parser.EndOfData)
            {
                var row = parser.ReadFields();
                if (row is null || row.Length != headers.Length || stream.Length > MaxBytes)
                    throw new InvalidDataException("The inventory has an incomplete row or exceeds the size limit.");

                var facts = new SortedDictionary<string, string>(StringComparer.Ordinal);
                for (int column = 0; column < headers.Length; column++)
                {
                    if (headers[column] != "time")
                        facts.Add(headers[column], row[column]);
                }
                var entry = new StartupEntry(facts["entry location"], facts["entry"], facts["profile"], facts);
                if (string.IsNullOrWhiteSpace(entry.Location) || string.IsNullOrWhiteSpace(entry.Name))
                    throw new InvalidDataException("Each inventory row needs an entry location and name.");
                if (!entries.TryAdd(entry.Key, entry) && !entries[entry.Key].Facts.SequenceEqual(entry.Facts))
                    throw new InvalidDataException("The inventory has conflicting rows for one startup entry.");
            }
            return new StartupSnapshot(device.Trim(), scope.Trim(), DateTimeOffset.UtcNow, entries.Values.ToArray());
        }
        catch (MalformedLineException)
        {
            throw new InvalidDataException("The Autorunsc CSV contains a malformed row.");
        }
    }

    internal static object Compare(StartupSnapshot baseline, StartupSnapshot current)
    {
        if (!string.Equals(baseline.Device, current.Device, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(baseline.Scope, current.Scope, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Compare inventories captured on the same device with the same scope.");

        var before = baseline.Entries.ToDictionary(entry => entry.Key);
        var after = current.Entries.ToDictionary(entry => entry.Key);
        var changes = before.Keys.Union(after.Keys).OrderBy(key => key).Select(key =>
        {
            var old = before.GetValueOrDefault(key);
            var now = after.GetValueOrDefault(key);
            string status = old is null ? "added" : now is null ? "removed" :
                old.Facts.SequenceEqual(now.Facts) ? "unchanged" : "changed";
            return new { status, before = old, after = now };
        }).Where(row => row.status != "unchanged");
        return new { baseline.Device, baseline.Scope, baselineUtc = baseline.ImportedUtc,
            currentUtc = current.ImportedUtc, changes };
    }
}
