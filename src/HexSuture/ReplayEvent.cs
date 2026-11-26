using System.Globalization;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace HexSuture;

internal sealed record ReplayEvent(
    string Device,
    string Channel,
    string Provider,
    long RecordId,
    int EventId,
    string OccurredUtc,
    string FactsJson)
{
    private static readonly XNamespace Events = "http://schemas.microsoft.com/win/2004/08/events/event";
    private const string DefenderProvider = "Microsoft-Windows-Windows Defender";
    private const string DefenderChannel = DefenderProvider + "/Operational";

    internal static ReplayEvent Read(string path)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 1_048_576
        };
        using var source = File.OpenRead(path);
        XElement root;
        try
        {
            using var reader = XmlReader.Create(source, settings);
            root = XDocument.Load(reader, LoadOptions.PreserveWhitespace).Root
                ?? throw new InvalidDataException("The XML file contains no event.");
        }
        catch (XmlException error)
        {
            throw new InvalidDataException($"Invalid event XML at line {error.LineNumber}.", error);
        }

        if (root.Name == Events + "Events" || root.Name == "Events")
        {
            var children = root.Elements().Take(2).ToArray();
            if (children.Length != 1)
                throw new InvalidDataException("The XML file must contain exactly one event.");
            root = children[0];
        }
        if (root.Name != Events + "Event")
            throw new InvalidDataException("Expected a Windows Event element in the Windows event namespace.");

        var system = RequiredChild(root, "System");
        var provider = (string?)RequiredChild(system, "Provider").Attribute("Name");
        var channel = RequiredText(system, "Channel");
        if (!string.Equals(provider, DefenderProvider, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(channel, DefenderChannel, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Expected an event from the Microsoft Defender Operational log.");

        var device = RequiredText(system, "Computer");
        if (!long.TryParse(RequiredText(system, "EventRecordID"), NumberStyles.None,
                CultureInfo.InvariantCulture, out var recordId) || recordId < 1)
            throw new InvalidDataException("Expected a positive EventRecordID that fits in a signed 64-bit integer.");
        if (!ushort.TryParse(RequiredText(system, "EventID"), NumberStyles.None,
                CultureInfo.InvariantCulture, out var eventId))
            throw new InvalidDataException("Expected a numeric EventID between 0 and 65535.");

        var time = (string?)RequiredChild(system, "TimeCreated").Attribute("SystemTime");
        return new ReplayEvent(device, DefenderChannel, DefenderProvider, recordId, eventId,
            ReadUtcTime(time), ReadFacts(root));
    }

    private static XElement RequiredChild(XElement parent, string name)
    {
        var matches = parent.Elements(Events + name).Take(2).ToArray();
        if (matches.Length != 1)
            throw new InvalidDataException($"Expected exactly one {name} element in {parent.Name.LocalName}.");
        return matches[0];
    }

    private static string RequiredText(XElement parent, string name)
    {
        var child = RequiredChild(parent, name);
        if (child.HasElements || string.IsNullOrWhiteSpace(child.Value))
            throw new InvalidDataException($"Expected a value for {name}.");
        return child.Value.Trim();
    }

    private static string ReadUtcTime(string? value)
    {
        var hasOffset = value is { Length: >= 6 } && (value[^6] is '+' or '-') && value[^3] == ':';
        if (value is null || !value.Contains('T') || !(value.EndsWith('Z') || hasOffset))
            throw new InvalidDataException("Expected a SystemTime timestamp with an explicit time zone.");

        try
        {
            var utc = XmlConvert.ToDateTimeOffset(value).UtcDateTime;
            return utc.ToString("O", CultureInfo.InvariantCulture);
        }
        catch (Exception error) when (error is FormatException or ArgumentException)
        {
            throw new InvalidDataException("Invalid SystemTime timestamp.", error);
        }
    }

    private static string ReadFacts(XElement root)
    {
        var payloads = root.Elements()
            .Where(element => element.Name != Events + "System" && element.Name != Events + "RenderingInfo")
            .Take(2).ToArray();
        if (payloads.Length == 0)
            return "{}";
        if (payloads.Length != 1 || payloads[0].Name != Events + "EventData")
            throw new InvalidDataException("Only named EventData fields are supported.");

        if (payloads[0].Nodes().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value)))
            throw new InvalidDataException("Unexpected text outside an EventData field.");

        var facts = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var field in payloads[0].Elements())
        {
            var name = (string?)field.Attribute("Name");
            if (field.Name != Events + "Data" || field.HasElements || string.IsNullOrWhiteSpace(name))
                throw new InvalidDataException("Expected a named Data element with a text value.");
            if (!facts.TryAdd(name, field.Value))
                throw new InvalidDataException("A Data field name occurs more than once.");
        }
        return JsonSerializer.Serialize(facts);
    }
}
