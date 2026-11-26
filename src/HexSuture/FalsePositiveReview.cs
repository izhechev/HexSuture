using System.Globalization;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text.Json;

namespace HexSuture;

internal sealed record FindingReview(
    string FindingId,
    string RuleVersion,
    string Decision,
    string Reviewer,
    string Reason,
    DateTimeOffset ReviewedUtc,
    DateTimeOffset? ExpiresUtc,
    string? ArtifactSha256,
    string? ArtifactPath);

internal sealed record ReviewFinding(string Mode, ReplayEvent Event, string? DetectionId, string? Resource)
{
    public const string RuleVersion = "defender-detection/1";

    public string Id => Identifier(Mode, Event);

    internal static string Identifier(string mode, ReplayEvent item) =>
        Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
        {
            Mode = mode, Device = item.Device.ToUpperInvariant(), item.Channel, item.Provider,
            item.RecordId, item.OccurredUtc
        })));
}

internal static class FalsePositiveReview
{
    public static void Record(CaseStore store, string id, string decision, string[] arguments)
    {
        if (decision is not ("benign" or "malicious" or "uncertain"))
            throw new ArgumentException("Choose benign, malicious, or uncertain.");

        var options = ReadOptions(arguments);
        if (!options.TryGetValue("--reviewer", out var reviewer) ||
            !options.TryGetValue("--reason", out var reason))
            throw new ArgumentException("Supply a reviewer alias and a reason.");

        var finding = ScanEvidence.ReviewFindings(store.ObservedEvents().ToList())
            .SingleOrDefault(item => string.Equals(item.Id, id, StringComparison.OrdinalIgnoreCase))
            ?? throw new ArgumentException("No detection has this finding ID. Use show to find the ID.");

        var now = DateTimeOffset.UtcNow;
        DateTimeOffset? expires = null;
        if (options.TryGetValue("--until", out var until))
        {
            if (decision != "benign" || !DateTimeOffset.TryParseExact(until,
                ["yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"],
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed) || parsed <= now)
                throw new ArgumentException("A benign review can expire at a future UTC time such as 2027-01-01T12:00:00Z.");
            expires = parsed;
        }

        string? path = null;
        string? digest = null;
        if (options.TryGetValue("--file", out var file))
        {
            if (expires is null)
                throw new ArgumentException("A file-bound benign review needs --until.");
            path = Path.GetFullPath(file);
            if (finding.Mode == "live")
                CheckLiveResource(finding, path);
            digest = HashFile(path);
        }

        if (expires <= DateTimeOffset.UtcNow)
            throw new ArgumentException("The review expiry passed before the decision could be saved.");
        store.AddReview(new FindingReview(finding.Id, ReviewFinding.RuleVersion,
            decision, reviewer, reason, now, expires, digest, path));
    }

    public static IEnumerable<object> Queue(IEnumerable<ReviewFinding> findings,
        IReadOnlyList<FindingReview> reviews, DateTimeOffset now, string? checkFile)
    {
        var latest = reviews.GroupBy(review => review.FindingId)
            .ToDictionary(group => group.Key, group => group.Last(), StringComparer.Ordinal);
        string? path = checkFile is null ? null : Path.GetFullPath(checkFile);
        string? digest = null;
        if (path is not null && latest.Values.Any(review => review.ExpiresUtc > now && SamePath(review.ArtifactPath, path)))
        {
            try
            {
                digest = HashFile(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                // The queue keeps this finding open when current file contents cannot be checked.
            }
        }

        foreach (var finding in findings)
        {
            var review = latest.GetValueOrDefault(finding.Id);
            string status = ReviewStatus(review, now, path, digest);
            yield return new
            {
                findingId = finding.Id, finding.Mode, device = finding.Event.Device,
                detectionId = finding.DetectionId, recordId = finding.Event.RecordId,
                occurredUtc = finding.Event.OccurredUtc, ruleVersion = ReviewFinding.RuleVersion,
                status, needsReview = status != "reviewed", decision = review?.Decision,
                expiresUtc = review?.ExpiresUtc, artifactSha256 = review?.ArtifactSha256
            };
        }
    }

    private static string ReviewStatus(FindingReview? review, DateTimeOffset now, string? path, string? digest)
    {
        if (review is null || review.RuleVersion != ReviewFinding.RuleVersion)
            return "open";
        if (review.ExpiresUtc <= now)
            return "expired";
        if (review.Decision == "uncertain")
            return "uncertain";
        if (review.ArtifactSha256 is null)
            return "reviewed";
        if (path is null || !SamePath(review.ArtifactPath, path))
            return "verification-required";
        if (digest is null)
            return "file-unavailable";
        return digest == review.ArtifactSha256 ? "reviewed" : "file-changed";
    }

    private static Dictionary<string, string> ReadOptions(string[] arguments)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int index = 0; index < arguments.Length; index += 2)
        {
            string name = arguments[index];
            if (name is not ("--reviewer" or "--reason" or "--until" or "--file") ||
                index + 1 == arguments.Length || string.IsNullOrWhiteSpace(arguments[index + 1]) ||
                !options.TryAdd(name, arguments[index + 1].Trim()))
                throw new ArgumentException("Use each supported review option once with a nonempty value.");
        }
        return options;
    }

    private static void CheckLiveResource(ReviewFinding finding, string path)
    {
        var node = IPGlobalProperties.GetIPGlobalProperties();
        string dnsName = string.IsNullOrEmpty(node.DomainName) ? node.HostName : $"{node.HostName}.{node.DomainName}";
        if (!string.Equals(finding.Event.Device, Environment.MachineName, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(finding.Event.Device, dnsName, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Verify a live finding on the device that recorded it.");

        var resource = finding.Resource;
        if (resource is null || !resource.StartsWith("file:_", StringComparison.OrdinalIgnoreCase) ||
            resource.Contains(';') || !SamePath(resource[6..], path))
            throw new ArgumentException("Use the single file recorded in the detection, or review just the occurrence.");
    }

    private static bool SamePath(string? left, string right) =>
        string.Equals(left, right, OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static string HashFile(string path)
    {
        if (OperatingSystem.IsWindows() &&
            (path.Length < 3 || path[1] != ':' || new DriveInfo(path[..3]).DriveType is not (DriveType.Fixed or DriveType.Removable)))
            throw new InvalidDataException("Choose a file on a local drive.");

        for (string? component = path; component is not null; component = Path.GetDirectoryName(component))
        {
            if ((File.GetAttributes(component) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Choose a file with a path that contains no symbolic links or junctions.");
        }
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.Device)) != 0)
            throw new InvalidDataException("Choose a regular file to verify.");

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var info = new FileInfo(path);
        var lastWrite = info.LastWriteTimeUtc;
        var length = stream.Length;
        var digest = SHA256.HashData(stream);
        info.Refresh();
        if (length != info.Length || info.LastWriteTimeUtc != lastWrite)
            throw new InvalidDataException("The file changed during verification. Try again.");
        return Convert.ToHexStringLower(digest);
    }
}
