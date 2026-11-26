using System.ComponentModel;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace HexSuture;

internal sealed record FilelessAction(long RecordId, int EventId, string OccurredUtc, string Action, string Status);
internal sealed record FilelessFinding(string FindingId, string Mode, string Device, string? DetectionId,
    string Kind, string Source, string? ThreatName, string? Process, string DetectedUtc,
    FilelessAction[] Timeline);
internal sealed record FilelessFollowUp(string FindingId, string ReviewId, DateTimeOffset TaskStepUtc,
    DateTimeOffset CheckedUtc, string Status);

internal static class FilelessReview
{
    [SupportedOSPlatform("windows")]
    internal static int CheckTask(CaseStore store, string findingId, string reviewId)
    {
        var finding = ScanEvidence.FilelessFindings(store.ObservedEvents().ToList())
            .SingleOrDefault(item => string.Equals(item.FindingId, findingId, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidDataException("No fileless finding has that ID.");
        var review = store.Task(reviewId);
        if (finding.Mode != "live" || !IsLocal(finding.Device))
            throw new InvalidDataException("Check linked tasks on the Windows computer that recorded the live detection.");

        string state;
        try
        {
            var tasks = new WindowsTasks();
            if (review.Device != tasks.Device || review.Actor != tasks.Actor)
                throw new InvalidDataException("Use the same Windows installation and user as the task review.");

            var current = tasks.Read(review.Path);
            if (current is not null)
                TaskCleanup.RequireSame(review.Before, current);
            state = current switch
            {
                null when review.Latest.State == "removed" => "removed",
                null => "unknown",
                { Enabled: true } => "active",
                _ when review.Latest.State == "verified" => "disabled-after-restart",
                _ => "restart-verification-needed"
            };
        }
        catch (Exception ex) when (ex is InvalidDataException or COMException or ManagementException
            or UnauthorizedAccessException or IdentityNotMappedException or Win32Exception
            or System.Xml.XmlException or System.Security.SecurityException)
        {
            state = "unknown";
            Console.Error.WriteLine($"Task follow-up could not establish the current state: {ex.Message}");
        }

        store.SaveFollowUp(new FilelessFollowUp(finding.FindingId, review.Id, review.Latest.ObservedUtc,
            DateTimeOffset.UtcNow, state));
        Console.WriteLine($"Linked task follow-up: {state}.");
        return state == "unknown" ? 1 : 0;
    }

    internal static IEnumerable<object> Report(IEnumerable<FilelessFinding> findings,
        IEnumerable<FilelessFollowUp> followUps, Func<string, TaskReview> task, bool includePaths)
    {
        var linked = followUps.ToLookup(item => item.FindingId);
        foreach (var finding in findings)
        {
            var followUp = linked[finding.FindingId].Select(check => new
            {
                taskReviewId = check.ReviewId, check.CheckedUtc,
                status = task(check.ReviewId).Latest.ObservedUtc == check.TaskStepUtc ? check.Status : "check-needed"
            }).ToArray();

            var latest = finding.Timeline.Last();
            string remediation = latest.Status == "detected" ? "unknown" : latest.Status;
            bool open = remediation != "remediated" ||
                followUp.Any(item => item.status is not ("removed" or "disabled-after-restart"));

            yield return new
            {
                finding.FindingId, finding.Mode, finding.Device, finding.DetectionId,
                finding.Kind, finding.Source, finding.ThreatName, finding.DetectedUtc,
                processName = ProcessName(finding.Process),
                processPath = includePaths ? finding.Process : null,
                remediation, status = open ? "open" : "closed",
                followUp, timeline = finding.Timeline
            };
        }
    }

    private static string? ProcessName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        var name = path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
        return name.Length <= 100 && Regex.IsMatch(name, @"\A[A-Za-z0-9_. -]+\.exe\z",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking) ? name : null;
    }

    [SupportedOSPlatform("windows")]
    private static bool IsLocal(string device)
    {
        var ip = IPGlobalProperties.GetIPGlobalProperties();
        string dnsName = string.IsNullOrEmpty(ip.DomainName) ? ip.HostName : $"{ip.HostName}.{ip.DomainName}";
        return string.Equals(device, Environment.MachineName, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(device, dnsName, StringComparison.OrdinalIgnoreCase);
    }
}
