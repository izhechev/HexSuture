using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HexSuture;

internal sealed record BootSnapshot(string Device, DateTimeOffset CapturedUtc, DateTimeOffset? BootUtc,
    string Architecture, bool? Windows11Client, string SecureBoot, string WinRe, string Defender,
    string BitLocker, bool? Administrator);
internal sealed record BootState(string Mode, bool Baseline, BootSnapshot Snapshot);
internal sealed record OfflineRequest(string Id, string Device, DateTimeOffset BootUtc,
    DateTimeOffset RequestedUtc, string State);
internal sealed record OfflineResult(string ScheduleId, string Outcome, DateTimeOffset BootUtc,
    DateTimeOffset RecordedUtc, string Note);

internal static class BootReview
{
    private sealed record Scheduled(string Id, string Mode, ReplayEvent Event, DateTimeOffset Time);

    internal static void ImportState(CaseStore store, string path, bool baseline)
    {
        using var source = File.OpenRead(path);
        if (source.Length > 64 * 1024)
            throw new InvalidDataException("Boot snapshot files must be smaller than 64 KB.");
        var state = JsonSerializer.Deserialize<BootSnapshot>(source, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            AllowDuplicateProperties = false
        });
        if (state is null || string.IsNullOrWhiteSpace(state.Device) || state.CapturedUtc == default ||
            state.BootUtc > state.CapturedUtc || state.BootUtc == default(DateTimeOffset) ||
            state.Architecture is not ("x64" or "arm64" or "x86" or "unknown") ||
            state.SecureBoot is not ("enabled" or "disabled" or "legacy" or "unknown") ||
            state.WinRe is not ("enabled" or "disabled" or "unknown") ||
            state.Defender is not ("active" or "inactive" or "unknown") ||
            state.BitLocker is not ("protected" or "suspended" or "unencrypted" or "unknown"))
            throw new InvalidDataException("The saved boot snapshot is incomplete or has an invalid setting.");
        StoreState(store, "replay", baseline, state with
        {
            Device = state.Device.Trim(), CapturedUtc = state.CapturedUtc.ToUniversalTime(),
            BootUtc = state.BootUtc?.ToUniversalTime()
        });
    }

    internal static void StoreState(CaseStore store, string mode, bool baseline, BootSnapshot state)
    {
        if (baseline && state.SecureBoot == "unknown")
            throw new InvalidDataException("A boot baseline needs an observed Secure Boot state.");
        store.SaveBootState(new BootState(mode, baseline, state));
    }

    internal static string[] Preflight(BootSnapshot state, bool recoveryKeyReady)
    {
        var gaps = new List<string>();
        if (state.Architecture != "x64" || state.Windows11Client != true)
            gaps.Add("Defender Offline requires Windows 11 x64 client in this workflow.");
        if (state.Administrator != true)
            gaps.Add("Open the terminal as an administrator.");
        if (state.WinRe != "enabled")
            gaps.Add($"Windows Recovery Environment is {state.WinRe}.");
        if (state.Defender != "active")
            gaps.Add($"Microsoft Defender Antivirus is {state.Defender}.");
        if (state.BitLocker == "protected")
            gaps.Add("Handle BitLocker recovery and suspend protection through Windows before requesting the scan.");
        else if (state.BitLocker == "suspended" && !recoveryKeyReady)
            gaps.Add("Confirm access to the separate BitLocker recovery key with --recovery-key-ready.");
        else if (state.BitLocker == "unknown")
            gaps.Add("Windows did not confirm BitLocker recovery readiness.");
        if (state.BootUtc is null)
            gaps.Add("Windows did not report the current boot time.");
        return gaps.ToArray();
    }

    internal static void AttachResult(CaseStore store, string id, string outcome, string note)
    {
        if (outcome is not ("completed-no-detections" or "completed-detected" or "failed") ||
            string.IsNullOrWhiteSpace(note) || note.Length > 2000)
            throw new ArgumentException("Supply a valid outcome and a short note from the observed result.");

        var schedule = Schedules(store.ObservedEvents()).ToList();
        var selected = schedule.SingleOrDefault(item => item.Id == id)
            ?? throw new InvalidDataException("Choose a schedule ID reported for Defender event 2030.");
        var snapshot = CurrentStates(store.BootStates()).GetValueOrDefault(Key(selected.Mode, selected.Event.Device));
        if (snapshot?.BootUtc is not { } booted || booted <= selected.Time)
            throw new InvalidDataException("Save a boot snapshot from after the scheduling event before attaching a result.");
        if (schedule.Any(item => item.Mode == selected.Mode && SameDevice(item.Event.Device, selected.Event.Device) &&
            item.Time < booted && (item.Time > selected.Time ||
                (item.Time == selected.Time && item.Event.RecordId > selected.Event.RecordId))))
            throw new InvalidDataException("A newer schedule precedes that restart. Attach the result to the latest schedule.");
        var result = new OfflineResult(id, outcome, booted, DateTimeOffset.UtcNow, note.Trim());
        if (!store.SaveOfflineResult(result))
            throw new InvalidDataException("This scheduling event already has a recorded result.");
    }

    internal static object Report(IReadOnlyList<(string Mode, ReplayEvent Item)> events, CaseStore store,
        bool includeNotes)
    {
        var states = store.BootStates().ToList();
        var latest = CurrentStates(states);
        var baseline = states.Where(item => item.Baseline)
            .ToDictionary(item => Key(item.Mode, item.Snapshot.Device), item => item.Snapshot);
        var results = store.OfflineResults().ToDictionary(item => item.ScheduleId);
        var schedules = Schedules(events).ToArray();
        return new
        {
            firmwareIntegrity = "unverified",
            devices = latest.Select(row =>
            {
                var reference = baseline.GetValueOrDefault(row.Key);
                string status = reference is null ? "baseline-missing" :
                    row.Value.SecureBoot == "unknown" ? "unknown" :
                    reference.SecureBoot == row.Value.SecureBoot ? "matches-baseline" : "changed";
                return new { row.Key.Mode, state = row.Value, baseline = reference, configurationStatus = status,
                    needsReview = status is "changed" or "unknown",
                    offlinePreflight = Preflight(row.Value, recoveryKeyReady: false) };
            }),
            findings = ScanEvidence.BootFindings(events),
            requests = store.OfflineRequests().Select(request => new
            {
                request.Id, request.Device, request.RequestedUtc, request.BootUtc, request.State,
                schedulingEvidencePresent = schedules.Any(schedule => schedule.Mode == "live" &&
                    SameDevice(schedule.Event.Device, request.Device) && schedule.Time >= request.RequestedUtc &&
                    schedule.Time <= request.RequestedUtc.AddMinutes(15))
            }),
            schedulingFailures = events.Where(entry => entry.Item.EventId == 2031).Select(entry => new
            {
                entry.Mode, entry.Item.Device, entry.Item.RecordId, entry.Item.OccurredUtc,
                status = "schedule-failed", needsReview = true
            }),
            offlineScans = schedules.Select(row =>
            {
                var result = results.GetValueOrDefault(row.Id);
                var booted = latest.GetValueOrDefault(Key(row.Mode, row.Event.Device))?.BootUtc;
                string status = result?.Outcome ?? (booted.HasValue && booted.Value <= row.Time ? "scheduled" : "outcome-unknown");
                return new
                {
                    scheduleId = row.Id, row.Mode, row.Event.Device, row.Event.RecordId,
                    scheduledUtc = row.Time, schedulingStatus = "scheduled", status,
                    needsReview = result?.Outcome != "completed-no-detections",
                    outcomeSource = result is not null ? "operator-supplied" : null,
                    rebootUtc = result?.BootUtc ?? (booted > row.Time ? booted : null),
                    recordedUtc = result?.RecordedUtc, note = includeNotes ? result?.Note : null
                };
            })
        };
    }

    private static IEnumerable<Scheduled> Schedules(IEnumerable<(string Mode, ReplayEvent Item)> events) =>
        events.Where(entry => entry.Item.EventId == 2030)
            .Select(entry => new Scheduled(ReviewFinding.Identifier(entry.Mode, entry.Item), entry.Mode, entry.Item,
                DateTimeOffset.Parse(entry.Item.OccurredUtc, CultureInfo.InvariantCulture)));

    private static Dictionary<(string Mode, string Device), BootSnapshot> CurrentStates(IEnumerable<BootState> states) =>
        states.Where(item => !item.Baseline)
            .ToDictionary(item => Key(item.Mode, item.Snapshot.Device), item => item.Snapshot);

    private static (string Mode, string Device) Key(string mode, string device) => (mode, device.ToUpperInvariant());

    internal static bool SameDevice(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
