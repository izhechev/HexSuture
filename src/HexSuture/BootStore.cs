using System.Text.Json;

namespace HexSuture;

internal sealed partial class CaseStore
{
    private const string CreateBootReview = """
        CREATE TABLE boot_states (
            mode TEXT NOT NULL,
            device TEXT NOT NULL COLLATE NOCASE,
            baseline INTEGER NOT NULL,
            captured_utc TEXT NOT NULL,
            document TEXT NOT NULL,
            PRIMARY KEY (mode, device, baseline)
        );
        CREATE TABLE offline_requests (
            id TEXT PRIMARY KEY,
            document TEXT NOT NULL
        );
        CREATE TABLE offline_results (
            schedule_id TEXT PRIMARY KEY,
            document TEXT NOT NULL
        );
        """;

    internal void SaveBootState(BootState state)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO boot_states (mode, device, baseline, captured_utc, document)
            VALUES ($mode, $device, $baseline, $time, $document)
            ON CONFLICT (mode, device, baseline) DO UPDATE SET
                captured_utc = excluded.captured_utc, document = excluded.document
            WHERE excluded.captured_utc >= boot_states.captured_utc;
            """;
        command.Parameters.AddWithValue("$mode", state.Mode);
        command.Parameters.AddWithValue("$device", state.Snapshot.Device);
        command.Parameters.AddWithValue("$baseline", state.Baseline);
        command.Parameters.AddWithValue("$time", state.Snapshot.CapturedUtc.ToString("O"));
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(state));
        command.ExecuteNonQuery();
    }

    internal void SaveOfflineRequest(OfflineRequest request)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO offline_requests (id, document) VALUES ($id, $document)
            ON CONFLICT (id) DO UPDATE SET document = excluded.document;
            """;
        command.Parameters.AddWithValue("$id", request.Id);
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(request));
        command.ExecuteNonQuery();
    }

    internal bool SaveOfflineResult(OfflineResult result)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO offline_results (schedule_id, document) VALUES ($id, $document)
            ON CONFLICT (schedule_id) DO NOTHING;
            """;
        command.Parameters.AddWithValue("$id", result.ScheduleId);
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(result));
        return command.ExecuteNonQuery() == 1;
    }

    internal IEnumerable<BootState> BootStates() =>
        ReadBootDocuments<BootState>("SELECT document FROM boot_states ORDER BY mode, device, baseline;");

    internal IEnumerable<OfflineRequest> OfflineRequests() =>
        ReadBootDocuments<OfflineRequest>("SELECT document FROM offline_requests ORDER BY rowid;");

    internal IEnumerable<OfflineResult> OfflineResults() =>
        ReadBootDocuments<OfflineResult>("SELECT document FROM offline_results ORDER BY rowid;");

    private IEnumerable<T> ReadBootDocuments<T>(string query)
    {
        if (version < 7)
            yield break;
        using var command = connection.CreateCommand();
        command.CommandText = query;
        using var rows = command.ExecuteReader();
        while (rows.Read())
            yield return JsonSerializer.Deserialize<T>(rows.GetString(0))!;
    }
}
