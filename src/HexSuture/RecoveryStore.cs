using System.Text.Json;

namespace HexSuture;

internal sealed partial class CaseStore
{
    private const string CreateRecovery = """
        CREATE TABLE cfa_coverage (
            device TEXT PRIMARY KEY COLLATE NOCASE,
            observed_utc TEXT NOT NULL,
            mode TEXT NOT NULL
        );
        CREATE TABLE restore_runs (
            id TEXT PRIMARY KEY,
            document TEXT NOT NULL
        );
        """;

    internal void SaveCfaCoverage(CfaCoverage state)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO cfa_coverage (device, observed_utc, mode) VALUES ($device, $time, $mode)
            ON CONFLICT (device) DO UPDATE SET observed_utc = excluded.observed_utc, mode = excluded.mode
            WHERE excluded.observed_utc >= cfa_coverage.observed_utc;
            """;
        command.Parameters.AddWithValue("$device", state.Device);
        command.Parameters.AddWithValue("$time", state.ObservedUtc.ToString("O"));
        command.Parameters.AddWithValue("$mode", state.Mode);
        command.ExecuteNonQuery();
    }

    internal IEnumerable<CfaCoverage> CfaSettings()
    {
        if (version < 6)
            yield break;
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT device, observed_utc, mode FROM cfa_coverage ORDER BY device;";
        using var rows = command.ExecuteReader();
        while (rows.Read())
            yield return new CfaCoverage(rows.GetString(0), rows.GetDateTimeOffset(1), rows.GetString(2));
    }

    internal void SaveRestoreRun(RestoreRun run)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO restore_runs (id, document) VALUES ($id, $document)
            ON CONFLICT (id) DO UPDATE SET document = excluded.document;
            """;
        command.Parameters.AddWithValue("$id", run.Id);
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(run));
        command.ExecuteNonQuery();
    }

    internal IEnumerable<RestoreRun> RestoreRuns()
    {
        if (version < 6)
            yield break;
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT document FROM restore_runs ORDER BY rowid;";
        using var rows = command.ExecuteReader();
        while (rows.Read())
            yield return JsonSerializer.Deserialize<RestoreRun>(rows.GetString(0))!;
    }
}
