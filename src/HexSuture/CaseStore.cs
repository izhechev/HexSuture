using Microsoft.Data.Sqlite;

namespace HexSuture;

internal sealed class CaseStore : IDisposable
{
    private const int ApplicationId = 0x48585355;
    private const int SchemaVersion = 1;
    private readonly SqliteConnection connection;

    public CaseStore(string databasePath, bool create)
    {
        var path = Path.GetFullPath(databasePath);
        if (create && !File.Exists(path))
        {
            CreateCase(path);
        }

        connection = ConnectionFor(path, create ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly);
        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA application_id";
            if (!Equals(command.ExecuteScalar(), (long)ApplicationId))
            {
                throw new InvalidDataException("This file is not a HexSuture case.");
            }

            command.CommandText = "PRAGMA user_version";
            if (!Equals(command.ExecuteScalar(), (long)SchemaVersion))
            {
                throw new InvalidDataException("Unsupported HexSuture case version.");
            }
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static SqliteConnection ConnectionFor(string path, SqliteOpenMode mode)
    {
        var settings = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = mode,
            Pooling = false
        };
        return new SqliteConnection(settings.ConnectionString);
    }

    private static void CreateCase(string path)
    {
        var tempPath = Path.Combine(Path.GetDirectoryName(path)!, Path.GetRandomFileName());
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        File.Open(tempPath, options).Dispose();
        try
        {
            using (var newCase = ConnectionFor(tempPath, SqliteOpenMode.ReadWrite))
            {
                newCase.Open();
                using var command = newCase.CreateCommand();
                command.CommandText = $"""
                    PRAGMA application_id = {ApplicationId};
                    PRAGMA user_version = {SchemaVersion};
                    CREATE TABLE observations (
                        device TEXT NOT NULL COLLATE NOCASE,
                        channel TEXT NOT NULL COLLATE NOCASE,
                        provider TEXT NOT NULL COLLATE NOCASE,
                        record_id INTEGER NOT NULL,
                        event_id INTEGER NOT NULL,
                        occurred_utc TEXT NOT NULL,
                        facts_json TEXT NOT NULL,
                        origin TEXT NOT NULL DEFAULT 'replay' CHECK (origin = 'replay'),
                        PRIMARY KEY (device, channel, provider, record_id, occurred_utc)
                    );
                    CREATE TABLE source_gaps (
                        source_name TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        PRIMARY KEY (source_name, reason)
                    );
                    """;
                command.ExecuteNonQuery();
            }

            try
            {
                File.Move(tempPath, path);
            }
            catch (IOException) when (File.Exists(path))
            {
                // A concurrent creator won. The caller validates that case before using it.
            }
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    public bool Add(ReplayEvent item)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO observations (device, channel, provider, record_id, event_id, occurred_utc, facts_json)
            VALUES ($device, $channel, $provider, $record, $event, $time, $facts)
            ON CONFLICT (device, channel, provider, record_id, occurred_utc) DO NOTHING;
            """;
        command.Parameters.AddWithValue("$device", item.Device);
        command.Parameters.AddWithValue("$channel", item.Channel);
        command.Parameters.AddWithValue("$provider", item.Provider);
        command.Parameters.AddWithValue("$record", item.RecordId);
        command.Parameters.AddWithValue("$event", item.EventId);
        command.Parameters.AddWithValue("$time", item.OccurredUtc);
        command.Parameters.AddWithValue("$facts", item.FactsJson);
        bool added = command.ExecuteNonQuery() == 1;
        if (!added)
        {
            command.CommandText = """
                SELECT event_id = $event AND facts_json = $facts FROM observations
                WHERE device = $device AND channel = $channel AND provider = $provider
                  AND record_id = $record AND occurred_utc = $time;
                """;
            if (!Equals(command.ExecuteScalar(), 1L))
            {
                throw new InvalidDataException("Different evidence already exists for this event identity.");
            }
        }

        transaction.Commit();
        return added;
    }

    public void FlagSource(string sourceName, string reason)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO source_gaps (source_name, reason) VALUES ($source, $reason)
            ON CONFLICT (source_name, reason) DO NOTHING;
            """;
        command.Parameters.AddWithValue("$source", sourceName);
        command.Parameters.AddWithValue("$reason", reason);
        command.ExecuteNonQuery();
    }

    public IEnumerable<ReplayEvent> Observations()
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT device, channel, provider, record_id, event_id, occurred_utc, facts_json
            FROM observations ORDER BY occurred_utc, device, channel, provider, record_id;
            """;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            yield return new ReplayEvent(
                rows.GetString(0), rows.GetString(1), rows.GetString(2), rows.GetInt64(3),
                rows.GetInt32(4), rows.GetString(5), rows.GetString(6));
        }
    }

    public IEnumerable<(string SourceName, string Reason)> SourceGaps()
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT source_name, reason FROM source_gaps ORDER BY source_name, reason";
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            yield return (rows.GetString(0), rows.GetString(1));
        }
    }

    public void Dispose() => connection.Dispose();
}
