using Microsoft.Data.Sqlite;

namespace HexSuture;

internal sealed partial class CaseStore : IDisposable
{
    private const int ApplicationId = 0x48585355;
    private const int SchemaVersion = 4;
    private const string CreateObservations = """
        CREATE TABLE observations_v2 (
            device TEXT NOT NULL COLLATE NOCASE,
            channel TEXT NOT NULL COLLATE NOCASE,
            provider TEXT NOT NULL COLLATE NOCASE,
            record_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            occurred_utc TEXT NOT NULL,
            facts_json TEXT NOT NULL,
            origin TEXT NOT NULL CHECK (origin IN ('live', 'replay')),
            PRIMARY KEY (device, channel, provider, record_id, occurred_utc, origin)
        );
        """;
    private const string CreateScanRequests = """
        CREATE TABLE scan_requests (
            id TEXT PRIMARY KEY NOT NULL,
            device TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('folder', 'quick', 'full')),
            folder TEXT,
            requested_utc TEXT NOT NULL,
            engine_version TEXT,
            signature_version TEXT,
            ended_utc TEXT,
            exit_code INTEGER,
            error TEXT,
            CHECK ((kind = 'folder') = (folder IS NOT NULL))
        );
        """;
    private const string CreateReviews = """
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY,
            finding_id TEXT NOT NULL,
            rule_version TEXT NOT NULL,
            decision TEXT NOT NULL CHECK (decision IN ('benign', 'malicious', 'uncertain')),
            reviewer TEXT NOT NULL,
            reason TEXT NOT NULL,
            reviewed_utc TEXT NOT NULL,
            expires_utc TEXT,
            artifact_sha256 TEXT,
            artifact_path TEXT,
            CHECK ((artifact_sha256 IS NULL) = (artifact_path IS NULL))
        );
        """;
    private readonly long version;
    private readonly SqliteConnection connection;

    public CaseStore(string databasePath, bool create, bool allowCreate = true)
    {
        var path = Path.GetFullPath(databasePath);
        if (create && allowCreate && !File.Exists(path))
        {
            CreateCase(path);
        }

        connection = ConnectionFor(path, create ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly);
        try
        {
            connection.Open();
            using var transaction = create ? connection.BeginTransaction() : null;
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "PRAGMA application_id";
            if (!Equals(command.ExecuteScalar(), (long)ApplicationId))
            {
                throw new InvalidDataException("This file is not a HexSuture case.");
            }

            command.CommandText = "PRAGMA user_version";
            version = (long)command.ExecuteScalar()!;
            if (version is < 1 or > SchemaVersion)
            {
                throw new InvalidDataException("Unsupported HexSuture case version.");
            }

            if (version == 1 && create)
            {
                command.CommandText = $"""
                    {CreateObservations}
                    INSERT INTO observations_v2
                        (device, channel, provider, record_id, event_id, occurred_utc, facts_json, origin)
                    SELECT device, channel, provider, record_id, event_id, occurred_utc, facts_json, origin
                        FROM observations;
                    DROP TABLE observations;
                    ALTER TABLE observations_v2 RENAME TO observations;
                    {CreateScanRequests}
                    """;
                command.ExecuteNonQuery();
            }
            if (version < 3 && create)
            {
                command.CommandText = CreateReviews;
                command.ExecuteNonQuery();
            }
            if (version < SchemaVersion && create)
            {
                command.CommandText = $"""
                    {CreatePersistence}
                    PRAGMA user_version = {SchemaVersion};
                    """;
                command.ExecuteNonQuery();
                version = SchemaVersion;
            }
            transaction?.Commit();
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
                    {CreateObservations}
                    ALTER TABLE observations_v2 RENAME TO observations;
                    {CreateScanRequests}
                    {CreateReviews}
                    {CreatePersistence}
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

    public bool Add(ReplayEvent item) => AddObservation(item, "replay");

    public bool AddLive(ReplayEvent item) => AddObservation(item, "live");

    private bool AddObservation(ReplayEvent item, string origin)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO observations (device, channel, provider, record_id, event_id, occurred_utc, facts_json, origin)
            VALUES ($device, $channel, $provider, $record, $event, $time, $facts, $origin)
            ON CONFLICT (device, channel, provider, record_id, occurred_utc, origin) DO NOTHING;
            """;
        command.Parameters.AddWithValue("$device", item.Device);
        command.Parameters.AddWithValue("$channel", item.Channel);
        command.Parameters.AddWithValue("$provider", item.Provider);
        command.Parameters.AddWithValue("$record", item.RecordId);
        command.Parameters.AddWithValue("$event", item.EventId);
        command.Parameters.AddWithValue("$time", item.OccurredUtc);
        command.Parameters.AddWithValue("$facts", item.FactsJson);
        command.Parameters.AddWithValue("$origin", origin);
        bool added = command.ExecuteNonQuery() == 1;
        if (!added)
        {
            command.CommandText = """
                SELECT event_id = $event AND facts_json = $facts FROM observations
                WHERE device = $device AND channel = $channel AND provider = $provider
                  AND record_id = $record AND occurred_utc = $time AND origin = $origin;
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

    public IEnumerable<(string Mode, ReplayEvent Item)> ObservedEvents()
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT device, channel, provider, record_id, event_id, occurred_utc, facts_json, origin
            FROM observations ORDER BY occurred_utc, device, channel, provider, record_id, origin;
            """;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            yield return (rows.GetString(7), new ReplayEvent(
                rows.GetString(0), rows.GetString(1), rows.GetString(2), rows.GetInt64(3),
                rows.GetInt32(4), rows.GetString(5), rows.GetString(6)));
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

    public void StartScan(ScanRequest request)
    {
        if (request.EndedUtc is not null || request.ExitCode is not null || request.Error is not null)
            throw new ArgumentException("A new scan request cannot have a prior outcome.");

        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO scan_requests (id, device, kind, folder, requested_utc, engine_version, signature_version)
            VALUES ($id, $device, $kind, $folder, $requested, $engine, $signature);
            """;
        command.Parameters.AddWithValue("$id", request.Id);
        command.Parameters.AddWithValue("$device", request.Device);
        command.Parameters.AddWithValue("$kind", request.Kind);
        command.Parameters.AddWithValue("$folder", (object?)request.Folder ?? DBNull.Value);
        command.Parameters.AddWithValue("$requested", request.RequestedUtc);
        command.Parameters.AddWithValue("$engine", (object?)request.EngineVersion ?? DBNull.Value);
        command.Parameters.AddWithValue("$signature", (object?)request.SignatureVersion ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    public void FinishScan(string id, string endedUtc, int? exitCode, string? error)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE scan_requests SET ended_utc = $ended, exit_code = $code, error = $error
            WHERE id = $id AND (ended_utc IS NULL OR
                (ended_utc = $ended AND exit_code IS $code AND error IS $error));
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$ended", endedUtc);
        command.Parameters.AddWithValue("$code", (object?)exitCode ?? DBNull.Value);
        command.Parameters.AddWithValue("$error", (object?)error ?? DBNull.Value);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidDataException("The scan request is missing or already has another outcome.");
    }

    public IEnumerable<ScanRequest> ScanRequests()
    {
        if (version < 2)
            yield break;

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, device, kind, folder, requested_utc, engine_version, signature_version,
                   ended_utc, exit_code, error
            FROM scan_requests ORDER BY requested_utc, id;
            """;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            yield return new ScanRequest(
                rows.GetString(0), rows.GetString(1), rows.GetString(2), OptionalText(rows, 3),
                rows.GetString(4), OptionalText(rows, 5), OptionalText(rows, 6), OptionalText(rows, 7),
                rows.IsDBNull(8) ? null : rows.GetInt32(8), OptionalText(rows, 9));
        }
    }

    private static string? OptionalText(SqliteDataReader rows, int ordinal) =>
        rows.IsDBNull(ordinal) ? null : rows.GetString(ordinal);

    public void AddReview(FindingReview review)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO reviews
                (finding_id, rule_version, decision, reviewer, reason, reviewed_utc,
                 expires_utc, artifact_sha256, artifact_path)
            VALUES ($finding, $rule, $decision, $reviewer, $reason, $reviewed, $expires, $hash, $path);
            """;
        command.Parameters.AddWithValue("$finding", review.FindingId);
        command.Parameters.AddWithValue("$rule", review.RuleVersion);
        command.Parameters.AddWithValue("$decision", review.Decision);
        command.Parameters.AddWithValue("$reviewer", review.Reviewer);
        command.Parameters.AddWithValue("$reason", review.Reason);
        command.Parameters.AddWithValue("$reviewed", review.ReviewedUtc.ToString("O"));
        command.Parameters.AddWithValue("$expires", (object?)review.ExpiresUtc?.ToString("O") ?? DBNull.Value);
        command.Parameters.AddWithValue("$hash", (object?)review.ArtifactSha256 ?? DBNull.Value);
        command.Parameters.AddWithValue("$path", (object?)review.ArtifactPath ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    public IEnumerable<FindingReview> Reviews()
    {
        if (version < 3)
            yield break;

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT finding_id, rule_version, decision, reviewer, reason, reviewed_utc,
                   expires_utc, artifact_sha256, artifact_path
            FROM reviews ORDER BY id;
            """;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            yield return new FindingReview(rows.GetString(0), rows.GetString(1), rows.GetString(2),
                rows.GetString(3), rows.GetString(4), rows.GetDateTimeOffset(5),
                rows.IsDBNull(6) ? null : rows.GetDateTimeOffset(6),
                OptionalText(rows, 7), OptionalText(rows, 8));
        }
    }

    public void Dispose() => connection.Dispose();
}
