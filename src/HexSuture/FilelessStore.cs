using System.Text.Json;

namespace HexSuture;

internal sealed partial class CaseStore
{
    private const string CreateFilelessFollowUps = """
        CREATE TABLE fileless_followups (
            finding_id TEXT NOT NULL,
            review_id TEXT NOT NULL,
            checked_utc TEXT NOT NULL,
            document TEXT NOT NULL,
            PRIMARY KEY (finding_id, review_id)
        );
        """;

    public void SaveFollowUp(FilelessFollowUp check)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO fileless_followups (finding_id, review_id, checked_utc, document)
            VALUES ($finding, $review, $time, $document)
            ON CONFLICT (finding_id, review_id) DO UPDATE SET
                checked_utc = excluded.checked_utc, document = excluded.document
            WHERE excluded.checked_utc >= fileless_followups.checked_utc;
            """;
        command.Parameters.AddWithValue("$finding", check.FindingId);
        command.Parameters.AddWithValue("$review", check.ReviewId);
        command.Parameters.AddWithValue("$time", check.CheckedUtc.ToString("O"));
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(check));
        command.ExecuteNonQuery();
    }

    public IEnumerable<FilelessFollowUp> FilelessFollowUps()
    {
        if (version < 5)
            yield break;
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT document FROM fileless_followups ORDER BY finding_id, review_id;";
        using var rows = command.ExecuteReader();
        while (rows.Read())
            yield return JsonSerializer.Deserialize<FilelessFollowUp>(rows.GetString(0))!;
    }
}
