using System.Text.Json;

namespace HexSuture;

internal sealed partial class CaseStore
{
    private const string CreatePersistence = """
        CREATE TABLE startup_snapshots (
            slot TEXT PRIMARY KEY CHECK (slot IN ('baseline', 'current')),
            document TEXT NOT NULL
        );
        CREATE TABLE task_reviews (
            id TEXT PRIMARY KEY,
            document TEXT NOT NULL
        );
        """;

    public void SaveInventory(string slot, StartupSnapshot snapshot)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO startup_snapshots (slot, document) VALUES ($slot, $document)
            ON CONFLICT (slot) DO UPDATE SET document = excluded.document;
            """;
        command.Parameters.AddWithValue("$slot", slot);
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(snapshot));
        command.ExecuteNonQuery();
    }

    public StartupSnapshot Inventory(string slot)
    {
        if (version >= 4)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT document FROM startup_snapshots WHERE slot = $slot;";
            command.Parameters.AddWithValue("$slot", slot);
            if (command.ExecuteScalar() is string document)
                return JsonSerializer.Deserialize<StartupSnapshot>(document)!;
        }
        throw new InvalidDataException($"Import the {slot} startup inventory first.");
    }

    public void SaveTask(TaskReview review)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO task_reviews (id, document) VALUES ($id, $document)
            ON CONFLICT (id) DO UPDATE SET document = excluded.document;
            """;
        command.Parameters.AddWithValue("$id", review.Id);
        command.Parameters.AddWithValue("$document", JsonSerializer.Serialize(review));
        command.ExecuteNonQuery();
    }

    public TaskReview Task(string id)
    {
        if (version >= 4)
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT document FROM task_reviews WHERE id = $id;";
            command.Parameters.AddWithValue("$id", id);
            if (command.ExecuteScalar() is string document)
                return JsonSerializer.Deserialize<TaskReview>(document)!;
        }
        throw new InvalidDataException("No scheduled task review has that ID.");
    }
}
