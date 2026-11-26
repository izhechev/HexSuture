using HexSuture;

var directory = Directory.CreateTempSubdirectory("hexsuture-tasks-");
try
{
    var path = Path.Combine(directory.FullName, "case.db");
    var scheduler = new FakeTasks();
    using var store = new CaseStore(path, create: true);
    var review = TaskCleanup.Review(store, scheduler, @"\Fixture", "Harmless fixture");
    scheduler.Current = scheduler.Current! with { Fingerprint = "changed", Definition = "<changed />" };
    Reject(() => TaskCleanup.Run(store, scheduler, review.Id, "disable"), "identity changed");
    Assert(scheduler.Writes == 0, "Changed task was written.");
    scheduler.Current = review.Before;
    scheduler.InterruptNextWrite = true;
    Reject(() => TaskCleanup.Run(store, scheduler, review.Id, "disable"), "simulated interruption");
    Assert(store.Task(review.Id).Latest.State == "disabling" && scheduler.Current is { Enabled: false }, "Pending step was lost.");

    using var reopened = new CaseStore(path, create: true);
    var disabled = TaskCleanup.Run(reopened, scheduler, review.Id, "disable");
    Assert(disabled.Latest.State == "disabled" && scheduler.Writes == 1, "Retry duplicated the write.");
    Reject(() => TaskCleanup.Run(reopened, scheduler, review.Id, "verify"), "Restart Windows");
    Reject(() => TaskCleanup.Run(reopened, scheduler, review.Id, "remove"), "after a restart");
    scheduler.BootUtc = scheduler.BootUtc.AddHours(1);
    Assert(TaskCleanup.Run(reopened, scheduler, review.Id, "verify").Latest.State == "verified", "Verification failed.");
    Assert(TaskCleanup.Run(reopened, scheduler, review.Id, "rollback").Latest.State == "rolled-back" &&
        scheduler.Current!.Enabled, "Rollback failed.");

    var removal = TaskCleanup.Review(reopened, scheduler, @"\Fixture", "Independent removal run");
    TaskCleanup.Run(reopened, scheduler, removal.Id, "disable");
    scheduler.BootUtc = scheduler.BootUtc.AddHours(1);
    TaskCleanup.Run(reopened, scheduler, removal.Id, "verify");
    scheduler.InterruptNextWrite = true;
    Reject(() => TaskCleanup.Run(reopened, scheduler, removal.Id, "remove"), "simulated interruption");
    Assert(scheduler.Current is null && reopened.Task(removal.Id).Latest.State == "removing", "Removal attempt was lost.");
    Assert(TaskCleanup.Run(reopened, scheduler, removal.Id, "remove").Latest.State == "removed" &&
        scheduler.Deletions == 1, "Removal retry issued a second delete.");
    scheduler.Current = removal.Before;
    Reject(() => TaskCleanup.Run(reopened, scheduler, removal.Id, "verify"), "returned");
    Console.WriteLine("Task workflow passed with simulated reboots, interruption, rollback, and removal.");
}
finally
{
    directory.Delete(recursive: true);
}

static void Assert(bool condition, string problem)
{
    if (!condition)
        throw new Exception(problem);
}

static void Reject(Action action, string expected)
{
    try
    {
        action();
    }
    catch (Exception error) when (error.Message.Contains(expected, StringComparison.OrdinalIgnoreCase))
    {
        return;
    }
    throw new Exception($"Expected rejection containing {expected}.");
}

internal sealed class FakeTasks : ILocalTasks
{
    public string Device => "fixture-device";
    public string Actor => "fixture-user";
    public DateTimeOffset BootUtc { get; set; } = DateTimeOffset.UtcNow.AddHours(-1);
    public TaskSnapshot? Current { get; set; } = new("original", true, "fixture-user", "permissions", "<task />");
    public int Writes { get; private set; }
    public int Deletions { get; private set; }
    public bool InterruptNextWrite { get; set; }

    public TaskSnapshot? Read(string path) => Current;

    public void SetEnabled(string path, TaskSnapshot before, bool enabled)
    {
        Writes++;
        Current = before with { Enabled = enabled };
        Interrupt();
    }

    public void DeleteDisabled(string path, TaskSnapshot before)
    {
        Deletions++;
        Current = null;
        Interrupt();
    }

    private void Interrupt()
    {
        if (!InterruptNextWrite)
            return;
        InterruptNextWrite = false;
        throw new IOException("simulated interruption");
    }
}
