using System.Security.Cryptography;
using System.Text;

namespace HexSuture;

internal sealed record TaskSnapshot(string Fingerprint, bool Enabled, string Owner, string Permissions, string Definition);
internal sealed record TaskStep(string State, DateTimeOffset ObservedUtc, DateTimeOffset BootUtc, bool? Enabled);
internal sealed record TaskReview(string Id, string Device, string Actor, string Path, string Reason,
    TaskSnapshot Before, TaskStep[] History)
{
    public TaskStep Latest => History[^1];
}

internal interface ILocalTasks
{
    string Device { get; }
    string Actor { get; }
    DateTimeOffset BootUtc { get; }
    TaskSnapshot? Read(string path);
    void SetEnabled(string path, TaskSnapshot before, bool enabled);
    void DeleteDisabled(string path, TaskSnapshot before);
}

internal static class TaskCleanup
{
    internal static string Digest(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    internal static TaskReview Review(CaseStore store, ILocalTasks tasks, string path, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
            throw new ArgumentException("Enter the reason for reviewing this task.");
        string device = tasks.Device;
        using var mutex = Lock(tasks.Actor, path);
        var before = Present(tasks.Read(path));
        if (!before.Enabled)
            throw new InvalidDataException("Choose an enabled task so rollback can restore its original state.");
        var review = new TaskReview(Guid.NewGuid().ToString("D"), device, tasks.Actor, path, reason.Trim(), before,
            [new TaskStep("reviewed", DateTimeOffset.UtcNow, tasks.BootUtc, true)]);
        store.SaveTask(review);
        return review;
    }

    internal static TaskReview Run(CaseStore store, ILocalTasks tasks, string id, string operation)
    {
        var review = store.Task(id);
        using var mutex = Lock(tasks.Actor, review.Path);
        review = store.Task(id);
        if (review.Device != tasks.Device || review.Actor != tasks.Actor)
            throw new InvalidDataException("Use the originating Windows installation and the user who reviewed the task.");

        DateTimeOffset boot = tasks.BootUtc;
        string state = review.Latest.State;
        bool wasRemoving = state is "removing" or "removed";
        TaskSnapshot? current = tasks.Read(review.Path);
        if (current is null)
        {
            if (wasRemoving && operation is "remove" or "verify")
                return state == "removed" ? review : Save(store, review, "removed", boot, null);
            throw new InvalidDataException("The reviewed scheduled task is missing.");
        }
        if (state == "removed")
            throw new InvalidDataException("A task has returned at the removed path. Review the new task separately.");
        RequireSame(review.Before, current);

        return operation switch
        {
            "disable" => Disable(store, tasks, review, state, boot, current),
            "verify" => Verify(store, review, state, boot, current),
            "rollback" => Rollback(store, tasks, review, state, boot, current),
            "remove" => Remove(store, tasks, review, state, boot, current),
            _ => throw new ArgumentException("Unknown scheduled task operation.")
        };
    }

    private static TaskReview Disable(CaseStore store, ILocalTasks tasks, TaskReview review, string state,
        DateTimeOffset boot, TaskSnapshot current)
    {
        if (state is "disabled" or "verified")
        {
            RequireEnabled(current, false);
            return review;
        }
        if (state == "reviewed")
        {
            RequireEnabled(current, true);
            review = Save(store, review, "disabling", boot, true);
        }
        else if (state != "disabling")
            throw new InvalidDataException("Disable requires a fresh review or an interrupted disable.");

        if (current.Enabled)
            tasks.SetEnabled(review.Path, current, false);
        return RecordEnabled(store, tasks, review, "disabled", boot, false);
    }

    private static TaskReview Verify(CaseStore store, TaskReview review, string state,
        DateTimeOffset boot, TaskSnapshot current)
    {
        if (state is not ("disabled" or "verified"))
            throw new InvalidDataException("Finish disabling the task before verifying it.");
        RequireEnabled(current, false);
        var disabledBoot = review.History.Last(step => step.State == "disabled").BootUtc;
        if (boot <= disabledBoot)
            throw new InvalidDataException("Restart Windows before verifying the task.");
        return state == "verified" ? review : Save(store, review, "verified", boot, false);
    }

    private static TaskReview Rollback(CaseStore store, ILocalTasks tasks, TaskReview review, string state,
        DateTimeOffset boot, TaskSnapshot current)
    {
        if (state == "rolled-back")
        {
            RequireEnabled(current, true);
            return review;
        }
        if (state is "disabled" or "verified")
        {
            RequireEnabled(current, false);
            review = Save(store, review, "rolling-back", boot, false);
        }
        else if (state != "rolling-back")
            throw new InvalidDataException("Rollback requires a completed disable and a task that still exists.");

        if (!current.Enabled)
            tasks.SetEnabled(review.Path, current, true);
        return RecordEnabled(store, tasks, review, "rolled-back", boot, true);
    }

    private static TaskReview Remove(CaseStore store, ILocalTasks tasks, TaskReview review, string state,
        DateTimeOffset boot, TaskSnapshot current)
    {
        if (state is not ("verified" or "removing"))
            throw new InvalidDataException("Verify the disabled task after a restart before approving removal.");
        RequireEnabled(current, false);
        if (state == "verified")
            review = Save(store, review, "removing", boot, false);
        tasks.DeleteDisabled(review.Path, current);
        if (tasks.Read(review.Path) is not null)
            throw new InvalidDataException("The task still exists after the removal request.");
        return Save(store, review, "removed", boot, null);
    }

    private static TaskReview RecordEnabled(CaseStore store, ILocalTasks tasks, TaskReview review,
        string state, DateTimeOffset boot, bool enabled)
    {
        var current = Present(tasks.Read(review.Path));
        RequireSame(review.Before, current);
        RequireEnabled(current, enabled);
        return Save(store, review, state, boot, enabled);
    }

    private static TaskReview Save(CaseStore store, TaskReview review, string state, DateTimeOffset boot, bool? enabled)
    {
        var updated = review with { History = [.. review.History, new TaskStep(state, DateTimeOffset.UtcNow, boot, enabled)] };
        store.SaveTask(updated);
        return updated;
    }

    private static TaskSnapshot Present(TaskSnapshot? snapshot) =>
        snapshot ?? throw new InvalidDataException("The scheduled task is missing.");

    private static void RequireEnabled(TaskSnapshot current, bool enabled)
    {
        if (current.Enabled != enabled)
            throw new InvalidDataException("The scheduled task no longer has the expected enabled state.");
    }

    internal static void RequireSame(TaskSnapshot before, TaskSnapshot current)
    {
        if (before.Fingerprint == current.Fingerprint)
            return;
        var differences = new List<string>();
        if (before.Owner != current.Owner)
            differences.Add("owner");
        if (before.Permissions != current.Permissions)
            differences.Add("permissions");
        if (before.Definition != current.Definition)
            differences.Add("definition");
        throw new InvalidDataException($"Task identity changed after review ({string.Join(", ", differences)}). " +
            $"Expected {before.Fingerprint}, observed {current.Fingerprint}. Review it again.");
    }

    private static IDisposable Lock(string actor, string path)
    {
        string name = "Global\\HexSutureTask-" + Digest(actor + "|" + path.ToUpperInvariant());
        return new TaskLock(name);
    }

    private sealed class TaskLock : IDisposable
    {
        private readonly Mutex mutex;

        internal TaskLock(string name)
        {
            mutex = new Mutex(false, name);
            try
            {
                if (!mutex.WaitOne(TimeSpan.FromSeconds(15)))
                    throw new IOException("Another HexSuture operation is using this task.");
            }
            catch (AbandonedMutexException)
            {
                // The journal records the pending step left by the previous process.
            }
            catch
            {
                mutex.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            mutex.ReleaseMutex();
            mutex.Dispose();
        }
    }
}
