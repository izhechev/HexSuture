using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace HexSuture;

internal sealed record BackupFile(string Path, string Sha256);
internal sealed record BackupManifest(string BackupVersion, BackupFile[] Files);
internal sealed record RestoreItem(string Path, string ExpectedSha256, string? ActualSha256, string Status);
internal sealed record RestoreRun(string Id, string BackupVersion, string ManifestSha256, string Backup, string Destination,
    DateTimeOffset StartedUtc, long? ElapsedMilliseconds, int Requested, RestoreItem[] Items)
{
    public int Matched => Items.Count(item => item.Status == "matched");
}

internal static class BackupRecovery
{
    private static readonly JsonSerializerOptions ManifestOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false
    };

    internal static RestoreRun Run(string casePath, string backup, string manifest, string destination)
    {
        casePath = FullPath(casePath);
        backup = FullPath(backup);
        manifest = FullPath(manifest);
        destination = FullPath(destination);
        if (IsWithin(backup, destination) || IsWithin(destination, backup) ||
            IsWithin(manifest, backup) || IsWithin(manifest, destination) ||
            IsWithin(casePath, backup) || IsWithin(casePath, destination) || SamePath(casePath, manifest))
            throw new InvalidDataException("Keep the case and trusted manifest outside the separate backup and restore directories.");

        var parent = Path.GetDirectoryName(destination);
        if (parent is null || !IsDirectory(Inspect(parent)))
            throw new InvalidDataException("Choose a new restore directory under an existing trusted parent.");
        Inspect(casePath);
        if (Inspect(manifest) is not { } manifestAttributes || IsDirectory(manifestAttributes))
            throw new InvalidDataException("The independent backup manifest is unavailable.");
        var (plan, manifestHash) = ReadManifest(manifest);

        // Serialize retries for this destination across HexSuture processes on this computer.
        using var mutex = new Mutex(false, "HexSutureRestore-" + TaskCleanup.Digest(destination.ToUpperInvariant()));
        try
        {
            if (!mutex.WaitOne(TimeSpan.FromSeconds(15)))
                throw new IOException("Another recovery operation is using this destination.");
        }
        catch (AbandonedMutexException)
        {
            // The saved run lets the next process check any files already published.
        }

        try
        {
            using var store = new CaseStore(casePath, create: true);
            var previous = store.RestoreRuns().FirstOrDefault(run => SamePath(run.Destination, destination));
            if (previous is not null && (!SamePath(previous.Backup, backup) || previous.ManifestSha256 != manifestHash))
                throw new InvalidDataException("Use a new destination for a different backup or manifest.");
            if (Inspect(destination) is { } existing && (previous is null || !IsDirectory(existing)))
                throw new InvalidDataException("Choose a new destination. The existing path was preserved.");

            var run = previous ?? new RestoreRun(Guid.NewGuid().ToString("D"), plan.BackupVersion, manifestHash,
                backup, destination, DateTimeOffset.UtcNow, null, plan.Files.Length, []);
            store.SaveRestoreRun(run with { ElapsedMilliseconds = null, Items = [] });
            var elapsed = Stopwatch.StartNew();
            RestoreItem[] items;
            string? backupProblem = BackupProblem(backup);
            if (backupProblem is not null)
            {
                items = plan.Files.Select(file => Item(file, backupProblem)).ToArray();
            }
            else
            {
                Directory.CreateDirectory(destination);
                Inspect(destination);
                items = plan.Files.Select(file => RestoreFile(backup, destination, file)).ToArray();
            }
            run = run with { ElapsedMilliseconds = elapsed.ElapsedMilliseconds, Items = items };
            store.SaveRestoreRun(run);
            return run;
        }
        finally
        {
            mutex.ReleaseMutex();
        }
    }

    internal static object Report(RestoreRun run, bool includePaths) => new
    {
        run.Id, run.BackupVersion, run.ManifestSha256, run.StartedUtc, run.ElapsedMilliseconds,
        run.Requested, run.Matched,
        mismatches = Count(run, "hash-mismatch"),
        missing = Count(run, "missing"),
        unavailable = Count(run, "backup-unavailable"),
        destinationConflicts = Count(run, "destination-exists"),
        unsafePaths = Count(run, "unsafe-path"),
        errors = Count(run, "read-or-write-error"),
        status = run.ElapsedMilliseconds is null ? "pending" :
            run.Matched == run.Requested ? "verified" : "incomplete",
        backup = includePaths ? run.Backup : null,
        destination = includePaths ? run.Destination : null,
        items = run.Items.Select(item => new
        {
            path = includePaths ? item.Path : null,
            item.ExpectedSha256, item.ActualSha256, item.Status
        })
    };

    private static int Count(RestoreRun run, string status) => run.Items.Count(item => item.Status == status);

    private static string? BackupProblem(string path)
    {
        try
        {
            return IsDirectory(Inspect(path)) ? null : "backup-unavailable";
        }
        catch (InvalidDataException)
        {
            return "unsafe-path";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "backup-unavailable";
        }
    }

    private static RestoreItem RestoreFile(string backup, string destination, BackupFile file)
    {
        string relative = file.Path.Replace('/', Path.DirectorySeparatorChar);
        string from = Path.GetFullPath(Path.Combine(backup, relative));
        string to = Path.GetFullPath(Path.Combine(destination, relative));
        if (!IsWithin(from, backup) || !IsWithin(to, destination))
            return Item(file, "unsafe-path");

        try
        {
            if (Inspect(to) is { } existing)
            {
                if (IsDirectory(existing))
                    return Item(file, "destination-exists");
                using var existingFile = File.OpenRead(to);
                string existingHash = Hash(existingFile);
                return Item(file, existingHash == file.Sha256 ? "matched" : "destination-exists", existingHash);
            }

            if (Inspect(from) is not { } sourceAttributes || IsDirectory(sourceAttributes))
                return Item(file, "missing");

            string parent = Path.GetDirectoryName(to)!;
            Directory.CreateDirectory(parent);
            Inspect(parent);
            return CopyVerified(from, to, parent, file);
        }
        catch (InvalidDataException)
        {
            return Item(file, "unsafe-path");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Item(file, "read-or-write-error");
        }
    }

    private static RestoreItem CopyVerified(string source, string destination, string parent, BackupFile file)
    {
        string temporary = Path.Combine(parent, ".hexsuture-" + Guid.NewGuid().ToString("N") + ".tmp");
        bool created = false;
        try
        {
            string actual;
            using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var staged = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                created = true;
                input.CopyTo(staged);
                staged.Flush(flushToDisk: true);
                staged.Position = 0;
                actual = Hash(staged);
            }
            if (actual != file.Sha256)
                return Item(file, "hash-mismatch", actual);

            Inspect(parent);
            if (Inspect(destination) is not null)
                return Item(file, "destination-exists");
            File.Move(temporary, destination, overwrite: false);
            created = false;
            return Item(file, "matched", actual);
        }
        finally
        {
            if (created)
                File.Delete(temporary);
        }
    }

    private static RestoreItem Item(BackupFile file, string status, string? actual = null) =>
        new(file.Path, file.Sha256, actual, status);

    private static (BackupManifest, string) ReadManifest(string path)
    {
        using var input = File.OpenRead(path);
        if (input.Length > 8 * 1024 * 1024)
            throw new InvalidDataException("The backup manifest exceeds 8 MB.");
        int length = checked((int)input.Length);
        var bytes = new byte[length];
        input.ReadExactly(bytes);
        if (input.ReadByte() != -1)
            throw new InvalidDataException("The backup manifest changed while reading it.");

        ReadOnlySpan<byte> json = bytes;
        if (json.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }))
            json = json[3..];
        var plan = JsonSerializer.Deserialize<BackupManifest>(json, ManifestOptions);
        if (plan?.BackupVersion is not { Length: > 0 and <= 80 } || plan.Files is not { Length: > 0 and <= 10000 } ||
            !plan.BackupVersion.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'))
            throw new InvalidDataException("The manifest needs a backup version and between 1 and 10,000 files.");

        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var folders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in plan.Files)
        {
            if (file?.Path is not { Length: > 0 and <= 1024 } || file.Sha256 is not { Length: 64 } ||
                !file.Sha256.All(char.IsAsciiHexDigit))
                throw new InvalidDataException("Each manifest file needs a relative path and a SHA-256 hash.");

            var parts = file.Path.Split('/');
            if (parts.Any(UnsafeComponent))
                throw new InvalidDataException("The manifest contains an unsafe relative path.");
            if (!files.Add(file.Path) || folders.Contains(file.Path))
                throw new InvalidDataException("The manifest contains overlapping or duplicate paths.");
            for (int slash = file.Path.IndexOf('/'); slash >= 0; slash = file.Path.IndexOf('/', slash + 1))
            {
                string folder = file.Path[..slash];
                if (files.Contains(folder))
                    throw new InvalidDataException("The manifest contains overlapping file and directory paths.");
                folders.Add(folder);
            }
        }
        return (plan with { Files = plan.Files.Select(file => file with { Sha256 = file.Sha256.ToLowerInvariant() }).ToArray() },
            Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    private static bool UnsafeComponent(string part) =>
        part.Length == 0 || part.EndsWith('.') || part.EndsWith(' ') ||
        part.Any(c => char.IsControl(c) || c is '<' or '>' or ':' or '"' or '\\' or '|' or '?' or '*') ||
        Regex.IsMatch(part, @"\A(?:CON|PRN|AUX|NUL|(?:COM|LPT)[0-9¹²³])(?:\.|\z)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static string FullPath(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static bool SamePath(string first, string second) =>
        string.Equals(first, second, StringComparison.OrdinalIgnoreCase);

    private static bool IsWithin(string path, string root)
    {
        string prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
        return SamePath(root, path) || path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDirectory(FileAttributes? attributes) =>
        attributes is { } value && (value & FileAttributes.Directory) != 0;

    private static FileAttributes? Inspect(string path)
    {
        FileAttributes? leaf = null;
        for (string? component = path; component is not null; component = Path.GetDirectoryName(component))
        {
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(component);
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
                continue;
            }

            if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
                throw new InvalidDataException("Backup and restore paths must use regular files and directories with no symbolic links or junctions.");
            if (component == path)
                leaf = attributes;
        }
        return leaf;
    }

    private static string Hash(Stream stream) => Convert.ToHexStringLower(SHA256.HashData(stream));
}
