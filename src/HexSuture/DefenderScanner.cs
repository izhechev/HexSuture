using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;

namespace HexSuture;

internal static class DefenderScanner
{
    private const string Channel = "Microsoft-Windows-Windows Defender/Operational";
    private const int EventLimit = 4096;

    internal static int Run(CaseStore store, string kind, string? folder)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Live scans require Windows and active Microsoft Defender Antivirus.");
            return 1;
        }
        return RunWindows(store, kind, folder);
    }

    [SupportedOSPlatform("windows")]
    private static int RunWindows(CaseStore store, string kind, string? folder)
    {
        string id = Guid.NewGuid().ToString();
        var requested = DateTime.UtcNow;
        string? engine = null;
        string? signatures = null;
        string? error = null;
        int? exit = null;
        try
        {
            using var user = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator))
                throw new InvalidOperationException("Run the scan from a Windows terminal opened as administrator.");
            (engine, signatures) = ReadStatus();
        }
        catch (Exception ex) when (IsWindowsSourceError(ex))
        {
            error = "Defender preflight failed: " + ex.Message;
        }

        store.StartScan(new ScanRequest(id, Environment.MachineName, kind, folder,
            requested.ToString("O"), engine, signatures, null, null, null));
        Console.WriteLine($"Scan request {id} ({kind}).");

        if (error is null)
        {
            try
            {
                exit = RunEngine(kind, folder);
                if (exit != 0)
                    error = $"MpCmdRun returned {exit}. Check event evidence and Windows Security.";
            }
            catch (OperationCanceledException)
            {
                error = "Stopped waiting for MpCmdRun. Check Defender for the scan outcome.";
            }
            catch (Exception ex) when (IsWindowsSourceError(ex))
            {
                error = "Could not run MpCmdRun: " + ex.Message;
            }
        }
        else
        {
            store.FinishScan(id, DateTime.UtcNow.ToString("O"), null, error);
            Console.Error.WriteLine(error);
            return 1;
        }

        var ended = DateTime.UtcNow;
        store.FinishScan(id, ended.ToString("O"), exit, error);
        if (error is not null)
            Console.Error.WriteLine(error);

        // Defender can publish its terminal event just after MpCmdRun returns.
        Thread.Sleep(TimeSpan.FromSeconds(3));
        bool completeRead = CollectEvidence(store, requested, folder, id);
        Console.WriteLine("Read the case report for observed scan states and item actions.");
        return exit == 0 && completeRead ? 0 : 1;
    }

    private static bool IsWindowsSourceError(Exception ex) =>
        ex is Win32Exception or ManagementException or COMException or IOException
            or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException;

    [SupportedOSPlatform("windows")]
    private static (string? Engine, string? Signatures) ReadStatus()
    {
        using var search = new ManagementObjectSearcher(
            @"root\Microsoft\Windows\Defender",
            "SELECT AMServiceEnabled, AntivirusEnabled, AMRunningMode, AMEngineVersion, AntivirusSignatureVersion FROM MSFT_MpComputerStatus");
        using var results = search.Get();
        foreach (ManagementObject result in results)
        {
            using (result)
            {
                if (result["AMServiceEnabled"] is not true || result["AntivirusEnabled"] is not true ||
                    !string.Equals(result["AMRunningMode"] as string, "Normal", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Microsoft Defender Antivirus is not in active mode.");
                return (result["AMEngineVersion"] as string, result["AntivirusSignatureVersion"] as string);
            }
        }
        throw new InvalidOperationException("Defender did not report its status.");
    }

    private static string FindScanner()
    {
        string platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        if (Path.IsPathFullyQualified(platform) && Directory.Exists(platform))
        {
            var binaries = new DirectoryInfo(platform).EnumerateDirectories()
                .Select(directory => new
                {
                    Version = Version.TryParse(directory.Name.Split('-')[0], out var number) ? number : null,
                    Path = Path.Combine(directory.FullName, "MpCmdRun.exe")
                })
                .Where(candidate => candidate.Version is not null && File.Exists(candidate.Path))
                .OrderByDescending(candidate => candidate.Version)
                .ThenByDescending(candidate => candidate.Path, StringComparer.Ordinal);
            var latest = binaries.FirstOrDefault();
            if (latest is not null)
                return latest.Path;
        }

        string inbox = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender", "MpCmdRun.exe");
        if (!Path.IsPathFullyQualified(inbox) || !File.Exists(inbox))
            throw new FileNotFoundException("MpCmdRun.exe was not found in the Defender installation.");
        return inbox;
    }

    private static int RunEngine(string kind, string? folder)
    {
        string scanner = FindScanner();
        var start = new ProcessStartInfo(scanner)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(scanner)!
        };
        start.ArgumentList.Add("-Scan");
        start.ArgumentList.Add("-ScanType");
        start.ArgumentList.Add(kind switch
        {
            "quick" => "1",
            "full" => "2",
            "folder" => "3",
            _ => throw new ArgumentException("Unknown scan scope.")
        });
        if (kind == "folder")
        {
            start.ArgumentList.Add("-File");
            start.ArgumentList.Add(folder ?? throw new ArgumentException("A folder scan needs a directory."));
        }

        using var interrupted = new CancellationTokenSource();
        ConsoleCancelEventHandler stopWaiting = (_, args) =>
        {
            args.Cancel = true;
            interrupted.Cancel();
        };
        Console.CancelKeyPress += stopWaiting;
        try
        {
            using var process = Process.Start(start) ?? throw new InvalidOperationException("MpCmdRun did not start.");
            process.WaitForExitAsync(interrupted.Token).GetAwaiter().GetResult();
            return process.ExitCode;
        }
        finally
        {
            Console.CancelKeyPress -= stopWaiting;
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool CollectEvidence(CaseStore store, DateTime requested, string? folder, string requestId)
    {
        string source = $"Defender events for request {requestId}";
        bool complete = true;
        bool sawTerminal = false;
        void Flag(string message)
        {
            store.FlagSource(source, message);
            Console.Error.WriteLine(message);
            complete = false;
        }

        if (folder is not null)
        {
            var matchingIds = new HashSet<Guid>();
            CollectWindow(requested.AddMinutes(-10), requested, detectionsOnly: true, item =>
            {
                var facts = JsonSerializer.Deserialize<Dictionary<string, string>>(item.FactsJson)!;
                facts.TryGetValue("Detection ID", out var id);
                Guid.TryParse(id, out var key);
                bool scoped = facts.TryGetValue("Path", out var paths) && MentionsFolder(paths, folder);
                if (scoped && key != Guid.Empty)
                    matchingIds.Add(key);
                if (scoped || matchingIds.Contains(key))
                    store.AddLive(item);
            }, Flag);
        }

        CollectWindow(requested, DateTime.UtcNow, detectionsOnly: false, item =>
        {
            store.AddLive(item);
            sawTerminal |= item.EventId is 1001 or 1002;
        }, Flag);
        if (!sawTerminal)
            Flag("No finished or stopped scan event was observed in the request window.");
        return complete;
    }

    [SupportedOSPlatform("windows")]
    private static void CollectWindow(DateTime start, DateTime end, bool detectionsOnly,
        Action<ReplayEvent> observe, Action<string> flag)
    {
        string ids = "EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119";
        if (!detectionsOnly)
            ids += " or EventID=1000 or EventID=1001 or EventID=1002";
        string from = start.ToString("O", CultureInfo.InvariantCulture);
        string to = end.ToString("O", CultureInfo.InvariantCulture);
        string filter = $"*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and " +
            $"TimeCreated[@SystemTime >= '{from}' and @SystemTime <= '{to}'] and ({ids})]]";
        try
        {
            var query = new EventLogQuery(Channel, PathType.LogName, filter);
            using var reader = new EventLogReader(query);
            for (int count = 0; ; count++)
            {
                using var record = reader.ReadEvent();
                if (record is null)
                    break;
                if (count == EventLimit)
                {
                    flag($"More than {EventLimit} relevant Defender events occurred in the capture window.");
                    break;
                }
                try
                {
                    observe(ReplayEvent.ReadXml(record.ToXml()));
                }
                catch (InvalidDataException ex)
                {
                    flag("Unreadable or conflicting Defender event: " + ex.Message);
                }
            }
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            flag("Could not read the Defender Operational log: " + ex.Message);
        }
    }

    private static bool MentionsFolder(string paths, string folder)
    {
        string directory = Path.TrimEndingDirectorySeparator(folder);
        string prefix = Path.EndsInDirectorySeparator(directory) ? directory : directory + Path.DirectorySeparatorChar;
        foreach (string entry in paths.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int marker = entry.IndexOf(":_", StringComparison.Ordinal);
            string path = marker < 0 ? entry : entry[(marker + 2)..];
            if (path.Equals(directory, StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
