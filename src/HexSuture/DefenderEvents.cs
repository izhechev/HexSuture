using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace HexSuture;

internal enum DefenderEventScope { Threats, Scan, Fileless, Ransomware, Boot, OfflineSchedule }

[SupportedOSPlatform("windows")]
internal static class DefenderEvents
{
    private const string Channel = "Microsoft-Windows-Windows Defender/Operational";
    private const int EventLimit = 4096;

    internal static int CaptureThreatEvents(CaseStore store, int minutes)
    {
        var end = DateTime.UtcNow;
        int imported = 0;
        bool complete = true;
        CollectWindow(end.AddMinutes(-minutes), end, DefenderEventScope.Fileless, item =>
        {
            if (store.AddLive(item))
                imported++;
        }, message =>
        {
            store.FlagSource("Defender fileless collection", message);
            Console.Error.WriteLine(message);
            complete = false;
        });
        Console.WriteLine($"Saved {imported} new Defender event(s). Use show to review the fileless findings.");
        return complete ? 0 : 1;
    }

    internal static int CaptureRansomwareEvents(CaseStore store, int minutes)
    {
        var end = DateTime.UtcNow;
        string mode = ReadFolderProtectionMode();
        store.SaveCfaCoverage(new CfaCoverage(Environment.MachineName, new DateTimeOffset(end), mode));
        bool complete = true;
        CollectWindow(end.AddMinutes(-minutes), end, DefenderEventScope.Ransomware,
            item => store.AddLive(item), message =>
            {
                store.FlagSource("Defender controlled folder access collection", message);
                Console.Error.WriteLine(message);
                complete = false;
            });
        Console.WriteLine($"Controlled folder access mode: {mode}. Use show to review folder-write evidence.");
        return complete ? 0 : 1;
    }

    private static string ReadFolderProtectionMode()
    {
        try
        {
            using var search = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender",
                "SELECT EnableControlledFolderAccess FROM MSFT_MpPreference");
            using var results = search.Get();
            foreach (ManagementObject result in results)
            {
                using (result)
                {
                    return Convert.ToString(result["EnableControlledFolderAccess"], CultureInfo.InvariantCulture) switch
                    {
                        "0" => "off",
                        "1" => "block",
                        "2" => "audit",
                        "3" => "disk-only-block",
                        "4" => "disk-only-audit",
                        _ => "unknown"
                    };
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or COMException
            or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // A collection can still provide event evidence when the settings query fails.
        }
        return "unknown";
    }

    [SupportedOSPlatform("windows")]
    internal static void CollectWindow(DateTime start, DateTime end, DefenderEventScope scope,
        Action<ReplayEvent> observe, Action<string> flag)
    {
        const string threats = "EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119";
        const string offline = "EventID=2030 or EventID=2031";
        string ids = scope switch
        {
            DefenderEventScope.Scan => threats + " or EventID=1000 or EventID=1001 or EventID=1002",
            DefenderEventScope.Fileless => threats + " or EventID=1015",
            DefenderEventScope.Ransomware => threats + " or EventID=1123 or EventID=1124",
            DefenderEventScope.Boot => threats + " or " + offline,
            DefenderEventScope.OfflineSchedule => offline,
            _ => threats
        };
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
}
