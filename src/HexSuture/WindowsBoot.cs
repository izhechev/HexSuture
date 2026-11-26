using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace HexSuture;

[SupportedOSPlatform("windows")]
internal static class WindowsBoot
{
    internal static int Collect(CaseStore store, int minutes, bool baseline)
    {
        var state = ReadState();
        BootReview.StoreState(store, "live", baseline, state);
        if (baseline)
            BootReview.StoreState(store, "live", false, state);

        var end = DateTime.UtcNow;
        bool complete = true;
        DefenderEvents.CollectWindow(end.AddMinutes(-minutes), end, DefenderEventScope.Boot, item => store.AddLive(item),
            message =>
            {
                store.FlagSource("Defender boot collection", message);
                Console.Error.WriteLine(message);
                complete = false;
            });
        Console.WriteLine($"Boot snapshot recorded. Secure Boot is {state.SecureBoot}.");
        return complete ? 0 : 1;
    }

    internal static int Request(CaseStore store, bool recoveryKeyReady)
    {
        using var mutex = new Mutex(false, @"Global\HexSutureOfflineScan");
        try
        {
            if (!mutex.WaitOne(TimeSpan.FromSeconds(10)))
                throw new IOException("Another HexSuture offline scan request is in progress.");
        }
        catch (AbandonedMutexException)
        {
            // The case retains the dispatch record if Windows restarted during the request.
        }

        try
        {
            var state = ReadState();
            BootReview.StoreState(store, "live", false, state);
            var gaps = BootReview.Preflight(state, recoveryKeyReady).ToList();
            if (state.Architecture == "x64" && RuntimeInformation.ProcessArchitecture != Architecture.X64)
                gaps.Add("Use the native x64 build of .NET and HexSuture.");

            if (gaps.Count > 0)
            {
                foreach (string gap in gaps)
                {
                    store.FlagSource("Defender Offline preflight", gap);
                    Console.Error.WriteLine(gap);
                }
                return 1;
            }
            var booted = state.BootUtc!.Value;
            bool alreadyRequested = store.OfflineRequests().Any(item => item.BootUtc == booted &&
                BootReview.SameDevice(item.Device, state.Device) && item.State != "invocation-error");
            var now = DateTimeOffset.UtcNow;
            bool logReadable = true;
            DefenderEvents.CollectWindow(now.AddHours(-24).UtcDateTime, now.UtcDateTime, DefenderEventScope.OfflineSchedule,
                item => store.AddLive(item), message =>
                {
                    store.FlagSource("Defender Offline preflight", message);
                    Console.Error.WriteLine(message);
                    logReadable = false;
                });
            if (!logReadable)
                return 1;
            bool scheduled = store.ObservedEvents().Any(item => item.Mode == "live" && item.Item.EventId == 2030 &&
                BootReview.SameDevice(item.Item.Device, state.Device) &&
                DateTimeOffset.Parse(item.Item.OccurredUtc, CultureInfo.InvariantCulture) >= booted);
            if (alreadyRequested || scheduled)
                throw new InvalidDataException("This Windows boot already has an offline scan request or schedule.");

            var request = new OfflineRequest(Guid.NewGuid().ToString("D"), state.Device,
                booted, DateTimeOffset.UtcNow, "dispatch-requested");
            store.SaveOfflineRequest(request);
            Console.WriteLine($"Request {request.Id} recorded. Defender Offline can restart Windows now.");
            try
            {
                using var process = StartSystemTool(@"WindowsPowerShell\v1.0\powershell.exe",
                    "-NoProfile", "-NonInteractive", "-Command",
                    """
                    $ErrorActionPreference = 'Stop'
                    Import-Module (Join-Path $PSHOME 'Modules\Defender\Defender.psd1')
                    Defender\Start-MpWDOScan
                    """);
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();
                store.SaveOfflineRequest(request with { State = process.ExitCode == 0 ? "returned" : "invocation-error" });
                if (process.ExitCode == 0)
                    return 0;
            }
            catch (Win32Exception)
            {
                store.SaveOfflineRequest(request with { State = "invocation-error" });
            }
            Console.Error.WriteLine("Defender Offline reported an invocation error. Check Protection History and event 2031.");
            return 1;
        }
        finally
        {
            mutex.ReleaseMutex();
        }
    }

    private static BootSnapshot ReadState()
    {
        var ip = IPGlobalProperties.GetIPGlobalProperties();
        string device = string.IsNullOrEmpty(ip.DomainName) ? Environment.MachineName : $"{ip.HostName}.{ip.DomainName}";
        var (client, boot) = ReadOperatingSystem();
        string arch = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            _ => "unknown"
        };
        using var identity = WindowsIdentity.GetCurrent();
        bool admin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        string secureBoot = ReadSecureBoot();
        string winRe = ReadWinRe();
        string defender = ReadDefender();
        string bitLocker = ReadBitLocker();
        bool? supported = client is null ? null : client.Value && OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000);
        return new BootSnapshot(device, DateTimeOffset.UtcNow, boot, arch, supported, secureBoot,
            winRe, defender, bitLocker, admin);
    }

    private static (bool?, DateTimeOffset?) ReadOperatingSystem()
    {
        try
        {
            using var query = new ManagementObjectSearcher("root\\CIMV2",
                "SELECT ProductType, LastBootUpTime FROM Win32_OperatingSystem");
            using var results = query.Get();
            foreach (ManagementObject result in results)
            {
                using (result)
                {
                    var boot = result["LastBootUpTime"] is string value
                        ? new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(value)).ToUniversalTime()
                        : (DateTimeOffset?)null;
                    return (Convert.ToString(result["ProductType"], CultureInfo.InvariantCulture) == "1", boot);
                }
            }
        }
        catch (Exception error) when (ReadError(error))
        {
        }
        return (null, null);
    }

    private static string ReadSecureBoot()
    {
        if (!GetFirmwareType(out uint firmware))
            return "unknown";
        if (firmware == 1)
            return "legacy";
        return firmware == 2 ? ReadTool(@"WindowsPowerShell\v1.0\powershell.exe",
            ["-NoProfile", "-NonInteractive", "-Command",
                """
                $ErrorActionPreference = 'Stop'
                Import-Module (Join-Path $PSHOME 'Modules\SecureBoot\SecureBoot.psd1')
                SecureBoot\Confirm-SecureBootUEFI
                """])?.Trim() switch
            {
                "True" => "enabled",
                "False" => "disabled",
                _ => "unknown"
            } : "unknown";
    }

    private static string ReadWinRe()
    {
        string? info = ReadTool("reagentc.exe", ["/info"]);
        if (info is null)
            return "unknown";

        // REAgentC labels are localized. Unknown output must block the restart request.
        var match = Regex.Match(info, @"^\s*Windows RE status:\s*(Enabled|Disabled)\s*$",
            RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value.ToLowerInvariant() : "unknown";
    }

    private static string ReadDefender()
    {
        try
        {
            using var query = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender",
                "SELECT AMRunningMode, AMServiceEnabled, AntivirusEnabled FROM MSFT_MpComputerStatus");
            using var results = query.Get();
            foreach (ManagementObject result in results)
            {
                using (result)
                    return result["AMServiceEnabled"] is true && result["AntivirusEnabled"] is true &&
                        string.Equals(result["AMRunningMode"] as string, "Normal", StringComparison.OrdinalIgnoreCase)
                        ? "active" : "inactive";
            }
        }
        catch (Exception error) when (ReadError(error))
        {
        }
        return "unknown";
    }

    private static string ReadBitLocker()
    {
        string? root = Path.GetPathRoot(Environment.SystemDirectory);
        if (root is not { Length: 3 } || root[1] != ':' || !char.IsAsciiLetter(root[0]))
            return "unknown";
        try
        {
            using var query = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftVolumeEncryption",
                $"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = '{root[..2]}'");
            using var results = query.Get();
            foreach (ManagementObject volume in results)
            {
                using (volume)
                using (var protection = volume.InvokeMethod("GetProtectionStatus", null, null))
                using (var conversion = volume.InvokeMethod("GetConversionStatus", null, null))
                {
                    if (protection?["ReturnValue"] is not 0u || conversion?["ReturnValue"] is not 0u)
                        return "unknown";
                    return (protection["ProtectionStatus"], conversion["ConversionStatus"]) switch
                    {
                        (1u, _) => "protected",
                        (0u, 0u) => "unencrypted",
                        (0u, 1u) => "suspended",
                        _ => "unknown"
                    };
                }
            }
        }
        catch (Exception error) when (ReadError(error))
        {
        }
        return "unknown";
    }

    private static bool ReadError(Exception error) => error is ManagementException or COMException
        or Win32Exception or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException;

    private static string? ReadTool(string file, string[] args)
    {
        try
        {
            using var process = StartSystemTool(file, args);
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(15000))
            {
                process.Kill();
                return null;
            }
            error.GetAwaiter().GetResult();
            return process.ExitCode == 0 ? output.GetAwaiter().GetResult() : null;
        }
        catch (Exception error) when (ReadError(error) || error is IOException or InvalidOperationException)
        {
            return null;
        }
    }

    private static Process StartSystemTool(string file, params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, file))
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Environment.SystemDirectory
        };
        foreach (string value in args)
            start.ArgumentList.Add(value);
        return Process.Start(start) ?? throw new Win32Exception("Windows could not start the system tool.");
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFirmwareType(out uint firmwareType);
}
