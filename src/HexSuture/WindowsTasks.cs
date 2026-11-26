using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml.Linq;

namespace HexSuture;

[SupportedOSPlatform("windows")]
internal sealed class WindowsTasks : ILocalTasks
{
    private const int InteractiveToken = 3;
    private const int LeastPrivilege = 0;
    private const int OwnerGroupAndDacl = 7;
    private readonly dynamic service;

    public WindowsTasks()
    {
        using var identity = WindowsIdentity.GetCurrent();
        Actor = identity.User?.Value ?? throw new InvalidDataException("Windows did not report the current user SID.");
        service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!)!;
        service.Connect();
    }

    public string Actor { get; }

    public string Device
    {
        get
        {
            var uuid = ReadWmi("SELECT UUID FROM Win32_ComputerSystemProduct", "UUID");
            if (!Guid.TryParse(uuid, out var id) || id == Guid.Empty || id.ToString("N") == new string('f', 32))
                throw new InvalidDataException("Windows did not report a usable machine UUID.");
            return TaskCleanup.Digest($"{Environment.MachineName.ToUpperInvariant()}|{id:D}");
        }
    }

    public DateTimeOffset BootUtc => new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(
        ReadWmi("SELECT LastBootUpTime FROM Win32_OperatingSystem", "LastBootUpTime"))).ToUniversalTime();

    public TaskSnapshot? Read(string path)
    {
        ValidatePath(path);
        try
        {
            var (folder, name) = Resolve(path);
            dynamic task = folder.GetTask(name);
            return Inspect(task, path);
        }
        catch (COMException ex) when (IsMissing(ex))
        {
            return null;
        }
    }

    public void SetEnabled(string path, TaskSnapshot before, bool enabled) =>
        Change(path, before, (folder, task, name) => task.Enabled = enabled);

    public void DeleteDisabled(string path, TaskSnapshot before) =>
        Change(path, before, (folder, task, name) => folder.DeleteTask(name, 0));

    private void Change(string path, TaskSnapshot before, Action<dynamic, dynamic, string> action)
    {
        var (folder, name) = Resolve(path);
        dynamic task = folder.GetTask(name);
        TaskSnapshot current = Inspect(task, path);
        TaskCleanup.RequireSame(before, current);
        if (current.Enabled != before.Enabled)
            throw new InvalidDataException("The task’s enabled state changed before the operation.");
        action(folder, task, name);
    }

    private TaskSnapshot Inspect(dynamic task, string path)
    {
        if (!string.Equals((string)task.Path, path, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Task Scheduler returned a different path.");
        dynamic principal = task.Definition.Principal;
        string? userId = principal.UserId;
        if ((int)principal.LogonType != InteractiveToken || (int)principal.RunLevel != LeastPrivilege ||
            string.IsNullOrWhiteSpace(userId) || !string.IsNullOrEmpty((string?)principal.GroupId) ||
            AccountSid(userId) != Actor)
            throw new InvalidDataException("Only tasks running as your interactive user at least privilege are supported.");

        string descriptor = task.GetSecurityDescriptor(OwnerGroupAndDacl);
        string? owner = new RawSecurityDescriptor(descriptor).Owner?.Value;
        if (owner != Actor)
            throw new InvalidDataException("The current user must own the task.");
        if ((int)task.State is not (1 or 3) || (int)task.GetInstances(0).Count != 0)
            throw new InvalidDataException("Wait for the task to be idle before making or verifying a change.");

        string xml = task.Xml;
        var root = XElement.Parse(xml);
        var ns = root.Name.Namespace;
        root.Element(ns + "Settings")?.Element(ns + "Enabled")?.Remove();
        string digest = TaskCleanup.Digest(root.ToString(SaveOptions.DisableFormatting) + "\n" + descriptor);
        return new TaskSnapshot(digest, (bool)task.Enabled, owner, descriptor, xml);
    }

    internal static void ValidatePath(string path)
    {
        if (!path.StartsWith('\\') || path.Contains('/') || path.Contains(':') ||
            path.Split('\\').Skip(1).Any(part => part.Length == 0 || part is "." or ".." ||
                part != part.Trim() || part.Any(char.IsControl)) ||
            path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(@"Use an exact task path outside the Microsoft folder, such as \MyTasks\Example.");
    }

    private (dynamic Folder, string Name) Resolve(string path)
    {
        int split = path.LastIndexOf('\\');
        return (service.GetFolder(split == 0 ? @"\" : path[..split]), path[(split + 1)..]);
    }

    private static bool IsMissing(COMException error) =>
        error.HResult is unchecked((int)0x80070002) or unchecked((int)0x80070003);

    private static string AccountSid(string userId)
    {
        if (userId.StartsWith("S-", StringComparison.OrdinalIgnoreCase))
            return new SecurityIdentifier(userId).Value;
        return ((SecurityIdentifier)new NTAccount(userId).Translate(typeof(SecurityIdentifier))).Value;
    }

    private static string ReadWmi(string query, string property)
    {
        using var search = new ManagementObjectSearcher("root\\CIMV2", query);
        using var results = search.Get();
        foreach (ManagementObject result in results)
        {
            using (result)
            {
                if (result[property] is string value && !string.IsNullOrWhiteSpace(value))
                    return value;
            }
        }
        throw new InvalidDataException("Windows did not report the machine identity or boot time.");
    }
}
