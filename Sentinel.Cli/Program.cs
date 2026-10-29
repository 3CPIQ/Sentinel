using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Sentinel currently supports Windows only.");
    return 1;
}

var results = new List<Finding>();
var inspect = args.Length >= 2 && args[0] == "--file" ? args[1] : null;
if (args.Length > 0 && inspect is null)
{
    Console.WriteLine("Usage: Sentinel.Cli [--file <path>]");
    return 2;
}

Console.WriteLine("Sentinel v0.1 — read-only Windows investigator");
if (inspect is not null)
{
    AnalyzeFile(inspect, "user-selected file");
}
else
{
    Console.WriteLine("Inspecting running processes...");
    foreach (var process in Process.GetProcesses())
    {
        try
        {
            var path = process.MainModule?.FileName;
            if (path is not null)
                AnalyzeFile(path, $"running process (PID {process.Id})");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception
                                   or InvalidOperationException
                                   or System.UnauthorizedAccessException)
        {
            // Access to protected processes is expected to fail.
        }
        finally
        {
            process.Dispose();
        }
    }

    Console.WriteLine("Inspecting startup registry entries...");
    InspectRunKeys(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run");
    InspectRunKeys(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run");
}

var report = new Report("0.1.0", DateTimeOffset.UtcNow, results);
var output = Path.GetFullPath("sentinel-report.json");
File.WriteAllText(output, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"Report: {output}");
Console.WriteLine($"Entries: {results.Count}. These are observations, not confirmed infections.");
return 0;

void AnalyzeFile(string path, string source)
{
    try
    {
        var info = new FileInfo(path);
        if (!info.Exists) return;
        using var stream = info.OpenRead();
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        var notes = new List<string>();
        var normalized = Path.GetFullPath(path);
        if (normalized.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
            notes.Add("Executable is in a temporary directory; review context.");
        if (normalized.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase))
            notes.Add("Located in ProgramData; not inherently malicious.");
        results.Add(new Finding(source, normalized, hash, info.Length, notes));
        Console.WriteLine($"[OBSERVED] {source}: {normalized}");
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
    {
        Console.Error.WriteLine($"[SKIP] {path}: {ex.Message}");
    }
}

void InspectRunKeys(RegistryKey root, string subkey)
{
    try
    {
        using var key = root.OpenSubKey(subkey);
        if (key is null) return;
        foreach (var name in key.GetValueNames())
        {
            var value = key.GetValue(name)?.ToString() ?? "";
            results.Add(new Finding($"startup: {root.Name}\\{subkey} ({name})", value, null, null,
                new List<string> { "Startup entry; inspect target before making changes." }));
        }
    }
    catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
    {
        Console.Error.WriteLine($"[SKIP] registry {subkey}: {ex.Message}");
    }
}

record Finding(string Source, string PathOrCommand, string? Sha256, long? SizeBytes, List<string> Notes);
record Report(string Version, DateTimeOffset ScannedAtUtc, List<Finding> Findings);
