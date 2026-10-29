using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Win32;
using Sentinel.App.Models;

namespace Sentinel.App.Services;

/// <summary>Non-destructive inventory. Observations are not malware verdicts.</summary>
public sealed class Investigator
{
    public async Task<IReadOnlyList<Finding>> ScanAsync(CancellationToken token = default)
    {
        return await Task.Run(() =>
        {
            var findings = new List<Finding>();
            foreach (var process in Process.GetProcesses())
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    var path = process.MainModule?.FileName;
                    if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) continue;
                    string? hash = null;
                    try
                    {
                        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        hash = Convert.ToHexString(SHA256.HashData(stream));
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                    findings.Add(new Finding(process.ProcessName, "Process", path,
                        "Observed", $"Running process · PID {process.Id}", hash));
                }
                catch (System.ComponentModel.Win32Exception) { }
                catch (InvalidOperationException) { }
                catch (UnauthorizedAccessException) { }
                finally { process.Dispose(); }
            }
            InspectRunKey(Registry.CurrentUser, "HKCU", findings);
            InspectRunKey(Registry.LocalMachine, "HKLM", findings);
            return (IReadOnlyList<Finding>)findings;
        }, token);
    }

    private static void InspectRunKey(RegistryKey root, string hive, List<Finding> findings)
    {
        try
        {
            using var key = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (key is null) return;
            foreach (var name in key.GetValueNames())
            {
                var command = key.GetValue(name)?.ToString() ?? "";
                findings.Add(new Finding(name, "Startup", command, "Review",
                    $"{hive} Run registry entry; not necessarily suspicious"));
            }
        }
        catch (System.Security.SecurityException) { }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }
}