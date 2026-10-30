using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Text.Json;
using System.Drawing;
using System.Windows.Forms;

namespace Sentinel.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new SentinelWindow());
    }
}

internal sealed class SentinelWindow : Form
{
    private readonly Button scanButton = new() { Text = "Run inspection", AutoSize = true };
    private readonly Button openButton = new() { Text = "Open report folder", AutoSize = true };
    private readonly Label status = new() { Text = "Ready to inspect this PC.", AutoSize = true };
    private readonly ListView findings = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true };
    private readonly string reportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel", "sentinel-report.json");

    public SentinelWindow()
    {
        Text = "Sentinel";
        Size = new Size(940, 590);
        MinimumSize = new Size(670, 420);
        StartPosition = FormStartPosition.CenterScreen;
        Font = SystemFonts.MessageBoxFont;
        BackColor = SystemColors.Control;

        var tabs = new TabControl { Dock = DockStyle.Fill };
        var overview = new TabPage("Overview") { Padding = new Padding(16) };
        var details = new TabPage("Findings") { Padding = new Padding(12) };
        tabs.TabPages.AddRange(new[] { overview, details });

        var heading = new Label { Text = "Sentinel", Font = new Font(Font.FontFamily, 20, FontStyle.Regular), AutoSize = true };
        var explanation = new Label
        {
            Text = "Read-only Windows security investigator. Findings are observations, not confirmed threats.",
            AutoSize = true,
            MaximumSize = new Size(740, 0)
        };

        var actions = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(0, 12, 0, 12) };
        actions.Controls.Add(scanButton);
        actions.Controls.Add(openButton);

        var stack = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(8), AutoScroll = true };
        stack.Controls.Add(heading);
        stack.Controls.Add(explanation);
        stack.Controls.Add(actions);
        stack.Controls.Add(status);
        overview.Controls.Add(stack);

        findings.Columns.Add("Source", 245);
        findings.Columns.Add("Path or command", 450);
        findings.Columns.Add("SHA-256", 230);
        details.Controls.Add(findings);

        Controls.Add(tabs);
        scanButton.Click += async (_, _) => await RunInspection();
        openButton.Click += (_, _) =>
        {
            if (File.Exists(reportPath))
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{reportPath}\"") { UseShellExecute = true });
            else
                MessageBox.Show(this, "Run an inspection first to generate a report.", "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };
    }

    private async Task RunInspection()
    {
        scanButton.Enabled = false;
        status.Text = "Inspecting processes and startup entries...";
        findings.Items.Clear();
        try
        {
            var entries = await Task.Run(() =>
            {
                var results = new List<Observation>();
                void AddFile(string path, string source)
                {
                    try
                    {
                        var info = new FileInfo(path);
                        if (!info.Exists) return;
                        using var stream = info.OpenRead();
                        var hash = Convert.ToHexString(SHA256.HashData(stream));
                        results.Add(new Observation(source, info.FullName, hash));
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { }
                }
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        var path = process.MainModule?.FileName;
                        if (path is not null) AddFile(path, $"Process (PID {process.Id})");
                    }
                    catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or UnauthorizedAccessException) { }
                    finally { process.Dispose(); }
                }
                void ReadStartup(RegistryKey root)
                {
                    try
                    {
                        using var key = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                        if (key is null) return;
                        foreach (var name in key.GetValueNames())
                            results.Add(new Observation($"Startup: {name}", key.GetValue(name)?.ToString() ?? "", null));
                    }
                    catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
                }
                ReadStartup(Registry.CurrentUser);
                ReadStartup(Registry.LocalMachine);
                return results;
            });
            Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
            await File.WriteAllTextAsync(reportPath, JsonSerializer.Serialize(new
            {
                Version = "0.1.0",
                ScannedAtUtc = DateTimeOffset.UtcNow,
                Findings = entries.Select(x => new { x.Source, PathOrCommand = x.Path, x.Sha256 })
            }, new JsonSerializerOptions { WriteIndented = true }));
            foreach (var entry in entries)
            {
                var item = new ListViewItem(entry.Source);
                item.SubItems.Add(entry.Path);
                item.SubItems.Add(entry.Sha256 ?? "");
                findings.Items.Add(item);
            }
            status.Text = $"Inspection finished. {findings.Items.Count} observations. Select the Findings tab to review.";
        }
        catch (Exception ex)
        {
            status.Text = "Inspection could not complete.";
            MessageBox.Show(this, ex.Message, "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { scanButton.Enabled = true; }
    }
}

internal sealed record Observation(string Source, string Path, string? Sha256);
