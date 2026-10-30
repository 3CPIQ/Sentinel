using System.Diagnostics;
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
    private readonly string reportPath = Path.Combine(AppContext.BaseDirectory, "sentinel-report.json");

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
            // Reuse the existing read-only CLI rather than inventing antivirus capabilities.
            var cli = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Sentinel.Cli", "Sentinel.Cli.csproj"));
            if (!File.Exists(cli))
                throw new FileNotFoundException("Sentinel.Cli project was not found. Run the desktop app from the repository's source checkout.", cli);

            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = AppContext.BaseDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            start.ArgumentList.Add("run");
            start.ArgumentList.Add("--project");
            start.ArgumentList.Add(cli);
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the inspector.");
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            var error = await errorTask;
            _ = await outputTask;
            if (process.ExitCode != 0) throw new InvalidOperationException(error);
            if (!File.Exists(reportPath)) throw new FileNotFoundException("Report was not generated.");

            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(reportPath));
            foreach (var finding in document.RootElement.GetProperty("Findings").EnumerateArray())
            {
                var item = new ListViewItem(finding.GetProperty("Source").GetString() ?? "");
                item.SubItems.Add(finding.GetProperty("PathOrCommand").GetString() ?? "");
                item.SubItems.Add(finding.GetProperty("Sha256").ValueKind == JsonValueKind.String ? finding.GetProperty("Sha256").GetString() ?? "" : "");
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
