using System.IO;
using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;
using Sentinel.App.Models;
using Sentinel.App.Services;

namespace Sentinel.App;
public partial class MainWindow : Window
{
    private readonly ObservableCollection<Finding> _findings = new();
    private readonly Investigator _investigator = new();
    private DateTimeOffset? _lastScan;
    public MainWindow()
    {
        InitializeComponent();
        ResultsGrid.ItemsSource = _findings;
    }
    private void Dashboard_Click(object sender, RoutedEventArgs e) =>
        PageTitle.Text = "Security Overview";
    private void Results_Click(object sender, RoutedEventArgs e) =>
        PageTitle.Text = "Scan Results";

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        ScanButton.IsEnabled = false;
        StatusText.Text = "Scanning accessible processes and startup entries…";
        try
        {
            var observations = await _investigator.ScanAsync();
            _findings.Clear();
            foreach (var item in observations) _findings.Add(item);
            _lastScan = DateTimeOffset.Now;
            PageTitle.Text = "Scan Results";
            SummaryText.Text = $"{_findings.Count} observations collected. These are NOT confirmed threats.";
            StatusText.Text = $"Last scan: {_lastScan:yyyy-MM-dd HH:mm}  •  Read-only mode";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"The scan could not complete: {ex.Message}", "Sentinel",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            StatusText.Text = "Scan failed. No changes made.";
        }
        finally { ScanButton.IsEnabled = true; }
    }
    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_lastScan is null)
        {
            MessageBox.Show("Run a scan before exporting.", "Sentinel",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dialog = new SaveFileDialog { FileName = "sentinel-report.json", Filter = "JSON files (*.json)|*.json" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var payload = new { Version = "0.2-preview", ScannedAt = _lastScan, Findings = _findings.ToArray() };
            File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
            StatusText.Text = "Report saved. It may contain personal file paths; review before sharing.";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}