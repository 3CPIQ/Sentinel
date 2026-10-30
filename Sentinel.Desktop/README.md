# Sentinel Desktop (Windows-style interface)

A plain Windows Forms interface for the existing read-only Sentinel CLI. Uses standard Windows tabs, buttons, labels, and list views with system fonts and colors. No custom neon, glassmorphism, or artificial intelligence branding.

## Run from the repository

On Windows with .NET 8 SDK:

```powershell
dotnet run --project Sentinel.Desktop
```

The app invokes `Sentinel.Cli`, saves a report beside the desktop executable and lists observations in the **Findings** tab. Run from the repository source checkout; this prototype does **not** bundle the CLI for standalone installation yet.

This is not a malware detector and does not delete or quarantine files.
