# Sentinel

Sentinel is an experimental **read-only Windows security investigator** written in C# and .NET.

## v0.1 prototype

This is **not yet an antivirus**: it does not detect, quarantine or remove malware. It inventories accessible running executables, computes SHA-256 hashes, lists common Windows Run startup entries, and creates a JSON report.

### Requirements
- Windows 10 or 11
- .NET 8 SDK

### Run
```powershell
dotnet run --project Sentinel.Cli
dotnet run --project Sentinel.Cli -- --file "C:\\path\\to\\file.exe"
```

Output: `sentinel-report.json` in the current directory.

### Safety
- No automatic removal, process termination, registry modifications or uploads.
- Executable location and hash are **observations, not proof of infection**.
- Some protected processes cannot be inspected.
- JSON reports can contain sensitive local paths and startup commands. Review before sharing.
- For active malware, use a maintained antivirus and trusted recovery tools.

### Roadmap
1. Automated tests and safer report export
2. Digital signature checks and opt-in known-bad hash matching
3. Task scheduler and service inventory
4. Audited, reversible quarantine with user confirmation
5. Offline investigation

License TBD.
