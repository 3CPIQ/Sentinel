namespace Sentinel.App.Models;
public sealed record Finding(string Name, string Category, string Path, string Status, string Evidence, string? Sha256 = null);
