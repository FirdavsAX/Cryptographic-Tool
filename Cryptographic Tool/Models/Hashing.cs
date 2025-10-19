namespace Cryptographic_Tool.Models;

public class Hashing
{
    public string Algorithm { get; set; } = string.Empty;
    public string Hash { get; set; } = string.Empty;
    public double TimeMs { get; set; }
    public string TimeMsDisplay => $"{TimeMs} ms";
}
