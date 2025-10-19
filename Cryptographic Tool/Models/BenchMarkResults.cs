namespace Cryptographic_Tool.Models;

public class BenchMarkResults
{
    public string LibraryName { get; set; }       // e.g., ".NET Native", "BouncyCastle"
    public string Algorithm { get; set; }         // e.g., "AES", "SHA512"
    public long DurationMs { get; set; }          // Measured execution time
    public string Notes { get; set; }
}
