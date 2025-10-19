namespace Cryptographic_Tool.Models;

public class EncryptionResult
{
    public string Algorithm { get; set; }
    public string EncryptedData { get; set; }
    public string DecryptedData { get; set; }
    public TimeOnly TimeMs { get; set; }
}
