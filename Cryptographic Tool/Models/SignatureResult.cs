namespace Cryptographic_Tool.Models;

public class SignatureResult
{
    public string Algorithm { get; set; }          // "RSA-PSS" or "ECDSA"
    public string SignatureBase64 { get; set; }    // Signature string
    public bool Verified { get; set; }             // True/False
    public long TimeMs { get; set; }               // Execution time
}
