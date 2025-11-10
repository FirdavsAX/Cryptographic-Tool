using System;

namespace Cryptographic_Tool.Models;

public class SymmetricEncryptionResult
{
    // Algorithm name (e.g. "AES")
    public string Algorithm { get; set; } = string.Empty;

    // "Encrypt" or "Decrypt"
    public string Operation { get; set; } = string.Empty;

    // Time in milliseconds
    public double TimeMs { get; set; }

    // Short preview of the result (ciphertext or plaintext)
    public string PreviewText { get; set; } = string.Empty;
}