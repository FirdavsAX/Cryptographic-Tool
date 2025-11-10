using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Cryptographic_Tool.Models;

namespace Cryptographic_Tool.ViewModels;

public partial class SymmetricEncryptionViewModel : ObservableObject
{
    // Observable properties
    [ObservableProperty]
    private bool isBusy = false;

    [ObservableProperty]
    private string plainText = string.Empty;

    [ObservableProperty]
    private string cipherText = string.Empty;

    // Base64 encoded key and IV
    [ObservableProperty]
    private string key = string.Empty;

    [ObservableProperty]
    private string iv = string.Empty;

    [ObservableProperty]
    private int keySize = 256; // bits

    [ObservableProperty]
    private string selectedAlgorithm = "AES";

    [ObservableProperty]
    private string statusMessage = string.Empty;

    // Output shown in the view (shows ciphertext after encrypt, plaintext after decrypt)
    [ObservableProperty]
    private string outputText = string.Empty;

    // Results history shown in the DataGrid
    public ObservableCollection<SymmetricEncryptionResult> Results { get; } = new();

    // Algorithms list (extendable)
    public ReadOnlyCollection<string> Algorithms { get; } =
        new ReadOnlyCollection<string>(new[] { "AES" });

    // Encrypt the PlainText and populate CipherText (Base64)
    [RelayCommand]
    private async Task EncryptAsync()
    {   
        if (string.IsNullOrEmpty(PlainText))
        {
            StatusMessage = "Nothing to encrypt.";
            return;
        }

        IsBusy = true;
        StatusMessage = string.Empty;

        var sw = Stopwatch.StartNew();
        try
        {
            using var aes = Aes.Create();
            aes.KeySize = KeySize;
            // If Key/IV provided, try to use them; otherwise generate new
            if (!TryParseBase64(Key, out var keyBytes) || !TryParseBase64(Iv, out var ivBytes))
            {
                aes.GenerateKey();
                aes.GenerateIV();
                Key = Convert.ToBase64String(aes.Key);
                Iv = Convert.ToBase64String(aes.IV);
            }
            else
            {
                aes.Key = keyBytes;
                aes.IV = ivBytes;
            }

            var plainBytes = Encoding.UTF8.GetBytes(PlainText);
            using var ms = new MemoryStream();
            using (var crypto = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                // do not ConfigureAwait(false) here to ensure we resume on UI thread for property updates
                await crypto.WriteAsync(plainBytes, 0, plainBytes.Length);
            }
            var encrypted = ms.ToArray();
            CipherText = Convert.ToBase64String(encrypted);

            // set output shown to user
            OutputText = CipherText;

            StatusMessage = "Encryption successful.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Encryption failed: {ex.Message}";
            OutputText = string.Empty;
        }
        finally
        {
            sw.Stop();
            IsBusy = false;

            // Add result entry
            var preview = CipherText ?? string.Empty;
            if (preview.Length > 120) preview = preview.Substring(0, 120) + "...";
            Results.Insert(0, new SymmetricEncryptionResult
            {
                Algorithm = SelectedAlgorithm,
                Operation = "Encrypt",
                TimeMs = sw.Elapsed.TotalMilliseconds,
                PreviewText = preview
            });
        }
    }

    // Decrypt the CipherText (Base64) and populate PlainText
    [RelayCommand]
    private async Task DecryptAsync()
    {
        if (string.IsNullOrEmpty(CipherText))
        {
            StatusMessage = "Nothing to decrypt.";
            return;
        }

        if (!TryParseBase64(Key, out var keyBytes) || !TryParseBase64(Iv, out var ivBytes))
        {
            StatusMessage = "Key and IV are required for decryption.";
            return;
        }

        IsBusy = true;
        StatusMessage = string.Empty;

        var sw = Stopwatch.StartNew();
        try
        {
            using var aes = Aes.Create();
            aes.KeySize = KeySize;
            aes.Key = keyBytes;
            aes.IV = ivBytes;

            var encryptedBytes = Convert.FromBase64String(CipherText);
            using var ms = new MemoryStream(encryptedBytes);
            using var crypto = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var reader = new MemoryStream();
            // do not ConfigureAwait(false) here to ensure UI thread resume
            await crypto.CopyToAsync(reader);
            var plainBytes = reader.ToArray();
            PlainText = Encoding.UTF8.GetString(plainBytes);

            // set output shown to user (decrypted result)
            OutputText = PlainText;

            StatusMessage = "Decryption successful.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Decryption failed: {ex.Message}";
            OutputText = string.Empty;
        }
        finally
        {
            sw.Stop();
            IsBusy = false;

            var preview = PlainText ?? string.Empty;
            if (preview.Length > 120) preview = preview.Substring(0, 120) + "...";
            Results.Insert(0, new SymmetricEncryptionResult
            {
                Algorithm = SelectedAlgorithm,
                Operation = "Decrypt",
                TimeMs = sw.Elapsed.TotalMilliseconds,
                PreviewText = preview
            });
        }
    }

    // Generate a new Key and IV and set the properties (Base64)
    [RelayCommand]
    private void GenerateKey()
    {
        try
        {
            using var aes = Aes.Create();
            aes.KeySize = KeySize;
            aes.GenerateKey();
            aes.GenerateIV();
            Key = Convert.ToBase64String(aes.Key);
            Iv = Convert.ToBase64String(aes.IV);
            StatusMessage = "Key and IV generated.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Key generation failed: {ex.Message}";
        }
    }

    // Clear inputs and outputs
    [RelayCommand]
    private void Clear()
    {
        PlainText = string.Empty;
        CipherText = string.Empty;
        OutputText = string.Empty;
        StatusMessage = string.Empty;
    }

    // Save Key and IV to file (JSON { "Key": "...", "IV": "..." }). Overwrites file if exists.
    public async Task SaveKeyToFileAsync(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
        {
            StatusMessage = "Invalid file path.";
            return;
        }

        if (string.IsNullOrEmpty(Key) || string.IsNullOrEmpty(Iv))
        {
            StatusMessage = "No key/IV to save.";
            return;
        }

        try
        {
            var content = new
            {
                Key = Key,
                IV = Iv
            };
            var json = JsonSerializer.Serialize(content, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(filePath, json).ConfigureAwait(false);
            StatusMessage = "Key saved to file.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Save failed: {ex.Message}";
        }
    }

    // Load Key and IV from file. Accepts either JSON { "Key": "...", "IV": "..." } or plain two-line key\niv
    public async Task LoadKeyFromFileAsync(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            StatusMessage = "File not found.";
            return;
        }

        try
        {
            var text = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);

            // Try JSON first
            try
            {
                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;
                if (root.TryGetProperty("Key", out var k) &&
                    (root.TryGetProperty("IV", out var v) || root.TryGetProperty("iv", out v)))
                {
                    Key = k.GetString() ?? string.Empty;
                    Iv = v.GetString() ?? string.Empty;
                    StatusMessage = "Key loaded from file (JSON).";
                    return;
                }
            }
            catch
            {
                // ignore and try plain format
            }

            // Plain two-line format
            var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length >= 2)
            {
                Key = lines[0].Trim();
                Iv = lines[1].Trim();
                StatusMessage = "Key loaded from file.";
                return;
            }

            StatusMessage = "Unrecognized key file format.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Load failed: {ex.Message}";
        }
    }

    // Helper: try parse base64 safely
    private static bool TryParseBase64(string base64, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(base64))
            return false;

        try
        {
            bytes = Convert.FromBase64String(base64);
            return bytes.Length > 0;
        }
        catch
        {
            return false;
        }
    }
}
