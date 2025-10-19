using BCrypt.Net;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Cryptographic_Tool.Models;
using Konscious.Security.Cryptography;
using Prism.Commands;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace Cryptographic_Tool.ViewModels;

public partial class HashingViewModel : ObservableObject
{
    // Best practice parameters recommended by OWASP (these should be your defaults)
    private const int DefaultMemory = 65536; // 64 MB
    private const int DefaultIterations = 3;
    private const int DefaultParallelism = 2; // Number of CPU threads/lanes

    [ObservableProperty]
    private string inputText;

    [ObservableProperty]
    private string saltText;

    [ObservableProperty]
    private bool isSHA256Selected = true;

    [ObservableProperty]
    private bool isSHA512Selected;

    [ObservableProperty]
    private bool isMD5Selected;

    [ObservableProperty]
    private bool isBCryptSelected;

    [ObservableProperty]
    private bool isArgon2Selected;

    [ObservableProperty]
    private int bcryptCost = 10;

    [ObservableProperty]
    private string argon2Memory = "65536";

    [ObservableProperty]
    private string argon2Iterations = "3";

    [ObservableProperty]
    private string argon2Parallelism = "2";

    [ObservableProperty]
    private bool isBusy;

    public ObservableCollection<Hashing> Results { get; set; }

    public ICommand GenerateHashesCommand { get; set; }

    public HashingViewModel()
    {
        GenerateHashesCommand = new AsyncRelayCommand(OnGenerateHashesAsync);
        Results = new ObservableCollection<Hashing>();
    }

    // 🧩 Now async, so UI can show throbber while hashing
    private async Task OnGenerateHashesAsync()
    {
        if (string.IsNullOrWhiteSpace(InputText))
            return;

        IsBusy = true; // 🌀 Show throbber

        var generatedResults = new List<Hashing>();

        await Task.Run(() =>
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(InputText);
            byte[]? saltBytes = GetSaltBytes();

            if (IsSHA256Selected)
            {
                generatedResults.Add(OnGenerateHash("SHA256", () => ComputeSHA256(inputBytes, saltBytes)));
            }
            else if (IsSHA512Selected)
            {
                generatedResults.Add(OnGenerateHash("SHA512", () => ComputeSHA512(inputBytes, saltBytes)));
            }
            else if (IsMD5Selected)
            {
                generatedResults.Add(OnGenerateHash("MD5", () => ComputeMD5(inputBytes, saltBytes)));
            }
            else if (IsBCryptSelected)
            {
                generatedResults.Add(OnGenerateHash($"BCrypt (Cost: {BcryptCost})", () => ComputeBCrypt(InputText, BcryptCost)));
            }
            else if (IsArgon2Selected)
            {
                generatedResults.Add(OnGenerateHash($"Argon2 (Mem: {Argon2Memory}, Iter: {Argon2Iterations})",
                    () => ComputeArgon2(InputText, saltBytes)));
            }
        });

        // Marshal modifications to the UI thread to avoid NotSupportedException
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null)
        {
            dispatcher.Invoke(() =>
            {
                foreach (var item in generatedResults)
                {
                    Results.Add(item);
                }
            });
        }
        else
        {
            // Fallback for non-UI contexts (e.g., unit tests)
            foreach (var item in generatedResults)
            {
                Results.Add(item);
            }
        }

        IsBusy = false; // 🌀 Hide throbber when done
    }

    // Changed to return a Hashing object instead of modifying UI collection directly
    private Hashing OnGenerateHash(string algorithmName, Func<string> hashFunction)
    {
        // For high-resolution measurement (avoid "0 ms" issue)
        const int iterations = 10;
        long totalTicks = 0;
        string hashOutput = string.Empty;

        for (int i = 0; i < iterations; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            hashOutput = hashFunction();
            stopwatch.Stop();
            totalTicks += stopwatch.ElapsedTicks;
        }

        double avgMilliseconds = (totalTicks / (double)iterations) * 1000.0 / Stopwatch.Frequency;

        return new Hashing
        {
            Algorithm = algorithmName,
            Hash = hashOutput,
            TimeMs = Math.Round(avgMilliseconds, 3)
        };
    }

    private byte[]? GetSaltBytes()
    {
        if (string.IsNullOrWhiteSpace(SaltText) || SaltText == "Optional salt (base64 or text)")
        {
            return null;
        }

        try
        {
            return Convert.FromBase64String(SaltText);
        }
        catch
        {
            return Encoding.UTF8.GetBytes(SaltText);
        }
    }

    private string ComputeSHA256(byte[] input, byte[]? salt)
    {
        byte[] dataToHash = salt != null ? CombineBytes(input, salt) : input;
        byte[] hash = SHA256.HashData(dataToHash);
        return Convert.ToBase64String(hash);
    }

    private string ComputeSHA512(byte[] input, byte[]? salt)
    {
        byte[] dataToHash = salt != null ? CombineBytes(input, salt) : input;
        byte[] hash = SHA512.HashData(dataToHash);
        return Convert.ToBase64String(hash);
    }

    private string ComputeMD5(byte[] input, byte[]? salt)
    {
        byte[] dataToHash = salt != null ? CombineBytes(input, salt) : input;
        byte[] hash = MD5.HashData(dataToHash);
        return Convert.ToBase64String(hash);
    }

    private byte[] CombineBytes(byte[] first, byte[] second)
    {
        byte[] combined = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, combined, 0, first.Length);
        Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
        return combined;
    }

    private string ComputeBCrypt(string input, int cost)
    {
        return BCrypt.Net.BCrypt.HashPassword(input, cost);
    }

    private string ComputeArgon2(string input, byte[]? salt)
    {
        if (salt == null || salt.Length == 0)
        {
            MessageBox.Show("Argon2 requires a salt. Please provide one in the salt field.", "Salt Required", MessageBoxButton.OK, MessageBoxImage.Error);
            return "Error";
        }

        // Convert your string properties to usable values
        int.TryParse(Argon2Memory, out int memorySize);
        int.TryParse(Argon2Iterations, out int iterations);
        int.TryParse(Argon2Parallelism, out int parallelism);

        // Convert input text to bytes
        byte[] passwordBytes = Encoding.UTF8.GetBytes(input);

        // Create Argon2id instance (secure hybrid version)
        var argon2 = new Argon2id(passwordBytes)
        {
            Salt = salt,
            DegreeOfParallelism = Math.Max(1, parallelism), // number of threads
            Iterations = Math.Max(1, iterations),           // how many passes
            MemorySize = Math.Max(8192, memorySize)         // memory in KB (minimum 8MB)
        };

        // Compute hash (can take some time depending on parameters)
        byte[] hashBytes = argon2.GetBytes(32); // 32 bytes = 256-bit hash

        // Return Base64 string for display
        return Convert.ToBase64String(hashBytes);
    }
}
