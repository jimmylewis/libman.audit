using System.Text.Json;
using Microsoft.Build.Framework;

namespace Libman.Audit;

public class LibmanJsonParser : ILibmanJsonParser
{
    private readonly ILogger _logger;

    public LibmanJsonParser(ILogger logger)
    {
        _logger = logger;
    }

    public List<LibmanPackage> Parse(string jsonContent)
    {
        List<LibmanPackage> packages = new List<LibmanPackage>();

        try
        {
            using (JsonDocument doc = JsonDocument.Parse(jsonContent))
            {
                JsonElement root = doc.RootElement;

                if (!root.TryGetProperty("libraries", out JsonElement librariesElement) ||
                    librariesElement.ValueKind != JsonValueKind.Array)
                {
                    _logger.LogMessage("No libraries found in libman.json");
                    return packages;
                }

                foreach (JsonElement library in librariesElement.EnumerateArray())
                {
                    if (!library.TryGetProperty("provider", out JsonElement providerElement) ||
                        !library.TryGetProperty("library", out JsonElement nameElement))
                    {
                        continue;
                    }

                    string provider = providerElement.GetString() ?? string.Empty;
                    string name = nameElement.GetString() ?? string.Empty;

                    if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    // Parse package name and version (format varies by provider)
                    string packageName;
                    string packageVersion;

                    if (name.Contains("@"))
                    {
                        string[] parts = name.Split(new[] { '@' }, 2);
                        packageName = parts[0];
                        packageVersion = parts[1];
                    }
                    else
                    {
                        // If no version is specified, use the name as-is and leave version empty
                        packageName = name;
                        packageVersion = string.Empty;
                    }

                    packages.Add(new LibmanPackage
                    {
                        Name = packageName,
                        Version = packageVersion,
                        Provider = provider
                    });

                    _logger.LogMessage($"Found package: {packageName} {packageVersion} (Provider: {provider})", LogLevel.Low);
                }
            }
        }
        catch (JsonException ex)
        {
            _logger.LogError($"Failed to parse libman.json: {ex.Message}");
        }

        return packages;
    }
}
