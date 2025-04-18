using System.Text.Json;

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

                // Get defaultProvider from the root object
                string defaultProvider = root.TryGetProperty("defaultProvider", out JsonElement defaultProviderElement)
                    ? defaultProviderElement.GetString() ?? string.Empty
                    : string.Empty;

                if (!root.TryGetProperty("libraries", out JsonElement librariesElement) 
                    || librariesElement.ValueKind != JsonValueKind.Array)
                {
                    _logger.LogMessage("No libraries found in libman.json");
                    return packages;
                }

                foreach (JsonElement library in librariesElement.EnumerateArray())
                {
                    string provider = library.TryGetProperty("provider", out JsonElement providerElement)
                        ? providerElement.GetString() ?? string.Empty
                        : defaultProvider; // Use defaultProvider if provider is missing

                    if (!library.TryGetProperty("library", out JsonElement nameElement))
                    {
                        continue;
                    }

                    string name = nameElement.GetString() ?? string.Empty;

                    if (string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    // Parse package name and version (format varies by provider)
                    string packageName;
                    string packageVersion;

                    if (provider == "filesystem")
                    {
                        // Filesystem packages don't split on '@'
                        packageName = name;
                        packageVersion = string.Empty;
                    }
                    else if ((provider == "unpkg" || provider == "jsdelivr") && name.StartsWith("@"))
                    {
                        // Scoped NPM packages split on the second '@'
                        int secondAtIndex = name.IndexOf('@', 1);
                        if (secondAtIndex > 0)
                        {
                            packageName = name.Substring(0, secondAtIndex);
                            packageVersion = name.Substring(secondAtIndex + 1);
                        }
                        else
                        {
                            packageName = name;
                            packageVersion = string.Empty;
                        }
                    }
                    else if (name.Contains("@"))
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

                if (packages.Count == 0)
                {
                    _logger.LogMessage("No libraries found in libman.json");
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
