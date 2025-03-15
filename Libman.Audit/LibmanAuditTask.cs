using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

using Task = Microsoft.Build.Utilities.Task;

namespace Libman.Audit;

public class LibmanAuditTask : Task
{
    [Required]
    public string LibmanJsonPath { get; set; }

    [Output]
    public ITaskItem[] VulnerablePackages { get; private set; }

    private readonly HttpClient _httpClient;
    private const string SonatypeApiBaseUrl = "https://ossindex.sonatype.org/api/v3/component-report";
    private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public LibmanAuditTask()
    {
        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "Libman.Audit/1.0");
        // initialize non-null values
        LibmanJsonPath = "";
        VulnerablePackages = Array.Empty<ITaskItem>();
    }

    public override bool Execute()
    {
        try
        {
            Log.LogMessage(MessageImportance.Normal, "Starting Libman audit task...");

            if (!File.Exists(LibmanJsonPath))
            {
                Log.LogError($"Libman.json file not found at: {LibmanJsonPath}");
                return false;
            }

            string jsonContent = File.ReadAllText(LibmanJsonPath);
            List<LibmanPackage> libmanPackages = ParseLibmanJson(jsonContent);

            if (libmanPackages.Count == 0)
            {
                Log.LogMessage(MessageImportance.Normal, "No packages found in libman.json");
                VulnerablePackages = new TaskItem[0];
                return true;
            }

            List<VulnerablePackage> vulnerablePackages = AuditPackagesAsync(libmanPackages).GetAwaiter().GetResult();
            VulnerablePackages = ConvertToTaskItems(vulnerablePackages);

            if (vulnerablePackages.Count > 0)
            {
                Log.LogWarning($"Found {vulnerablePackages.Count} vulnerable packages in libman.json");
                foreach (VulnerablePackage package in vulnerablePackages)
                {
                    Log.LogWarning($"Vulnerable package: {package.Name} {package.Version}, Vulnerability count: {package.VulnerabilityCount}, Severity: {package.Severity}");
                }
            }
            else
            {
                Log.LogMessage(MessageImportance.Normal, "No vulnerable packages found");
            }

            return true;
        }
        catch (Exception ex)
        {
            Log.LogErrorFromException(ex);
            return false;
        }
    }

    private List<LibmanPackage> ParseLibmanJson(string jsonContent)
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
                    Log.LogMessage(MessageImportance.Normal, "No libraries found in libman.json");
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

                    Log.LogMessage(MessageImportance.Low, $"Found package: {packageName} {packageVersion} (Provider: {provider})");
                }
            }
        }
        catch (JsonException ex)
        {
            Log.LogError($"Failed to parse libman.json: {ex.Message}");
        }

        return packages;
    }

    private async Task<List<VulnerablePackage>> AuditPackagesAsync(List<LibmanPackage> packages)
    {
        List<VulnerablePackage> vulnerablePackages = new List<VulnerablePackage>();

        try
        {
            // Group packages in batches to avoid large requests
            for (int i = 0; i < packages.Count; i += 20)
            {
                List<LibmanPackage> batch = packages.Skip(i).Take(20).ToList();
                List<string> components = new List<string>();

                foreach (LibmanPackage package in batch)
                {
                    string packageId = GetPackageCoordinates(package);
                    if (!string.IsNullOrEmpty(packageId))
                    {
                        components.Add(packageId);
                    }
                }

                if (components.Count > 0)
                {
                    SonatypeRequest requestData = new SonatypeRequest
                    {
                        Coordinates = components.ToArray()
                    };

                    StringContent content = new StringContent(
                        JsonSerializer.Serialize(requestData, _jsonOptions),
                        Encoding.UTF8,
                        "application/json");

                    HttpResponseMessage response = await _httpClient.PostAsync(SonatypeApiBaseUrl, content);

                    if (response.IsSuccessStatusCode)
                    {
                        string responseContent = await response.Content.ReadAsStringAsync();
                        List<SonatypeResult>? results = JsonSerializer.Deserialize<List<SonatypeResult>>(responseContent, _jsonOptions);

                        if (results != null)
                        {
                            foreach (SonatypeResult result in results)
                            {
                                if (result.Vulnerabilities != null && result.Vulnerabilities.Count > 0)
                                {
                                    LibmanPackage? package = batch.FirstOrDefault(p => GetPackageCoordinates(p) == result.Coordinates);
                                    if (package != null)
                                    {
                                        string severity = DetermineSeverity(result.Vulnerabilities);
                                        vulnerablePackages.Add(new VulnerablePackage
                                        {
                                            Name = package.Name,
                                            Version = package.Version,
                                            Provider = package.Provider,
                                            VulnerabilityCount = result.Vulnerabilities.Count,
                                            Description = string.Join("; ", result.Vulnerabilities.Select(v => v.Title)),
                                            Severity = severity
                                        });
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        Log.LogWarning($"Failed to get vulnerability data: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Log.LogWarning($"Error checking for vulnerabilities: {ex.Message}");
        }

        return vulnerablePackages;
    }

    private string DetermineSeverity(List<Vulnerability> vulnerabilities)
    {
        // Determine the highest severity level among the vulnerabilities
        if (vulnerabilities.Any(v => v.CvssScore >= 9.0))
        {
            return "Critical";
        }
        if (vulnerabilities.Any(v => v.CvssScore >= 7.0))
        {
            return "High";
        }
        if (vulnerabilities.Any(v => v.CvssScore >= 4.0))
        {
            return "Medium";
        }
        return "Low";
    }

    private string GetPackageCoordinates(LibmanPackage package)
    {
        // Map libman providers to Sonatype coordinate formats
        switch (package.Provider.ToLowerInvariant())
        {
            case "cdnjs":
                return $"pkg:npm/{package.Name}@{package.Version}";
            case "unpkg":
                return $"pkg:npm/{package.Name}@{package.Version}";
            case "jsdelivr":
                return $"pkg:npm/{package.Name}@{package.Version}";
            default:
                Log.LogWarning($"Unsupported provider: {package.Provider}");
                return "";
        }
    }

    private ITaskItem[] ConvertToTaskItems(List<VulnerablePackage> vulnerablePackages)
    {
        List<TaskItem> taskItems = new List<TaskItem>();

        foreach (VulnerablePackage package in vulnerablePackages)
        {
            TaskItem taskItem = new TaskItem(package.Name);
            taskItem.SetMetadata("Version", package.Version);
            taskItem.SetMetadata("Provider", package.Provider);
            taskItem.SetMetadata("VulnerabilityCount", package.VulnerabilityCount.ToString());
            taskItem.SetMetadata("Description", package.Description);
            taskItem.SetMetadata("Severity", package.Severity);
            taskItems.Add(taskItem);
        }

        return taskItems.ToArray();
    }
}
