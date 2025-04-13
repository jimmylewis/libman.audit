using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

using Task = Microsoft.Build.Utilities.Task;

namespace Libman.Audit;

public class LibmanAuditTask : Task
{
    private readonly Dictionary<string, int> s_severityRanking = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            { "Critical", 4 },
            { "High", 3 },
            { "Medium", 2 },
            { "Low", 1 },
            { "Unknown", 0 }
        };

    [Required]
    public string LibmanJsonPath { get; set; }

    [Output]
    public ITaskItem[] VulnerablePackages { get; private set; }

    private readonly HttpClient _httpClient;
    private const string GitHubApiUrl = "https://api.github.com/advisories";
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
        return ExecuteAsync().GetAwaiter().GetResult();
    }

    private async Task<bool> ExecuteAsync()
    {
        try
        {
            Log.LogMessage(MessageImportance.Normal, "Starting Libman audit task...");

            if (!File.Exists(LibmanJsonPath))
            {
                Log.LogError($"Libman.json file not found at: {LibmanJsonPath}");
                return false;
            }
#if NETFRAMEWORK
            string jsonContent = File.ReadAllText(LibmanJsonPath);
#else
            string jsonContent = await File.ReadAllTextAsync(LibmanJsonPath);
#endif
            List<LibmanPackage> libmanPackages = ParseLibmanJson(jsonContent);

            if (libmanPackages.Count == 0)
            {
                Log.LogMessage(MessageImportance.Normal, "No packages found in libman.json");
                VulnerablePackages = new TaskItem[0];
                return true;
            }

            List<VulnerablePackage> vulnerablePackages = await AuditPackagesAsync(libmanPackages);
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
        Dictionary<string, VulnerablePackage> packageVulnerabilities = new Dictionary<string, VulnerablePackage>();
        System.Diagnostics.Debugger.Launch();

        try
        {
            foreach (LibmanPackage package in packages)
            {
                string url = $"{GitHubApiUrl}?package={package.Name}&version={package.Version}";
                HttpResponseMessage response = await _httpClient.GetAsync(url);

                if (response.IsSuccessStatusCode)
                {
                    string responseContent = await response.Content.ReadAsStringAsync();
                    List<GitHubAdvisory>? advisories = JsonSerializer.Deserialize<List<GitHubAdvisory>>(responseContent, _jsonOptions);

                    if (advisories != null && advisories.Count > 0)
                    {
                        // Create a unique key for this package
                        string packageKey = $"{package.Name}|{package.Version}|{package.Provider}";

                        // Get or create an entry for this package
                        if (!packageVulnerabilities.TryGetValue(packageKey, out VulnerablePackage? vulnerablePackage))
                        {
                            vulnerablePackage = new VulnerablePackage
                            {
                                Name = package.Name,
                                Version = package.Version,
                                Provider = package.Provider,
                                VulnerabilityCount = 0,
                                Description = string.Empty,
                                Severity = string.Empty
                            };
                            packageVulnerabilities.Add(packageKey, vulnerablePackage);
                        }

                        // Update total vulnerability count
                        vulnerablePackage.VulnerabilityCount = advisories.Count;

                        // Count occurrences of each severity level
                        Dictionary<string, int> severityCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                        foreach (GitHubAdvisory advisory in advisories)
                        {
                            string severity = string.IsNullOrEmpty(advisory.Severity) ? "Unknown" : advisory.Severity;
                            if (severityCounts.ContainsKey(severity))
                            {
                                severityCounts[severity]++;
                            }
                            else
                            {
                                severityCounts[severity] = 1;
                            }
                        }

                        // Create a summary description
                        List<string> severitySummaries = new List<string>();
                        foreach (KeyValuePair<string, int> severityCount in severityCounts)
                        {
                            severitySummaries.Add($"{severityCount.Value} {severityCount.Key}");
                        }
                        vulnerablePackage.Description = string.Join(", ", severitySummaries);

                        // Determine maximum severity level
                        vulnerablePackage.Severity = GetMaxSeverity(advisories.Select(a => a.Severity).ToList());
                    }
                }
                else
                {
                    Log.LogWarning($"Failed to get vulnerability data: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");
                }
            }
        }
        catch (Exception ex)
        {
            Log.LogWarning($"Error checking for vulnerabilities: {ex.Message}");
        }

        return packageVulnerabilities.Values.ToList();
    }

    private string GetMaxSeverity(List<string> severities)
    {
        if (severities == null || severities.Count == 0)
        {
            return "Unknown";
        }

        string maxSeverity = "Unknown";
        int maxRank = 0;

        foreach (string severity in severities)
        {
            string normalizedSeverity = string.IsNullOrEmpty(severity) ? "Unknown" : severity;

            if (s_severityRanking.TryGetValue(normalizedSeverity, out int rank))
            {
                if (rank > maxRank)
                {
                    maxRank = rank;
                    maxSeverity = normalizedSeverity;
                }
            }
        }

        return maxSeverity;
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
