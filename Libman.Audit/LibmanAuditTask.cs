using System.Net.Http;
using Microsoft.Build.Framework;

using Task = Microsoft.Build.Utilities.Task;

namespace Libman.Audit;

public class LibmanAuditTask : Task
{
    private readonly ILibmanJsonParser _jsonParser;
    private readonly IVulnerabilityAnalyzer _vulnerabilityAnalyzer;
    private readonly ITaskItemConverter _taskItemConverter;
    private readonly ILogger _logger;

    [Required]
    public string LibmanJsonPath { get; set; }

    // Constructor for MSBuild to use
    public LibmanAuditTask()
    {
        HttpClient httpClient = new HttpClient();
        ILogger logger = new MsBuildLogger(Log);

        _jsonParser = new LibmanJsonParser(logger);
        _taskItemConverter = new TaskItemConverter();

        IGitHubAdvisoryClient advisoryClient = new GitHubAdvisoryClient(httpClient);
        _vulnerabilityAnalyzer = new VulnerabilityAnalyzer(advisoryClient, logger);

        // initialize non-null values
        LibmanJsonPath = "";
        _logger = logger;
    }

    // Constructor for testing
    internal LibmanAuditTask(
        ILibmanJsonParser jsonParser,
        IVulnerabilityAnalyzer vulnerabilityAnalyzer,
        ITaskItemConverter taskItemConverter,
        ILogger logger)
    {
        _jsonParser = jsonParser;
        _vulnerabilityAnalyzer = vulnerabilityAnalyzer;
        _taskItemConverter = taskItemConverter;
        _logger = logger;

        // initialize non-null values
        LibmanJsonPath = "";
    }

    public override bool Execute()
    {
        return ExecuteAsync().GetAwaiter().GetResult();
    }

    private async Task<bool> ExecuteAsync()
    {
        try
        {
            _logger.LogMessage("Starting Libman audit task...", LogLevel.Low);

            if (!File.Exists(LibmanJsonPath))
            {
                _logger.LogError($"Libman.json file not found at: {LibmanJsonPath}");
                return false;
            }

#if NETFRAMEWORK
            string jsonContent = File.ReadAllText(LibmanJsonPath);
#else
            string jsonContent = await File.ReadAllTextAsync(LibmanJsonPath);
#endif

            // Parse the libman.json file
            List<LibmanPackage> libmanPackages = _jsonParser.Parse(jsonContent);

            if (libmanPackages.Count == 0)
            {
                _logger.LogMessage("No packages found in libman.json");
                return true;
            }

            // Analyze packages for vulnerabilities
            List<VulnerablePackage> vulnerablePackages = await _vulnerabilityAnalyzer.AnalyzePackagesAsync(libmanPackages);

            if (vulnerablePackages.Count > 0)
            {
                _logger.LogWarning($"Found {vulnerablePackages.Count} vulnerable packages in libman.json");
                foreach (VulnerablePackage package in vulnerablePackages)
                {
                    _logger.LogWarning($"Vulnerable package: {package.Name}@{package.Version} has {package.Description}");
                }
            }
            else
            {
                _logger.LogMessage("No vulnerable packages found", LogLevel.Low);
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error executing LibmanAuditTask: {ex.Message}");
            return false;
        }
    }
}
