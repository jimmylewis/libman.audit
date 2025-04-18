namespace Libman.Audit;

public interface IGitHubAdvisoryClient
{
    Task<AdvisoryResult> GetAdvisoriesAsync(string packageName, string packageVersion);
}
