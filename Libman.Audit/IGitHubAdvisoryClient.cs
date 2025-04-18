namespace Libman.Audit;

public interface IGitHubAdvisoryClient
{
    Task<List<GitHubAdvisory>> GetAdvisoriesAsync(string packageName, string packageVersion);
}
