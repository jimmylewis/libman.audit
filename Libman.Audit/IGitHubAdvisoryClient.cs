using System.Collections.Generic;
using System.Threading.Tasks;

namespace Libman.Audit;

public interface IGitHubAdvisoryClient
{
    Task<List<GitHubAdvisory>> GetAdvisoriesAsync(string packageName, string packageVersion);
}
