namespace Libman.Audit;

public class AdvisoryResult
{
    public List<GitHubAdvisory> Advisories { get; } = new List<GitHubAdvisory>();
    public string? Warning { get; }
    public bool HasWarning => !string.IsNullOrEmpty(Warning);

    public AdvisoryResult(List<GitHubAdvisory> advisories, string? warning = null)
    {
        Advisories = advisories;
        Warning = warning;
    }
}
