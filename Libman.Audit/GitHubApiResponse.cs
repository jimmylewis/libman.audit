namespace Libman.Audit;

public class GitHubAdvisory
{
    public string Severity { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

public class GitHubApiResponse
{
    public Data Data { get; set; } = new Data();
}

public class Data
{
    public SecurityVulnerabilities SecurityVulnerabilities { get; set; } = new SecurityVulnerabilities();
}

public class SecurityVulnerabilities
{
    public List<Node> Nodes { get; set; } = new List<Node>();
}

public class Node
{
    public string Severity { get; set; } = string.Empty;
    public Advisory Advisory { get; set; } = new Advisory();
}
