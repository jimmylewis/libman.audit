using System;

namespace Libman.Audit;

public class VulnerablePackage
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public int VulnerabilityCount { get; set; }
    public string Description { get; set; } = string.Empty;
}
