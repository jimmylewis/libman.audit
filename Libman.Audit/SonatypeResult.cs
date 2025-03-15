using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Libman.Audit;

public class SonatypeResult
{
    [JsonPropertyName("coordinates")]
    public string Coordinates { get; set; } = string.Empty;

    [JsonPropertyName("vulnerabilities")]
    public List<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();
}
