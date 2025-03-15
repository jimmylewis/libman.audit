using System;
using System.Text.Json.Serialization;

namespace Libman.Audit;

public class SonatypeRequest
{
    [JsonPropertyName("coordinates")]
    public string[] Coordinates { get; set; } = Array.Empty<string>();
}
