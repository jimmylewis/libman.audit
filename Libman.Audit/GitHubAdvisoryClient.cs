using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace Libman.Audit;

public class GitHubAdvisoryClient : IGitHubAdvisoryClient
{
    private readonly HttpClient _httpClient;
    private const string GitHubApiUrl = "https://api.github.com/advisories";
    private readonly JsonSerializerOptions _jsonOptions;

    public GitHubAdvisoryClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "Libman.Audit/1.0");
        
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
    }

    public async Task<List<GitHubAdvisory>> GetAdvisoriesAsync(string packageName, string packageVersion)
    {
        string url = $"{GitHubApiUrl}?package={packageName}&version={packageVersion}";
        HttpResponseMessage response = await _httpClient.GetAsync(url);

        if (!response.IsSuccessStatusCode)
        {
            return new List<GitHubAdvisory>();
        }

        string responseContent = await response.Content.ReadAsStringAsync();
        List<GitHubAdvisory>? advisories = JsonSerializer.Deserialize<List<GitHubAdvisory>>(responseContent, _jsonOptions);
        
        return advisories ?? new List<GitHubAdvisory>();
    }
}
