using System.Net.Http;
using System.Text.Json;

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

    public async Task<AdvisoryResult> GetAdvisoriesAsync(string packageName, string packageVersion)
    {
        string url = $"{GitHubApiUrl}?affects={packageName}@{packageVersion}";

        try
        {
            HttpResponseMessage response = await _httpClient.GetAsync(url);

            if (!response.IsSuccessStatusCode)
            {
                // Check if we have connectivity issues
                if (response.StatusCode == System.Net.HttpStatusCode.ServiceUnavailable ||
                    response.StatusCode == System.Net.HttpStatusCode.RequestTimeout ||
                    response.StatusCode == System.Net.HttpStatusCode.GatewayTimeout)
                {
                    return new AdvisoryResult(
                        new List<GitHubAdvisory>(),
                        $"Warning: Unable to access GitHub Advisory API due to connectivity issues. Security vulnerabilities cannot be checked for {packageName} {packageVersion}."
                    );
                }

                return new AdvisoryResult(new List<GitHubAdvisory>());
            }

            string responseContent = await response.Content.ReadAsStringAsync();
            List<GitHubAdvisory>? advisories = JsonSerializer.Deserialize<List<GitHubAdvisory>>(responseContent, _jsonOptions);

            return new AdvisoryResult(advisories ?? new List<GitHubAdvisory>());
        }
        catch (HttpRequestException ex)
        {
            // Catch network-related exceptions
            return new AdvisoryResult(
                new List<GitHubAdvisory>(),
                $"Warning: Unable to access GitHub Advisory API. Security vulnerabilities cannot be checked for {packageName} {packageVersion}. Error: {ex.Message}"
            );
        }
        catch (TaskCanceledException)
        {
            // Timeout exceptions
            return new AdvisoryResult(
                new List<GitHubAdvisory>(),
                $"Warning: Request to GitHub Advisory API timed out. Security vulnerabilities cannot be checked for {packageName} {packageVersion}."
            );
        }
        catch (Exception ex)
        {
            // Other unexpected exceptions
            return new AdvisoryResult(
                new List<GitHubAdvisory>(),
                $"Warning: An error occurred while checking for security vulnerabilities for {packageName} {packageVersion}. Error: {ex.Message}"
            );
        }
    }
}
