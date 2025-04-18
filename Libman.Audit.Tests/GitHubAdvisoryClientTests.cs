using System.Net;

namespace Libman.Audit.Tests;

public class GitHubAdvisoryClientTests
{
    private readonly MockHttpMessageHandler _handler;
    private readonly HttpClient _httpClient;
    private readonly GitHubAdvisoryClient _sut;

    public GitHubAdvisoryClientTests()
    {
        _handler = new MockHttpMessageHandler();
        _httpClient = new HttpClient(_handler);
        _sut = new GitHubAdvisoryClient(_httpClient);
    }

    [Fact]
    public async Task GetAdvisoriesAsync_SuccessfulResponse_ReturnsAdvisories()
    {
        // Arrange
        string packageName = "test-package";
        string packageVersion = "1.0.0";
        string jsonResponse = "[{\"severity\":\"high\",\"description\":\"Test advisory\"}]";

        var handler = new MockHttpMessageHandler();
        handler.SetResponse(HttpStatusCode.OK, jsonResponse);

        var client = new HttpClient(handler);
        var sut = new GitHubAdvisoryClient(client);

        // Act
        var result = await sut.GetAdvisoriesAsync(packageName, packageVersion);

        // Assert
        Assert.Single(result.Advisories);
        Assert.Equal("high", result.Advisories[0].Severity);
        Assert.Equal("Test advisory", result.Advisories[0].Description);
        Assert.False(result.HasWarning);
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.RequestTimeout)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    public async Task GetAdvisoriesAsync_ConnectivityIssue_ReturnsWarning(HttpStatusCode responseCode)
    {
        // Arrange
        string packageName = "test-package";
        string packageVersion = "1.0.0";

        var handler = new MockHttpMessageHandler();
        handler.SetResponse(responseCode);

        var client = new HttpClient(handler);
        var sut = new GitHubAdvisoryClient(client);

        // Act
        var result = await sut.GetAdvisoriesAsync(packageName, packageVersion);

        // Assert
        Assert.Empty(result.Advisories);
        Assert.True(result.HasWarning);
        Assert.Contains("connectivity issues", result.Warning);
    }

    [Fact]
    public async Task GetAdvisoriesAsync_Timeout_ReturnsWarning()
    {
        // Arrange
        string packageName = "test-package";
        string packageVersion = "1.0.0";

        var handler = new MockHttpMessageHandler();
        handler.SetTimeout();

        var client = new HttpClient(handler);
        var sut = new GitHubAdvisoryClient(client);

        // Act
        var result = await sut.GetAdvisoriesAsync(packageName, packageVersion);

        // Assert
        Assert.Empty(result.Advisories);
        Assert.True(result.HasWarning);
        Assert.Contains("timed out", result.Warning);
    }

    [Fact]
    public async Task GetAdvisoriesAsync_UnexpectedException_ReturnsWarning()
    {
        // Arrange
        string packageName = "test-package";
        string packageVersion = "1.0.0";

        var handler = new MockHttpMessageHandler();
        handler.SetException(new Exception("Unexpected error"));

        var client = new HttpClient(handler);
        var sut = new GitHubAdvisoryClient(client);

        // Act
        var result = await sut.GetAdvisoriesAsync(packageName, packageVersion);

        // Assert
        Assert.Empty(result.Advisories);
        Assert.True(result.HasWarning);
        Assert.Contains("Unexpected error", result.Warning);
    }
}

public class MockHttpMessageHandler : HttpMessageHandler
{
    private List<(Func<HttpRequestMessage, bool> Predicate, HttpResponseMessage Response)> _responses = new();
    private HttpResponseMessage? _response;
    private Exception? _exception;

    public void SetResponseIf(Func<HttpRequestMessage, bool> predicate, HttpResponseMessage response)
    {
        _responses.Add((predicate, response));
    }

    public void SetResponse(HttpStatusCode statusCode, string? content = null)
    {
        _response = new HttpResponseMessage
        {
            StatusCode = statusCode,
            Content = content != null ? new StringContent(content) : null
        };
    }

    public void SetTimeout()
    {
        _exception = new TaskCanceledException();
    }

    public void SetException(Exception exception)
    {
        _exception = exception;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_exception != null)
        {
            throw _exception;
        }

        foreach (var (predicate, response) in _responses)
        {
            if (predicate(request))
            {
                return Task.FromResult(response);
            }
        }

        return Task.FromResult(_response ?? new HttpResponseMessage(HttpStatusCode.InternalServerError));
    }
}
