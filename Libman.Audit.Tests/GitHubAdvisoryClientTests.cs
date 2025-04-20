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
    public async Task GetAdvisoriesAsync_SuccessfulResponse_ReturnsSingleAdvisory()
    {
        // Arrange
        string packageName = "test-package";
        string packageVersion = "1.0.0";

        _handler.SetResponse(HttpStatusCode.OK, _recordedResponse);

        // Act
        var result = await _sut.GetAdvisoriesAsync(packageName, packageVersion);

        // Assert
        Assert.Single(result.Advisories);
        Assert.Equal("low", result.Advisories[0].Severity);
        Assert.Equal("Test advisory", result.Advisories[0].Description);
        Assert.False(result.HasWarning);
    }

    [Fact]
    public async Task GetAdvisoriesAsync_SuccessfulResponse_MultipleRecords_ReturnsAllAdvisories()
    {
        // Arrange
        string packageName = "test-package";
        string packageVersion = "1.0.0";
        _handler.SetResponse(HttpStatusCode.OK, _recordedResponseMultipleRecords);
        // Act
        var result = await _sut.GetAdvisoriesAsync(packageName, packageVersion);
        // Assert
        Assert.Equal(3, result.Advisories.Count);
        Assert.Equal("high", result.Advisories[2].Severity);
        Assert.Equal("test advisory - high", result.Advisories[2].Description);
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

    private const string _recordedResponse = """
        [
          {
            "ghsa_id": "GHSA-8p5q-j9m2-g8wr",
            "cve_id": "CVE-2021-41720",
            "url": "https://api.github.com/advisories/GHSA-8p5q-j9m2-g8wr",
            "html_url": "https://github.com/advisories/GHSA-8p5q-j9m2-g8wr",
            "summary": "Withdrawn: Arbitrary code execution in lodash",
            "description": "Test advisory",
            "type": "unreviewed",
            "severity": "low",
            "repository_advisory_url": null,
            "source_code_location": "https://github.com/lodash/lodash",
            "identifiers": [
              {
                "value": "GHSA-8p5q-j9m2-g8wr",
                "type": "GHSA"
              },
              {
                "value": "CVE-2021-41720",
                "type": "CVE"
              }
            ],
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-41720",
              "https://github.com/lodash/lodash/issues/5261",
              "https://web.archive.org/web/20211004200531/https:/github.com/lodash/lodash/issues/5261",
              "https://github.com/advisories/GHSA-8p5q-j9m2-g8wr"
            ],
            "published_at": "2021-12-03T20:37:32Z",
            "updated_at": "2023-02-01T05:06:10Z",
            "github_reviewed_at": null,
            "nvd_published_at": "2021-09-30T14:15:00Z",
            "withdrawn_at": "2021-10-01T22:04:28Z",
            "vulnerabilities": [
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash"
                },
                "vulnerable_version_range": "<= 4.17.21",
                "first_patched_version": null,
                "vulnerable_functions": []
              }
            ],
            "cvss_severities": {
              "cvss_v3": {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8
              },
              "cvss_v4": {
                "vector_string": null,
                "score": 0.0
              }
            },
            "cwes": [
              {
                "cwe_id": "CWE-77",
                "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')"
              }
            ],
            "credits": [],
            "cvss": {
              "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "score": 9.8
            },
            "epss": {
              "percentage": 0.00602,
              "percentile": 0.78507
            }
          }
        ]
        
        """;

    private const string _recordedResponseMultipleRecords = """
        [
          {
            "ghsa_id": "GHSA-29mw-wpgm-hmr9",
            "cve_id": "CVE-2020-28500",
            "url": "https://api.github.com/advisories/GHSA-29mw-wpgm-hmr9",
            "html_url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
            "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
            "description": "test advisory - medium",
            "type": "reviewed",
            "severity": "medium",
            "repository_advisory_url": null,
            "source_code_location": "https://github.com/lodash/lodash",
            "identifiers": [
              {
                "value": "GHSA-29mw-wpgm-hmr9",
                "type": "GHSA"
              },
              {
                "value": "CVE-2020-28500",
                "type": "CVE"
              }
            ],
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2020-28500",
              "https://github.com/lodash/lodash/pull/5065",
              "https://github.com/lodash/lodash/pull/5065/commits/02906b8191d3c100c193fe6f7b27d1c40f200bb7",
              "https://github.com/lodash/lodash/blob/npm/trimEnd.js%23L8",
              "https://security.netapp.com/advisory/ntap-20210312-0006/",
              "https://snyk.io/vuln/SNYK-JS-LODASH-1018905",
              "https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074896",
              "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074894",
              "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074892",
              "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074895",
              "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074893",
              "https://www.oracle.com//security-alerts/cpujul2021.html",
              "https://www.oracle.com/security-alerts/cpuoct2021.html",
              "https://www.oracle.com/security-alerts/cpujan2022.html",
              "https://www.oracle.com/security-alerts/cpujul2022.html",
              "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
              "https://github.com/lodash/lodash/commit/c4847ebe7d14540bb28a8b932a9ce1b9ecbfee1a",
              "https://github.com/advisories/GHSA-29mw-wpgm-hmr9"
            ],
            "published_at": "2022-01-06T20:30:46Z",
            "updated_at": "2023-11-01T23:21:12Z",
            "github_reviewed_at": "2021-03-19T22:45:28Z",
            "nvd_published_at": "2021-02-15T11:15:00Z",
            "withdrawn_at": null,
            "vulnerabilities": [
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash"
                },
                "vulnerable_version_range": "< 4.17.21",
                "first_patched_version": "4.17.21",
                "vulnerable_functions": []
              },
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash-es"
                },
                "vulnerable_version_range": "< 4.17.21",
                "first_patched_version": "4.17.21",
                "vulnerable_functions": []
              },
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash.trimend"
                },
                "vulnerable_version_range": "<= 4.5.1",
                "first_patched_version": null,
                "vulnerable_functions": []
              },
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash.trim"
                },
                "vulnerable_version_range": "<= 4.5.1",
                "first_patched_version": null,
                "vulnerable_functions": []
              }
            ],
            "cvss_severities": {
              "cvss_v3": {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                "score": 5.3
              },
              "cvss_v4": {
                "vector_string": null,
                "score": 0.0
              }
            },
            "cwes": [
              {
                "cwe_id": "CWE-400",
                "name": "Uncontrolled Resource Consumption"
              },
              {
                "cwe_id": "CWE-1333",
                "name": "Inefficient Regular Expression Complexity"
              }
            ],
            "credits": [
              {
                "user": {
                  "login": "mitchell-codecov",
                  "id": 88285871,
                  "node_id": "MDQ6VXNlcjg4Mjg1ODcx",
                  "avatar_url": "https://avatars.githubusercontent.com/u/88285871?v=4",
                  "gravatar_id": "",
                  "url": "https://api.github.com/users/mitchell-codecov",
                  "html_url": "https://github.com/mitchell-codecov",
                  "followers_url": "https://api.github.com/users/mitchell-codecov/followers",
                  "following_url": "https://api.github.com/users/mitchell-codecov/following{/other_user}",
                  "gists_url": "https://api.github.com/users/mitchell-codecov/gists{/gist_id}",
                  "starred_url": "https://api.github.com/users/mitchell-codecov/starred{/owner}{/repo}",
                  "subscriptions_url": "https://api.github.com/users/mitchell-codecov/subscriptions",
                  "organizations_url": "https://api.github.com/users/mitchell-codecov/orgs",
                  "repos_url": "https://api.github.com/users/mitchell-codecov/repos",
                  "events_url": "https://api.github.com/users/mitchell-codecov/events{/privacy}",
                  "received_events_url": "https://api.github.com/users/mitchell-codecov/received_events",
                  "type": "User",
                  "user_view_type": "public",
                  "site_admin": false
                },
                "type": "analyst"
              },
              {
                "user": {
                  "login": "nitaiapiiro",
                  "id": 108618197,
                  "node_id": "U_kgDOBnlh1Q",
                  "avatar_url": "https://avatars.githubusercontent.com/u/108618197?v=4",
                  "gravatar_id": "",
                  "url": "https://api.github.com/users/nitaiapiiro",
                  "html_url": "https://github.com/nitaiapiiro",
                  "followers_url": "https://api.github.com/users/nitaiapiiro/followers",
                  "following_url": "https://api.github.com/users/nitaiapiiro/following{/other_user}",
                  "gists_url": "https://api.github.com/users/nitaiapiiro/gists{/gist_id}",
                  "starred_url": "https://api.github.com/users/nitaiapiiro/starred{/owner}{/repo}",
                  "subscriptions_url": "https://api.github.com/users/nitaiapiiro/subscriptions",
                  "organizations_url": "https://api.github.com/users/nitaiapiiro/orgs",
                  "repos_url": "https://api.github.com/users/nitaiapiiro/repos",
                  "events_url": "https://api.github.com/users/nitaiapiiro/events{/privacy}",
                  "received_events_url": "https://api.github.com/users/nitaiapiiro/received_events",
                  "type": "User",
                  "user_view_type": "public",
                  "site_admin": false
                },
                "type": "analyst"
              },
              {
                "user": {
                  "login": "DmitriyLewen",
                  "id": 91113035,
                  "node_id": "MDQ6VXNlcjkxMTEzMDM1",
                  "avatar_url": "https://avatars.githubusercontent.com/u/91113035?v=4",
                  "gravatar_id": "",
                  "url": "https://api.github.com/users/DmitriyLewen",
                  "html_url": "https://github.com/DmitriyLewen",
                  "followers_url": "https://api.github.com/users/DmitriyLewen/followers",
                  "following_url": "https://api.github.com/users/DmitriyLewen/following{/other_user}",
                  "gists_url": "https://api.github.com/users/DmitriyLewen/gists{/gist_id}",
                  "starred_url": "https://api.github.com/users/DmitriyLewen/starred{/owner}{/repo}",
                  "subscriptions_url": "https://api.github.com/users/DmitriyLewen/subscriptions",
                  "organizations_url": "https://api.github.com/users/DmitriyLewen/orgs",
                  "repos_url": "https://api.github.com/users/DmitriyLewen/repos",
                  "events_url": "https://api.github.com/users/DmitriyLewen/events{/privacy}",
                  "received_events_url": "https://api.github.com/users/DmitriyLewen/received_events",
                  "type": "User",
                  "user_view_type": "public",
                  "site_admin": false
                },
                "type": "analyst"
              },
              {
                "user": {
                  "login": "jkmartindale",
                  "id": 11380394,
                  "node_id": "MDQ6VXNlcjExMzgwMzk0",
                  "avatar_url": "https://avatars.githubusercontent.com/u/11380394?v=4",
                  "gravatar_id": "",
                  "url": "https://api.github.com/users/jkmartindale",
                  "html_url": "https://github.com/jkmartindale",
                  "followers_url": "https://api.github.com/users/jkmartindale/followers",
                  "following_url": "https://api.github.com/users/jkmartindale/following{/other_user}",
                  "gists_url": "https://api.github.com/users/jkmartindale/gists{/gist_id}",
                  "starred_url": "https://api.github.com/users/jkmartindale/starred{/owner}{/repo}",
                  "subscriptions_url": "https://api.github.com/users/jkmartindale/subscriptions",
                  "organizations_url": "https://api.github.com/users/jkmartindale/orgs",
                  "repos_url": "https://api.github.com/users/jkmartindale/repos",
                  "events_url": "https://api.github.com/users/jkmartindale/events{/privacy}",
                  "received_events_url": "https://api.github.com/users/jkmartindale/received_events",
                  "type": "User",
                  "user_view_type": "public",
                  "site_admin": false
                },
                "type": "analyst"
              }
            ],
            "cvss": {
              "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "score": 5.3
            },
            "epss": {
              "percentage": 0.00275,
              "percentile": 0.50507
            }
          },
          {
            "ghsa_id": "GHSA-8p5q-j9m2-g8wr",
            "cve_id": "CVE-2021-41720",
            "url": "https://api.github.com/advisories/GHSA-8p5q-j9m2-g8wr",
            "html_url": "https://github.com/advisories/GHSA-8p5q-j9m2-g8wr",
            "summary": "Withdrawn: Arbitrary code execution in lodash",
            "description": "test advisory - low",
            "type": "unreviewed",
            "severity": "low",
            "repository_advisory_url": null,
            "source_code_location": "https://github.com/lodash/lodash",
            "identifiers": [
              {
                "value": "GHSA-8p5q-j9m2-g8wr",
                "type": "GHSA"
              },
              {
                "value": "CVE-2021-41720",
                "type": "CVE"
              }
            ],
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-41720",
              "https://github.com/lodash/lodash/issues/5261",
              "https://web.archive.org/web/20211004200531/https:/github.com/lodash/lodash/issues/5261",
              "https://github.com/advisories/GHSA-8p5q-j9m2-g8wr"
            ],
            "published_at": "2021-12-03T20:37:32Z",
            "updated_at": "2023-02-01T05:06:10Z",
            "github_reviewed_at": null,
            "nvd_published_at": "2021-09-30T14:15:00Z",
            "withdrawn_at": "2021-10-01T22:04:28Z",
            "vulnerabilities": [
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash"
                },
                "vulnerable_version_range": "<= 4.17.21",
                "first_patched_version": null,
                "vulnerable_functions": []
              }
            ],
            "cvss_severities": {
              "cvss_v3": {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8
              },
              "cvss_v4": {
                "vector_string": null,
                "score": 0.0
              }
            },
            "cwes": [
              {
                "cwe_id": "CWE-77",
                "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')"
              }
            ],
            "credits": [],
            "cvss": {
              "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "score": 9.8
            },
            "epss": {
              "percentage": 0.00602,
              "percentile": 0.78507
            }
          },
          {
            "ghsa_id": "GHSA-35jh-r3h4-6jhm",
            "cve_id": "CVE-2021-23337",
            "url": "https://api.github.com/advisories/GHSA-35jh-r3h4-6jhm",
            "html_url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
            "summary": "Command Injection in lodash",
            "description": "test advisory - high",
            "type": "reviewed",
            "severity": "high",
            "repository_advisory_url": null,
            "source_code_location": "https://github.com/lodash/lodash",
            "identifiers": [
              {
                "value": "GHSA-35jh-r3h4-6jhm",
                "type": "GHSA"
              },
              {
                "value": "CVE-2021-23337",
                "type": "CVE"
              }
            ],
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
              "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c",
              "https://snyk.io/vuln/SNYK-JS-LODASH-1040724",
              "https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js#L14851",
              "https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js%23L14851",
              "https://snyk.io/vuln/SNYK-JAVA-ORGFUJIONWEBJARS-1074932",
              "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARS-1074930",
              "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWER-1074928",
              "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSBOWERGITHUBLODASH-1074931",
              "https://snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-1074929",
              "https://www.oracle.com//security-alerts/cpujul2021.html",
              "https://www.oracle.com/security-alerts/cpuoct2021.html",
              "https://www.oracle.com/security-alerts/cpujan2022.html",
              "https://www.oracle.com/security-alerts/cpujul2022.html",
              "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
              "https://security.netapp.com/advisory/ntap-20210312-0006",
              "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"
            ],
            "published_at": "2021-05-06T16:05:51Z",
            "updated_at": "2024-04-17T18:39:19Z",
            "github_reviewed_at": "2021-03-31T23:59:26Z",
            "nvd_published_at": "2021-02-15T13:15:00Z",
            "withdrawn_at": null,
            "vulnerabilities": [
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash"
                },
                "vulnerable_version_range": "< 4.17.21",
                "first_patched_version": "4.17.21",
                "vulnerable_functions": []
              },
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash-es"
                },
                "vulnerable_version_range": "< 4.17.21",
                "first_patched_version": "4.17.21",
                "vulnerable_functions": []
              },
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash.template"
                },
                "vulnerable_version_range": "<= 4.5.0",
                "first_patched_version": null,
                "vulnerable_functions": []
              },
              {
                "package": {
                  "ecosystem": "npm",
                  "name": "lodash-template"
                },
                "vulnerable_version_range": "<= 1.0.0",
                "first_patched_version": null,
                "vulnerable_functions": []
              }
            ],
            "cvss_severities": {
              "cvss_v3": {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                "score": 7.2
              },
              "cvss_v4": {
                "vector_string": null,
                "score": 0.0
              }
            },
            "cwes": [
              {
                "cwe_id": "CWE-77",
                "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')"
              },
              {
                "cwe_id": "CWE-94",
                "name": "Improper Control of Generation of Code ('Code Injection')"
              }
            ],
            "credits": [
              {
                "user": {
                  "login": "mitchell-codecov",
                  "id": 88285871,
                  "node_id": "MDQ6VXNlcjg4Mjg1ODcx",
                  "avatar_url": "https://avatars.githubusercontent.com/u/88285871?v=4",
                  "gravatar_id": "",
                  "url": "https://api.github.com/users/mitchell-codecov",
                  "html_url": "https://github.com/mitchell-codecov",
                  "followers_url": "https://api.github.com/users/mitchell-codecov/followers",
                  "following_url": "https://api.github.com/users/mitchell-codecov/following{/other_user}",
                  "gists_url": "https://api.github.com/users/mitchell-codecov/gists{/gist_id}",
                  "starred_url": "https://api.github.com/users/mitchell-codecov/starred{/owner}{/repo}",
                  "subscriptions_url": "https://api.github.com/users/mitchell-codecov/subscriptions",
                  "organizations_url": "https://api.github.com/users/mitchell-codecov/orgs",
                  "repos_url": "https://api.github.com/users/mitchell-codecov/repos",
                  "events_url": "https://api.github.com/users/mitchell-codecov/events{/privacy}",
                  "received_events_url": "https://api.github.com/users/mitchell-codecov/received_events",
                  "type": "User",
                  "user_view_type": "public",
                  "site_admin": false
                },
                "type": "analyst"
              },
              {
                "user": {
                  "login": "nitaiapiiro",
                  "id": 108618197,
                  "node_id": "U_kgDOBnlh1Q",
                  "avatar_url": "https://avatars.githubusercontent.com/u/108618197?v=4",
                  "gravatar_id": "",
                  "url": "https://api.github.com/users/nitaiapiiro",
                  "html_url": "https://github.com/nitaiapiiro",
                  "followers_url": "https://api.github.com/users/nitaiapiiro/followers",
                  "following_url": "https://api.github.com/users/nitaiapiiro/following{/other_user}",
                  "gists_url": "https://api.github.com/users/nitaiapiiro/gists{/gist_id}",
                  "starred_url": "https://api.github.com/users/nitaiapiiro/starred{/owner}{/repo}",
                  "subscriptions_url": "https://api.github.com/users/nitaiapiiro/subscriptions",
                  "organizations_url": "https://api.github.com/users/nitaiapiiro/orgs",
                  "repos_url": "https://api.github.com/users/nitaiapiiro/repos",
                  "events_url": "https://api.github.com/users/nitaiapiiro/events{/privacy}",
                  "received_events_url": "https://api.github.com/users/nitaiapiiro/received_events",
                  "type": "User",
                  "user_view_type": "public",
                  "site_admin": false
                },
                "type": "analyst"
              },
              {
                "user": {
                  "login": "ebickle",
                  "id": 2086875,
                  "node_id": "MDQ6VXNlcjIwODY4NzU=",
                  "avatar_url": "https://avatars.githubusercontent.com/u/2086875?v=4",
                  "gravatar_id": "",
                  "url": "https://api.github.com/users/ebickle",
                  "html_url": "https://github.com/ebickle",
                  "followers_url": "https://api.github.com/users/ebickle/followers",
                  "following_url": "https://api.github.com/users/ebickle/following{/other_user}",
                  "gists_url": "https://api.github.com/users/ebickle/gists{/gist_id}",
                  "starred_url": "https://api.github.com/users/ebickle/starred{/owner}{/repo}",
                  "subscriptions_url": "https://api.github.com/users/ebickle/subscriptions",
                  "organizations_url": "https://api.github.com/users/ebickle/orgs",
                  "repos_url": "https://api.github.com/users/ebickle/repos",
                  "events_url": "https://api.github.com/users/ebickle/events{/privacy}",
                  "received_events_url": "https://api.github.com/users/ebickle/received_events",
                  "type": "User",
                  "user_view_type": "public",
                  "site_admin": false
                },
                "type": "analyst"
              }
            ],
            "cvss": {
              "vector_string": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
              "score": 7.2
            },
            "epss": {
              "percentage": 0.00859,
              "percentile": 0.73725
            }
          }
        ]
        
        """;
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
