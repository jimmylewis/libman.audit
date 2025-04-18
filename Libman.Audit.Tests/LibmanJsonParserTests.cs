using NSubstitute;

namespace Libman.Audit.Tests;

public class LibmanJsonParserTests
{
    private readonly ILogger _logger;
    private readonly LibmanJsonParser _sut;

    public LibmanJsonParserTests()
    {
        _logger = Substitute.For<ILogger>();
        _sut = new LibmanJsonParser(_logger);
    }

    [Fact]
    public void Parse_ValidJson_WithCdnjsProvider_WithVersion_ShouldReturnPackage()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "library": "jquery@3.6.0",
                    "destination": "wwwroot/lib/jquery/",
                    "provider": "cdnjs",
                    "files": ["jquery.min.js"]
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("jquery", result[0].Name);
        Assert.Equal("3.6.0", result[0].Version);
        Assert.Equal("cdnjs", result[0].Provider);
    }

    [Fact]
    public void Parse_ValidJson_WithUnpkgProvider_WithVersion_ShouldReturnPackage()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "library": "react@17.0.2",
                    "destination": "wwwroot/lib/react/",
                    "provider": "unpkg",
                    "files": ["umd/react.production.min.js"]
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("react", result[0].Name);
        Assert.Equal("17.0.2", result[0].Version);
        Assert.Equal("unpkg", result[0].Provider);
    }

    [Fact]
    public void Parse_ValidJson_WithJsdelivrProvider_WithVersion_ShouldReturnPackage()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "library": "bootstrap@5.1.3",
                    "destination": "wwwroot/lib/bootstrap/",
                    "provider": "jsdelivr",
                    "files": ["dist/css/bootstrap.min.css"]
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("bootstrap", result[0].Name);
        Assert.Equal("5.1.3", result[0].Version);
        Assert.Equal("jsdelivr", result[0].Provider);
    }

    [Fact]
    public void Parse_ValidJson_WithFilesystemProvider_ShouldReturnPackage()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "library": "locallib",
                    "destination": "wwwroot/lib/local/",
                    "provider": "filesystem",
                    "files": ["js/local.js"]
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("locallib", result[0].Name);
        Assert.Equal("", result[0].Version);
        Assert.Equal("filesystem", result[0].Provider);
    }

    [Fact]
    public void Parse_ValidJson_WithNoVersion_ShouldReturnPackageWithEmptyVersion()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "library": "font-awesome",
                    "destination": "wwwroot/lib/font-awesome/",
                    "provider": "cdnjs"
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("font-awesome", result[0].Name);
        Assert.Equal("", result[0].Version);
        Assert.Equal("cdnjs", result[0].Provider);
    }

    [Fact]
    public void Parse_ValidJson_WithMultipleLibraries_ShouldReturnMultiplePackages()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "library": "jquery@3.6.0",
                    "destination": "wwwroot/lib/jquery/",
                    "provider": "cdnjs"
                },
                {
                    "library": "bootstrap@5.1.3",
                    "destination": "wwwroot/lib/bootstrap/",
                    "provider": "jsdelivr"
                },
                {
                    "library": "vue@3.2.31",
                    "destination": "wwwroot/lib/vue/",
                    "provider": "unpkg"
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Equal(3, result.Count);
        Assert.Equal("jquery", result[0].Name);
        Assert.Equal("bootstrap", result[1].Name);
        Assert.Equal("vue", result[2].Name);
    }

    [Fact]
    public void Parse_EmptyLibrariesArray_ShouldReturnEmptyList()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": []
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Empty(result);
        _logger.Received(1).LogMessage("No libraries found in libman.json");
    }

    [Fact]
    public void Parse_NoLibrariesProperty_ShouldReturnEmptyList()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs"
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Empty(result);
        _logger.Received(1).LogMessage("No libraries found in libman.json");
    }

    [Fact]
    public void Parse_MissingProviderProperty_ShouldSkipLibrary()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "libraries": [
                {
                    "library": "jquery@3.6.0",
                    "destination": "wwwroot/lib/jquery/"
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void Parse_MissingProviderProperty_WithDefaultProvider_ShouldUseDefaultProvider()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "library": "jquery@3.6.0",
                    "destination": "wwwroot/lib/jquery/"
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("jquery", result[0].Name);
        Assert.Equal("3.6.0", result[0].Version);
        Assert.Equal("cdnjs", result[0].Provider); // Should use defaultProvider
    }

    [Fact]
    public void Parse_MissingLibraryProperty_ShouldSkipLibrary()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "provider": "cdnjs",
                    "destination": "wwwroot/lib/jquery/"
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void Parse_InvalidJson_ShouldReturnEmptyListAndLogError()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "defaultProvider": "cdnjs",
            "libraries": [
                {
                    "library": "jquery@3.6.0",
                    "destination": "wwwroot/lib/jquery/",
                    "provider": "cdnjs",
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Empty(result);
        _logger.Received(1).LogError(Arg.Any<string>());
    }

    [Fact]
    public void Parse_EmptyJson_ShouldReturnEmptyListAndLogError()
    {
        // Arrange
        string jsonContent = "";

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Empty(result);
        _logger.Received(1).LogError(Arg.Any<string>());
    }

    [Fact]
    public void Parse_ValidJson_WithFilesystemProvider_ShouldNotSplitOnAtSymbol()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "libraries": [
                {
                    "library": "local@lib",
                    "provider": "filesystem"
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("local@lib", result[0].Name);
        Assert.Equal("", result[0].Version);
        Assert.Equal("filesystem", result[0].Provider);
    }

    [Fact]
    public void Parse_ValidJson_WithUnpkgProvider_WithScopedPackage_ShouldSplitOnSecondAtSymbol()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "libraries": [
                {
                    "library": "@scope/package@1.0.0",
                    "provider": "unpkg"
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("@scope/package", result[0].Name);
        Assert.Equal("1.0.0", result[0].Version);
        Assert.Equal("unpkg", result[0].Provider);
    }

    [Fact]
    public void Parse_ValidJson_WithJsdelivrProvider_WithScopedPackage_ShouldSplitOnSecondAtSymbol()
    {
        // Arrange
        string jsonContent = """
        {
            "version": "1.0",
            "libraries": [
                {
                    "library": "@scope/package@2.0.0",
                    "provider": "jsdelivr"
                }
            ]
        }
        """;

        // Act
        var result = _sut.Parse(jsonContent);

        // Assert
        Assert.Single(result);
        Assert.Equal("@scope/package", result[0].Name);
        Assert.Equal("2.0.0", result[0].Version);
        Assert.Equal("jsdelivr", result[0].Provider);
    }
}
