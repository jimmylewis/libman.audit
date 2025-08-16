# Libman.Audit

[![.NET CI/CD](https://github.com/jimmylewis/libman.audit/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/libman-audit/actions/workflows/ci.yml)
<!--
[![NuGet Version](https://img.shields.io/nuget/v/Libman.Audit.svg)](https://www.nuget.org/packages/Libman.Audit/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Libman.Audit.svg)](https://www.nuget.org/packages/Libman.Audit/)
-->

A security audit tool for LibMan (Library Manager) that automatically scans your `libman.json` file for known security vulnerabilities in client-side libraries during the build process.

## Features

- 🔍 **Automatic vulnerability scanning** during MSBuild
- 🚨 **GitHub Advisory Database integration** for up-to-date vulnerability information
- 🎯 **Supports multiple LibMan providers** (cdnjs, unpkg, jsdelivr)
- 🛑 **Build failures** for Critical and High severity vulnerabilities
- ⚠️ **Build warnings** for Medium and Low severity vulnerabilities
- 📊 **Detailed vulnerability reporting** with severity levels and counts
- 🔧 **Zero configuration** - works automatically when installed
- 🎨 **Multi-targeting** - supports MSBuild for .NET Framework and .NET (8+)

## Installation

Install the NuGet package in your ASP.NET Core or web project:

### Package Manager Console
```
dotnet add package Libman.Audit
```

### PackageReference
```
<PackageReference Include="Libman.Audit" Version="..." />
```


## How It Works

Libman.Audit automatically integrates with your build process and:

1. **Scans** your `libman.json` file for client-side library dependencies
2. **Queries** the GitHub Advisory Database for known vulnerabilities
3. **Reports** findings during build with appropriate severity levels
4. **Fails the build** for Critical/High severity vulnerabilities
5. **Shows warnings** for Medium/Low severity vulnerabilities

## Usage

### Automatic Integration

Once installed, Libman.Audit runs automatically during every build. No configuration required!


## Supported Providers

Libman.Audit supports the LibMan providers that source from well-known packages:

- **cdnjs** 
- **unpkg** 
- **jsdelivr** 

Note: **filesystem** provider is not supported as it does not catalog well-known libraries.

## Default Vulnerability Severity Levels

| Severity		| Build Action		| Description |
|----------		|-------------		|-------------|
| **Critical**	| ❌ Build Error	| Immediate action required |
| **High**		| ❌ Build Error	| Should be addressed promptly |
| **Medium**	| ⚠️ Build Warning	| Should be reviewed and planned for remediation |
| **Low**		| ⚠️ Build Warning	| Consider updating when convenient |
| **Unknown**	| ⚠️ Build Warning	| Severity could not be determined |

## Configuration

### Disable for Specific Projects

To disable Libman.Audit for a specific project, add this to your `.csproj` file:
```
<PropertyGroup>
  <SkipLibmanAudit>true</SkipLibmanAudit>
</PropertyGroup>
```

<!--
### Custom libman.json Location

By default, Libman.Audit looks for `libman.json` in your project root. To specify a different location:
```
<PropertyGroup>
  <LibmanJsonPath>path/to/your/libman.json</LibmanJsonPath>
</PropertyGroup>
```
-->
