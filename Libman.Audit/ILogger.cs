using Microsoft.Build.Framework;

namespace Libman.Audit;

public interface ILogger
{
    void LogMessage(string message, MessageImportance importance = MessageImportance.Normal);
    void LogWarning(string message);
    void LogError(string message);
}
