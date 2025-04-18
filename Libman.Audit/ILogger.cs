namespace Libman.Audit;

public interface ILogger
{
    void LogMessage(string message, LogLevel level = LogLevel.Normal);
    void LogWarning(string message);
    void LogError(string message);
}
