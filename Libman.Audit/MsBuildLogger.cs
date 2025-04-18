using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

namespace Libman.Audit;

public class MsBuildLogger : ILogger
{
    private readonly TaskLoggingHelper _log;

    public MsBuildLogger(TaskLoggingHelper log)
    {
        _log = log;
    }

    public void LogMessage(string message, LogLevel level = LogLevel.Normal)
    {
        _log.LogMessage(MapToMessageImportance(level), message);
    }

    public void LogWarning(string message)
    {
        _log.LogWarning(message);
    }

    public void LogError(string message)
    {
        _log.LogError(message);
    }

    private static MessageImportance MapToMessageImportance(LogLevel level)
    {
        return level switch
        {
            LogLevel.Low => MessageImportance.Low,
            LogLevel.Normal => MessageImportance.Normal,
            LogLevel.High => MessageImportance.High,
            _ => MessageImportance.Normal
        };
    }
}
