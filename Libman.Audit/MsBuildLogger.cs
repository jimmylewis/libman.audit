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

    public void LogMessage(string message, MessageImportance importance = MessageImportance.Normal)
    {
        _log.LogMessage(importance, message);
    }

    public void LogWarning(string message)
    {
        _log.LogWarning(message);
    }

    public void LogError(string message)
    {
        _log.LogError(message);
    }
}
