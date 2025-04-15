using System.Collections.Generic;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

namespace Libman.Audit;

public class TaskItemConverter : ITaskItemConverter
{
    public ITaskItem[] ConvertToTaskItems(List<VulnerablePackage> vulnerablePackages)
    {
        List<TaskItem> taskItems = new List<TaskItem>();

        foreach (VulnerablePackage package in vulnerablePackages)
        {
            TaskItem taskItem = new TaskItem(package.Name);
            taskItem.SetMetadata("Version", package.Version);
            taskItem.SetMetadata("Provider", package.Provider);
            taskItem.SetMetadata("VulnerabilityCount", package.VulnerabilityCount.ToString());
            taskItem.SetMetadata("Description", package.Description);
            taskItem.SetMetadata("Severity", package.Severity);
            taskItems.Add(taskItem);
        }

        return taskItems.ToArray();
    }
}
