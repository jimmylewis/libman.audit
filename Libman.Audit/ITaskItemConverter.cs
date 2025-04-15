using System.Collections.Generic;
using Microsoft.Build.Framework;

namespace Libman.Audit;

public interface ITaskItemConverter
{
    ITaskItem[] ConvertToTaskItems(List<VulnerablePackage> vulnerablePackages);
}
