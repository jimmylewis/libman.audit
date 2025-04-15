using System.Collections.Generic;
using Microsoft.Build.Framework;

namespace Libman.Audit;

public interface ILibmanJsonParser
{
    List<LibmanPackage> Parse(string jsonContent);
}
