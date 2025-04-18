namespace Libman.Audit;

public interface ILibmanJsonParser
{
    List<LibmanPackage> Parse(string jsonContent);
}
