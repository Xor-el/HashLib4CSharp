
namespace HashLib4CSharp.Interfaces
{
    public interface ICRC : IChecksum
    {
        string[] Names { get; }
        int Width { get; }
        ulong Polynomial { get; }
        ulong InitialValue { get; }
        bool IsInputReflected { get; }
        bool IsOutputReflected { get; }
        ulong OutputXor { get; }
        ulong CheckValue { get; }
    }
}