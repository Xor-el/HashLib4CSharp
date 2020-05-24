
namespace HashLib4CSharp.Interfaces
{
    public interface IXOF : IHash
    {
        ulong XofSizeInBits { get; set; }

        void DoOutput(byte[] dest, ulong destOffset, ulong outputLength);
    }
}