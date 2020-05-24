using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Interfaces;

namespace HashLib4CSharp.KDF
{
    internal abstract class KDFNotBuiltIn : IKDFNotBuiltIn
    {
        public abstract void Clear();

        public abstract byte[] GetBytes(int byteCount);

        public abstract Task<byte[]> GetBytesAsync(int byteCount,
            CancellationToken cancellationToken = default(CancellationToken));
        
        public abstract string Name { get; }

        public abstract override string ToString();
    }
}