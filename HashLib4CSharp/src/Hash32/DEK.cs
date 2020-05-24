using System.Linq;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash32
{
    internal sealed class DEK : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        internal DEK()
            : base(4, 1)
        {
        }

        protected override IHashResult ComputeAggregatedBytes(byte[] data)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));

            if (data.Length <= 0) return new HashResult((uint) 0);
            var hash = (uint) data.Length;

            hash = data.Aggregate(hash, (current, b) => Bits.RotateLeft32(current, 5) ^ b);

            return new HashResult(hash);
        }
    }
}