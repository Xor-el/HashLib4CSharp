using System.Diagnostics;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash32
{
    internal sealed class FNV1a : FNV
    {
        public override IHash Clone() => new FNV1a {Hash = Hash, BufferSize = BufferSize};
        public override void Initialize() => Hash = 2166136261;

        public override void TransformBytes(byte[] data, int index, int length)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            Debug.Assert(index >= 0);
            Debug.Assert(length >= 0);
            Debug.Assert(index + length <= data.Length);
            var i = index;
            var hash = Hash;
            while (length > 0)
            {
                hash = (hash ^ data[i]) * 16777619;
                i++;
                length--;
            }

            Hash = hash;
        }
    }
}