using System.Diagnostics;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash32
{
    internal sealed class Bernstein1 : Bernstein
    {
        public override IHash Clone() => new Bernstein1 {Hash = Hash, BufferSize = BufferSize};

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
                hash = (hash * 33) ^ data[i];
                i++;
                length--;
            }

            Hash = hash;
        }
    }
}