using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash64
{
    internal class FNV64 : Hash, IHash64, ITransformBlock
    {
        protected ulong Hash;

        internal FNV64()
            : base(8, 1)
        {
        }

        public override IHash Clone() => new FNV64 {Hash = Hash, BufferSize = BufferSize};

        public override void Initialize() => Hash = 0;

        public override IHashResult TransformFinal()
        {
            var result = new HashResult(Hash);
            Initialize();
            return result;
        }

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
                hash = (hash * 1099511628211) ^ data[i];
                i++;
                length--;
            }

            Hash = hash;
        }
    }
}