using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash32
{
    internal class FNV : Hash, IHash32, ITransformBlock
    {
        protected uint Hash;

        internal FNV()
            : base(4, 1)
        {
        }

        public override IHash Clone() => new FNV {Hash = Hash, BufferSize = BufferSize};

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
                hash = (hash * 16777619) ^ data[i];
                i++;
                length--;
            }

            Hash = hash;
        }
    }
}