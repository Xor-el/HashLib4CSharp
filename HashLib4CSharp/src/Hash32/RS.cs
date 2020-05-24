using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash32
{
    internal sealed class RS : Hash, IHash32, ITransformBlock
    {
        private uint _a, _hash;
        private const uint B = 378551;

        internal RS()
            : base(4, 1)
        {
        }

        public override IHash Clone()
        {
            var hashInstance = new RS {_hash = _hash, _a = _a, BufferSize = BufferSize};
            return hashInstance;
        }

        public override void Initialize()
        {
            _hash = 0;
            _a = 63689;
        }

        public override IHashResult TransformFinal()
        {
            var result = new HashResult(_hash);
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
            var hash = _hash;
            var a = _a;
            while (length > 0)
            {
                hash = (hash * a) + data[i];
                a *= B;
                i++;
                length--;
            }

            _a = a;
            _hash = hash;
        }
    }
}