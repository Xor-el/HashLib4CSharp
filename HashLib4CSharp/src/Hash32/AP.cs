using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash32
{
    internal sealed class AP : Hash, IHash32, ITransformBlock
    {
        private uint _hash;
        private int _index;

        internal AP()
            : base(4, 1)
        {
        }

        public override IHash Clone() => new AP {_hash = _hash, _index = _index, BufferSize = BufferSize};

        public override void Initialize()
        {
            _hash = 0xAAAAAAAA;
            _index = 0;
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

            while (length > 0)
            {
                hash ^= (_index & 1) == 0
                    ? (hash << 7) ^ data[i] * (hash >> 3)
                    : ~((hash << 11) ^ data[i] ^ (hash >> 5));

                _index++;
                i++;
                length--;
            }

            _hash = hash;
        }
    }
}