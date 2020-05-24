using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash32
{
    internal sealed class OneAtTime : Hash, IHash32, ITransformBlock
    {
        private uint _hash;

        internal OneAtTime()
            : base(4, 1)
        {
        }

        public override IHash Clone() => new OneAtTime {_hash = _hash, BufferSize = BufferSize};

        public override void Initialize() => _hash = 0;

        public override IHashResult TransformFinal()
        {
            _hash += _hash << 3;
            _hash ^= _hash >> 11;
            _hash += _hash << 15;
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
                hash += data[i];
                hash += hash << 10;
                hash ^= hash >> 6;
                i++;
                length--;
            }

            _hash = hash;
        }
    }
}