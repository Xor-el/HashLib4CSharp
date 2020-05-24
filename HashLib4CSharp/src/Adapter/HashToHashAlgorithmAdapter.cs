using System.Diagnostics;
using System.Security.Cryptography;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Adapter
{
    internal sealed class HashToHashAlgorithmAdapter : HashAlgorithm
    {
        private readonly IHash _hash;

        internal HashToHashAlgorithmAdapter(IHash hash)
        {
            _hash = hash != null
                ? hash.Clone()
                : throw new ArgumentNullHashLibException(nameof(hash));
            HashSizeValue = _hash.HashSize * 8;
            Initialize();
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array == null) throw new ArgumentNullHashLibException(nameof(array));
            Debug.Assert(cbSize >= 0);
            Debug.Assert(ibStart >= 0);
            Debug.Assert(ibStart + cbSize <= array.Length);

            _hash.TransformBytes(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            var hashValue = _hash.TransformFinal().GetBytes();
            HashValue = ArrayUtils.Clone(hashValue);
            return hashValue;
        }

        public override void Initialize()
        {
            _hash.Initialize();
        }

        public override string ToString() => $"{GetType().Name}({_hash.Name})";
    }
}