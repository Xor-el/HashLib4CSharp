using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Crypto;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Params;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.MAC
{
    internal sealed class Blake2BMACNotBuiltIn : Hash, IBlake2BMACNotBuiltIn, ICryptoNotBuiltIn
    {
        private readonly IHash _hash;
        private byte[] _key;

        private Blake2BMACNotBuiltIn(IHash hash, byte[] key) : base(hash.HashSize, hash.BlockSize)
        {
            _key = key;
            _hash = hash;
        }

        ~Blake2BMACNotBuiltIn()
        {
            Clear();
        }

        public byte[] Key
        {
            get => _key;
            set => _key = value != null
                ? ArrayUtils.Clone(value)
                : throw new ArgumentNullHashLibException(nameof(value));
        }

        public override IHash Clone() => new Blake2BMACNotBuiltIn(_hash.Clone(), Key) {BufferSize = BufferSize};

        public void Clear() => ArrayUtils.ZeroFill(_key);

        public override void Initialize() => _hash.Initialize();

        public override IHashResult TransformFinal() => _hash.TransformFinal();

        public override void TransformBytes(byte[] data, int index, int length)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            Debug.Assert(index >= 0);
            Debug.Assert(length >= 0);
            Debug.Assert(index + length <= data.Length);
            _hash.TransformBytes(data, index, length);
        }

        public static IBlake2BMACNotBuiltIn CreateBlake2BMAC(byte[] key, byte[] salt, byte[] personalization,
            int outputLengthInBits)
        {
            var config = Blake2BConfig.CreateBlake2BConfig(outputLengthInBits >> 3);
            config.Key = key;
            config.Salt = salt;
            config.Personalization = personalization;
            return new Blake2BMACNotBuiltIn(new Blake2B(config), config.Key);
        }
    }
}