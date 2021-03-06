/*
HashLib4CSharp Library
Copyright (c) 2020 Ugochukwu Mmaduekwe
GitHub Profile URL <https://github.com/Xor-el>

Distributed under the MIT software license, see the accompanying LICENSE file
or visit http://www.opensource.org/licenses/mit-license.php.

Acknowledgements:
This library was sponsored by Sphere 10 Software (https://www.sphere10.com)
for the purposes of supporting the XXX (https://YYY) project.
*/

using System;
using HashLib4CSharp.Base;
using HashLib4CSharp.Crypto;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Params;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.MAC
{
    internal sealed class Blake2SMACNotBuiltIn : Hash, IBlake2SMACNotBuiltIn, ICryptoNotBuiltIn
    {
        private readonly IHash _hash;
        private byte[] _key;

        private Blake2SMACNotBuiltIn(IHash hash, byte[] key) : base(hash.HashSize, hash.BlockSize)
        {
            _key = key;
            _hash = hash;
        }

        ~Blake2SMACNotBuiltIn()
        {
            Clear();
        }

        public byte[] Key
        {
            get => ArrayUtils.Clone(_key);
            set => _key = value != null
                ? ArrayUtils.Clone(value)
                : throw new ArgumentNullException(nameof(value));
        }

        public override IHash Clone() => new Blake2SMACNotBuiltIn(_hash.Clone(), Key) { BufferSize = BufferSize };

        public void Clear() => ArrayUtils.ZeroFill(_key);

        public override void Initialize()
        {
            ((Blake2S)_hash).Config.Key = _key;
            _hash.Initialize();
        }

        public override IHashResult TransformFinal() => _hash.TransformFinal();

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            _hash.TransformByteSpan(data);
        }

        public static IBlake2SMACNotBuiltIn CreateBlake2SMAC(byte[] key, byte[] salt, byte[] personalization,
            int outputLengthInBits)
        {
            var config = Blake2SConfig.CreateBlake2SConfig(outputLengthInBits >> 3);
            config.Key = key;
            config.Salt = salt;
            config.Personalization = personalization;
            return new Blake2SMACNotBuiltIn(new Blake2S(config), config.Key);
        }
    }
}