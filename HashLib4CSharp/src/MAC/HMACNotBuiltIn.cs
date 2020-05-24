using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.MAC
{
    internal sealed class HMACNotBuiltIn : Hash, IHMACNotBuiltIn, ICryptoNotBuiltIn
    {
        private readonly IHash _hash;
        private byte[] _opad, _ipad, _key, _workingKey;

        private HMACNotBuiltIn(IHash underlyingHash)
            : base(underlyingHash.HashSize, underlyingHash.BlockSize)
        {
            _hash = underlyingHash;
        }

        private HMACNotBuiltIn(IHash underlyingHash, byte[] hmacKey)
            : base(underlyingHash.HashSize, underlyingHash.BlockSize)
        {
            _hash = underlyingHash.Clone();
            Key = hmacKey;
            _ipad = new byte[_hash.BlockSize];
            _opad = new byte[_hash.BlockSize];
        }

        public override string Name => $"HMACNotBuiltIn({_hash.Name})";

        public byte[] Key
        {
            get => ArrayUtils.Clone(_key);
            set
            {
                if (value == null) throw new ArgumentNullHashLibException(nameof(value));
                _key = ArrayUtils.Clone(value);
                TransformKey();
            }
        }

        public byte[] WorkingKey
        {
            get => ArrayUtils.Clone(_workingKey);
            private set => _workingKey = value != null
                ? ArrayUtils.Clone(value)
                : throw new ArgumentNullHashLibException(nameof(value));
        }

        public void Clear()
        {
            ArrayUtils.ZeroFill(_key);
            ArrayUtils.ZeroFill(_workingKey);
        }

        public override IHash Clone() =>
            new HMACNotBuiltIn(_hash.Clone())
            {
                _opad = ArrayUtils.Clone(_opad),
                _ipad = ArrayUtils.Clone(_ipad),
                _key = ArrayUtils.Clone(_key),
                _workingKey = ArrayUtils.Clone(_workingKey),
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            _hash.Initialize();
            UpdatePads();
            _hash.TransformBytes(_ipad);
        }

        public override IHashResult TransformFinal()
        {
            var result = _hash.TransformFinal();
            _hash.TransformBytes(_opad);
            _hash.TransformBytes(result.GetBytes());
            result = _hash.TransformFinal();
            Initialize();
            return result;
        }

        public override void TransformBytes(byte[] data, int index, int length)
        {
            if (data == null) throw new ArgumentNullHashLibException(nameof(data));
            Debug.Assert(index >= 0);
            Debug.Assert(length >= 0);
            Debug.Assert(index + length <= data.Length);
            _hash.TransformBytes(data, index, length);
        }

        public override string ToString() => Name;

        ~HMACNotBuiltIn()
        {
            Clear();
        }

        public static IHMACNotBuiltIn CreateHMAC(IHash hash, byte[] hmacKey)
        {
            return hmacKey == null ? throw new ArgumentNullHashLibException(nameof(hmacKey)) :
                hash == null ? throw new ArgumentNullHashLibException(nameof(hash)) :
                hash is IHMACNotBuiltIn hmacNotBuiltIn ? (IHMACNotBuiltIn) hmacNotBuiltIn.Clone() :
                new HMACNotBuiltIn(hash, hmacKey);
        }

        private void UpdatePads()
        {
            var blockSize = _hash.BlockSize;

            ArrayUtils.Fill<byte>(_ipad, 0, blockSize, 0x36);
            ArrayUtils.Fill<byte>(_opad, 0, blockSize, 0x5C);

            var idx = 0;
            var length = _workingKey.Length;
            while (idx < length && idx < _hash.BlockSize)
            {
                _ipad[idx] = (byte) (_ipad[idx] ^ _workingKey[idx]);
                _opad[idx] = (byte) (_opad[idx] ^ _workingKey[idx]);
                idx++;
            }
        }

        /// <summary>
        /// Computes the actual key used for hashing. This will not be the same as the
        /// original key passed to TransformKey() if the original key exceeds the <br />
        /// hash algorithm's block size. (See RFC 2104, section 2)
        /// </summary>
        private void TransformKey()
        {
            var blockSize = _hash.BlockSize;
            // Perform RFC 2104, section 2 key adjustment.
            WorkingKey = _key.Length > blockSize ? _hash.ComputeBytes(_key).GetBytes() : _key;
        }
    }
}