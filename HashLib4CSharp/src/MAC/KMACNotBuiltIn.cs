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
using System.Diagnostics;
using HashLib4CSharp.Base;
using HashLib4CSharp.Crypto;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.MAC
{
    internal abstract class KMACNotBuiltIn : Hash, IKMACNotBuiltIn, ICryptoNotBuiltIn
    {
        private byte[] _key;
        protected IHash Hash;
        protected bool Finalized;

        protected static readonly byte[] KmacBytes = { 75, 77, 65, 67 };

        protected KMACNotBuiltIn(int hashSize)
            : base(hashSize, 200 - hashSize * 2)
        {
        }

        ~KMACNotBuiltIn()
        {
            Clear();
        }

        public override void Initialize()
        {
            Finalized = false;
            Hash.Initialize();
            TransformByteSpan(CShake.BytePad(CShake.EncodeString(_key), BlockSize));
        }

        private byte[] GetResult()
        {
            var xofSizeInBytes = (int)(((IXOF)Hash).XofSizeInBits >> 3);

            var result = new byte[xofSizeInBytes];

            DoOutput(result.AsSpan().Slice(0, xofSizeInBytes));

            return result;
        }

        public override IHashResult TransformFinal()
        {
            var buffer = GetResult();
            Debug.Assert((ulong)buffer.Length == ((IXOF)Hash).XofSizeInBits >> 3);
            Initialize();

            return new HashResult(buffer);
        }

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            Hash.TransformByteSpan(data);
        }

        public virtual void Clear() => ArrayUtils.ZeroFill(_key);

        public virtual byte[] Key
        {
            get => ArrayUtils.Clone(_key);
            set => _key = value != null
                ? ArrayUtils.Clone(value)
                : throw new ArgumentNullException(nameof(value));
        }

        public override string Name => GetType().Name;

        public override string ToString() => Name;

        public void DoOutput(Span<byte> dest)
        {
            if (!Finalized)
            {
                TransformByteSpan(this is IXOF ? CShake.RightEncode(0) : CShake.RightEncode(((IXOF)Hash).XofSizeInBits));
                Finalized = true;
            }

            ((IXOF)Hash).DoOutput(dest);
        }

        public static IKMACNotBuiltIn CreateKMAC128(byte[] kmacKey, byte[] customization,
            ulong outputLengthInBits)
        {
            return new KMAC128(kmacKey, customization, outputLengthInBits);
        }

        public static IKMACNotBuiltIn CreateKMAC256(byte[] kmacKey, byte[] customization,
            ulong outputLengthInBits)
        {
            return new KMAC256(kmacKey, customization, outputLengthInBits);
        }
    }

    internal sealed class KMAC128 : KMACNotBuiltIn
    {
        private KMAC128(IHash hash, byte[] kmacKey,
            ulong outputLengthInBits) : base((int)Enum.HashSize.HashSize128)
        {
            Hash = hash ?? throw new ArgumentNullException(nameof(hash));
            Key = kmacKey;
            ((IXOF)Hash).XofSizeInBits = outputLengthInBits;
        }

        internal KMAC128(byte[] kmacKey, byte[] customization,
            ulong outputLengthInBits) : this(
            new CShake_128(KmacBytes ?? throw new ArgumentNullException(nameof(KmacBytes)),
                customization ?? throw new ArgumentNullException(nameof(customization))), kmacKey,
            outputLengthInBits)
        {
        }

        public override IHash Clone() =>
            new KMAC128(Hash.Clone(), Key,
                ((IXOF)Hash).XofSizeInBits)
            { BufferSize = BufferSize, Finalized = Finalized };
    }

    internal sealed class KMAC256 : KMACNotBuiltIn
    {
        private KMAC256(IHash hash, byte[] kmacKey,
            ulong outputLengthInBits) : base((int)Enum.HashSize.HashSize256)
        {
            Hash = hash ?? throw new ArgumentNullException(nameof(hash));
            Key = kmacKey;
            ((IXOF)Hash).XofSizeInBits = outputLengthInBits;
        }

        internal KMAC256(byte[] kmacKey, byte[] customization,
            ulong outputLengthInBits) : this(
            new CShake_256(KmacBytes ?? throw new ArgumentNullException(nameof(KmacBytes)),
                customization ?? throw new ArgumentNullException(nameof(customization))), kmacKey,
            outputLengthInBits)
        {
        }

        public override IHash Clone() =>
            new KMAC256(Hash.Clone(), Key,
                ((IXOF)Hash).XofSizeInBits)
            { BufferSize = BufferSize, Finalized = Finalized };
    }

    internal abstract class KMACXOF : KMACNotBuiltIn, IXOF
    {
        private const string InvalidXofSize = "XofSize in Bits must be multiples of 8 & be greater than 0";

        private void SetXofSizeInBitsInternal(ulong xofSizeInBits)
        {
            var xofSizeInBytes = xofSizeInBits >> 3;

            if ((xofSizeInBytes & 0x07) != 0 || xofSizeInBytes < 1)
                throw new ArgumentException(InvalidXofSize);

            ((IXOF)Hash).XofSizeInBits = xofSizeInBits;
        }

        protected KMACXOF(int hashSize) : base(hashSize)
        {
        }

        public ulong XofSizeInBits
        {
            get => ((IXOF)Hash).XofSizeInBits;
            set => SetXofSizeInBitsInternal(value);
        }
    }

    internal sealed class KMAC128XOF : KMACXOF
    {
        private KMAC128XOF(IHash hash, byte[] kmacKey) : base((int)Enum.HashSize.HashSize128)
        {
            Hash = hash ?? throw new ArgumentNullException(nameof(hash));
            Key = kmacKey;
        }

        internal KMAC128XOF(byte[] kmacKey, byte[] customization) : this(
            new CShake_128(KmacBytes ?? throw new ArgumentNullException(nameof(KmacBytes)),
                customization ?? throw new ArgumentNullException(nameof(customization))), kmacKey)
        {
        }

        public override IHash Clone() =>
            new KMAC128XOF(Hash.Clone(), Key)
            {
                XofSizeInBits = XofSizeInBits,
                BufferSize = BufferSize,
                Finalized = Finalized
            };
    }

    internal sealed class KMAC256XOF : KMACXOF
    {
        private KMAC256XOF(IHash hash, byte[] kmacKey) : base((int)Enum.HashSize.HashSize256)
        {
            Hash = hash ?? throw new ArgumentNullException(nameof(hash));
            Key = kmacKey;
        }

        internal KMAC256XOF(byte[] kmacKey, byte[] customization) : this(
            new CShake_256(KmacBytes ?? throw new ArgumentNullException(nameof(KmacBytes)),
                customization ?? throw new ArgumentNullException(nameof(customization))), kmacKey)
        {
        }

        public override IHash Clone() =>
            new KMAC256XOF(Hash.Clone(), Key)
            {
                XofSizeInBits = XofSizeInBits,
                BufferSize = BufferSize,
                Finalized = Finalized
            };
    }
}