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
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash64
{
    // MurmurHash64A (64-bit) algorithm by Austin Appleby.
    internal sealed class Murmur2_64 : MultipleTransformNonBlock, IHash64, IHashWithKey, ITransformBlock
    {
        private ulong _key;

        private const ulong CKey = 0x0;
        private const ulong M = 0xC6A4A7935BD1E995;
        private const int R = 47;

        private const string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        internal Murmur2_64()
            : base(8, 8)
        {
            _key = CKey;
        }

        public override IHash Clone()
        {
            var hashInstance = base.Clone();
            ((Murmur2_64) hashInstance)._key = _key;
            return hashInstance;
        }

        protected override IHashResult ComputeAggregatedBytes(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            return new HashResult(InternalComputeBytes(data));
        }

        private unsafe ulong InternalComputeBytes(byte[] data)
        {
            var length = data.Length;

            if (length == 0)
                return 0;

            var h = _key ^ ((ulong) length * M);
            var currentIndex = 0;
            var idx = 0;
            var nBlocks = length >> 3;
            fixed (byte* dataPtr = data)
            {
                var dataPtr2 = (ulong*) dataPtr;

                while (idx < nBlocks)
                {
                    var block = Converters.ReadPUInt64AsUInt64LE(dataPtr2 + idx);

                    block *= M;
                    block ^= block >> R;
                    block *= M;

                    h ^= block;
                    h *= M;

                    idx++;
                    currentIndex += 8;
                    length -= 8;
                }

                switch (length)
                {
                    case 7:
                        h ^= (ulong) data[currentIndex + 6] << 48;

                        h ^= (ulong) data[currentIndex + 5] << 40;

                        h ^= (ulong) data[currentIndex + 4] << 32;

                        h ^= (ulong) data[currentIndex + 3] << 24;

                        h ^= (ulong) data[currentIndex + 2] << 16;

                        h ^= (ulong) data[currentIndex + 1] << 8;

                        h ^= data[currentIndex];

                        h *= M;
                        break;

                    case 6:
                        h ^= (ulong) data[currentIndex + 5] << 40;

                        h ^= (ulong) data[currentIndex + 4] << 32;

                        h ^= (ulong) data[currentIndex + 3] << 24;

                        h ^= (ulong) data[currentIndex + 2] << 16;

                        h ^= (ulong) data[currentIndex + 1] << 8;

                        h ^= data[currentIndex];

                        h *= M;
                        break;

                    case 5:
                        h ^= (ulong) data[currentIndex + 4] << 32;

                        h ^= (ulong) data[currentIndex + 3] << 24;

                        h ^= (ulong) data[currentIndex + 2] << 16;

                        h ^= (ulong) data[currentIndex + 1] << 8;

                        h ^= data[currentIndex];

                        h *= M;
                        break;

                    case 4:
                        h ^= (ulong) data[currentIndex + 3] << 24;

                        h ^= (ulong) data[currentIndex + 2] << 16;

                        h ^= (ulong) data[currentIndex + 1] << 8;

                        h ^= data[currentIndex];

                        h *= M;
                        break;

                    case 3:
                        h ^= (ulong) data[currentIndex + 2] << 16;

                        h ^= (ulong) data[currentIndex + 1] << 8;

                        h ^= data[currentIndex];

                        h *= M;
                        break;

                    case 2:
                        h ^= (ulong) data[currentIndex + 1] << 8;

                        h ^= data[currentIndex];

                        h *= M;
                        break;

                    case 1:
                        h ^= data[currentIndex];

                        h *= M;
                        break;
                }

                h ^= h >> R;
                h *= M;
                h ^= h >> R;
            }

            return h;
        }

        public int KeyLength => 8;

        public unsafe byte[] Key
        {
            get => Converters.ReadUInt64AsBytesLE(_key);

            set
            {
                if (value == null) throw new ArgumentNullException(nameof(value));
                if (value.Length == 0)
                    _key = CKey;
                else
                {
                    if (value.Length != KeyLength)
                        throw new ArgumentException(string.Format(InvalidKeyLength, KeyLength));

                    fixed (byte* valuePtr = value)
                    {
                        _key = Converters.ReadBytesAsUInt64LE(valuePtr, 0);
                    }
                }
            }
        }
    }
}