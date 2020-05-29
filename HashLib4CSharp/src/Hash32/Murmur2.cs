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

namespace HashLib4CSharp.Hash32
{
    // The original MurmurHash2 32-bit algorithm by Austin Appleby.
    internal sealed class Murmur2 : MultipleTransformNonBlock, IHash32, IHashWithKey, ITransformBlock
    {
        private uint _key;

        private const uint CKey = 0x0;
        private const uint M = 0x5BD1E995;
        private const int R = 24;

        private const string InvalidKeyLength = "KeyLength Must Be Equal to {0}";

        internal Murmur2()
            : base(4, 4)
        {
            _key = CKey;
        }

        public override IHash Clone()
        {
            var hashInstance = base.Clone();
            ((Murmur2) hashInstance)._key = _key;
            return hashInstance;
        }

        protected override IHashResult ComputeAggregatedBytes(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            return new HashResult(InternalComputeBytes(data));
        }

        private unsafe int InternalComputeBytes(byte[] data)
        {
            var length = data.Length;

            if (length == 0)
                return 0;

            var h = _key ^ (uint) length;
            var currentIndex = 0;
            var idx = 0;
            var nBlocks = length >> 2;
            fixed (byte* dataPtr = data)
            {
                var dataPtr2 = (uint*) dataPtr;
                while (idx < nBlocks)
                {
                    var block = Converters.ReadPCardinalAsUInt32LE(dataPtr2 + idx);
                    block *= M;
                    block ^= block >> R;
                    block *= M;

                    h *= M;
                    h ^= block;

                    idx++;
                    currentIndex += 4;
                    length -= 4;
                }
            }

            switch (length)
            {
                case 3:
                    h ^= (uint) (data[currentIndex + 2] << 16);
                    h ^= (uint) (data[currentIndex + 1] << 8);
                    h ^= data[currentIndex];
                    h *= M;
                    break;

                case 2:
                    h ^= (uint) (data[currentIndex + 1] << 8);
                    h ^= data[currentIndex];
                    h *= M;
                    break;

                case 1:
                    h ^= data[currentIndex];
                    h *= M;
                    break;
            }

            h ^= h >> 13;

            h *= M;
            h ^= h >> 15;

            return (int) h;
        }

        public int KeyLength => 4;

        public unsafe byte[] Key
        {
            get => Converters.ReadUInt32AsBytesLE(_key);
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
                        _key = Converters.ReadBytesAsUInt32LE(valuePtr, 0);
                    }
                }
            }
        }
    }
}