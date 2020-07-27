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

namespace HashLib4CSharp.Crypto
{
    internal sealed class HAS160 : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        private static readonly int[] Rot = { 5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13 };

        private static readonly int[] Tor =
            {27, 21, 25, 17, 26, 19, 24, 18, 25, 20, 23, 21, 24, 17, 26, 20, 23, 18, 27, 19};

        private static readonly int[] Index =
        {
            18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8,
            9, 10, 11, 17, 12, 13, 14, 15, 18, 3, 6, 9, 12, 19, 15, 2, 5, 8, 16, 11,
            14, 1, 4, 17, 7, 10, 13, 0, 18, 12, 5, 14, 7, 19, 0, 9, 2, 11, 16, 4, 13,
            6, 15, 17, 8, 1, 10, 3, 18, 7, 2, 13, 8, 19, 3, 14, 9, 4, 16, 15, 10, 5,
            0, 17, 11, 6, 1, 12
        };

        private uint[] _state;

        internal HAS160()
            : base(20, 64)
        {
            _state = new uint[5];
        }

        public override IHash Clone() =>
            new HAS160
            {
                _state = ArrayUtils.Clone(_state),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            _state[0] = 0x67452301;
            _state[1] = 0xEFCDAB89;
            _state[2] = 0x98BADCFE;
            _state[3] = 0x10325476;
            _state[4] = 0xC3D2E1F0;

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (uint* statePtr = _state)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le32_copy(statePtr, 0, resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        }

        protected override void Finish()
        {
            var bits = ProcessedBytesCount * 8;

            var padIndex = Buffer.Position < 56 ? 56 - Buffer.Position : 120 - Buffer.Position;

            Span<byte> pad = stackalloc byte[padIndex + 8];

            pad[0] = 0x80;

            bits = Converters.le2me_64(bits);

            Converters.ReadUInt64AsBytesLE(bits, pad.Slice(padIndex));

            padIndex += 8;

            TransformByteSpan(pad.Slice(0, padIndex));
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            uint T;
            var buffer = stackalloc uint[20];

            var a = _state[0];
            var b = _state[1];
            var c = _state[2];
            var d = _state[3];
            var e = _state[4];

            Converters.le32_copy(data, index, buffer, 0, dataLength);

            buffer[16] = buffer[0] ^ buffer[1] ^ buffer[2] ^ buffer[3];
            buffer[17] = buffer[4] ^ buffer[5] ^ buffer[6] ^ buffer[7];
            buffer[18] = buffer[8] ^ buffer[9] ^ buffer[10] ^ buffer[11];
            buffer[19] = buffer[12] ^ buffer[13] ^ buffer[14] ^ buffer[15];

            uint r = 0;
            while (r < 20)
            {
                T = buffer[Index[r]] + ((a << Rot[r]) | (a >> Tor[r])) + ((b & c) | (~b & d)) + e;
                e = d;
                d = c;
                c = (b << 10) | (b >> 22);
                b = a;
                a = T;
                r += 1;
            }

            buffer[16] = buffer[3] ^ buffer[6] ^ buffer[9] ^ buffer[12];
            buffer[17] = buffer[2] ^ buffer[5] ^ buffer[8] ^ buffer[15];
            buffer[18] = buffer[1] ^ buffer[4] ^ buffer[11] ^ buffer[14];
            buffer[19] = buffer[0] ^ buffer[7] ^ buffer[10] ^ buffer[13];

            r = 20;
            while (r < 40)
            {
                T = buffer[Index[r]] + 0x5A827999 + ((a << Rot[r - 20]) | (a >> Tor[r - 20])) + (b ^ c ^ d) + e;
                e = d;
                d = c;
                c = (b << 17) | (b >> 15);
                b = a;
                a = T;
                r += 1;
            }

            buffer[16] = buffer[5] ^ buffer[7] ^ buffer[12] ^ buffer[14];
            buffer[17] = buffer[0] ^ buffer[2] ^ buffer[9] ^ buffer[11];
            buffer[18] = buffer[4] ^ buffer[6] ^ buffer[13] ^ buffer[15];
            buffer[19] = buffer[1] ^ buffer[3] ^ buffer[8] ^ buffer[10];

            r = 40;
            while (r < 60)
            {
                T = buffer[Index[r]] + 0x6ED9EBA1 + ((a << Rot[r - 40]) | (a >> Tor[r - 40])) + (c ^ (b | ~d)) + e;
                e = d;
                d = c;
                c = (b << 25) | (b >> 7);
                b = a;
                a = T;
                r += 1;
            }

            buffer[16] = buffer[2] ^ buffer[7] ^ buffer[8] ^ buffer[13];
            buffer[17] = buffer[3] ^ buffer[4] ^ buffer[9] ^ buffer[14];
            buffer[18] = buffer[0] ^ buffer[5] ^ buffer[10] ^ buffer[15];
            buffer[19] = buffer[1] ^ buffer[6] ^ buffer[11] ^ buffer[12];

            r = 60;
            while (r < 80)
            {
                T = buffer[Index[r]] + 0x8F1BBCDC + ((a << Rot[r - 60]) | (a >> Tor[r - 60])) + (b ^ c ^ d) + e;
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = T;
                r += 1;
            }

            _state[0] = _state[0] + a;
            _state[1] = _state[1] + b;
            _state[2] = _state[2] + c;
            _state[3] = _state[3] + d;
            _state[4] = _state[4] + e;
        }
    }
}