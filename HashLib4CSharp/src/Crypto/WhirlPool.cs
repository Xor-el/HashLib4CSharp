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
using System.Runtime.CompilerServices;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class WhirlPool : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        private ulong[] _state;

        private const uint Rounds = 10;
        private const uint ReductionPolynomial = 0x011D;

        private static readonly ulong[] C0 = new ulong[256];
        private static readonly ulong[] C1 = new ulong[256];
        private static readonly ulong[] C2 = new ulong[256];
        private static readonly ulong[] C3 = new ulong[256];
        private static readonly ulong[] C4 = new ulong[256];
        private static readonly ulong[] C5 = new ulong[256];
        private static readonly ulong[] C6 = new ulong[256];
        private static readonly ulong[] C7 = new ulong[256];
        private static readonly ulong[] Rc = new ulong[Rounds + 1];

        private static readonly uint[] Sbox =
        {
            0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01,
            0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52, 0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C,
            0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57, 0x15, 0x77, 0x37, 0xE5, 0x9F,
            0xF0, 0x4A, 0xDA, 0x58, 0xC9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85, 0xBD, 0x5D, 0x10, 0xF4,
            0xCB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7D, 0x95, 0xD8, 0xFB, 0xEE, 0x7C,
            0x66, 0xDD, 0x17, 0x47, 0x9E, 0xCA, 0x2D, 0xBF, 0x07, 0xAD, 0x5A, 0x83, 0x33, 0x63, 0x02,
            0xAA, 0x71, 0xC8, 0x19, 0x49, 0xD9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0, 0xE9,
            0x0F, 0xD5, 0x80, 0xBE, 0xCD, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE,
            0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xC3, 0xEC, 0xDB, 0xA1, 0x8D,
            0x3D, 0x97, 0x00, 0xCF, 0x2B, 0x76, 0x82, 0xD6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3,
            0x30, 0xEF, 0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xC0, 0xDE, 0x1C, 0xFD, 0x4D, 0x92,
            0x75, 0x06, 0x8A, 0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xD4, 0xA8, 0x96, 0xF9, 0xC5, 0x25, 0x59,
            0x84, 0x72, 0x39, 0x4C, 0x5E, 0x78, 0x38, 0x8C, 0xD1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9C,
            0x1E, 0x43, 0xC7, 0xFC, 0x04, 0x51, 0x99, 0x6D, 0x0D, 0xFA, 0xDF, 0x7E, 0x24, 0x3B, 0xAB,
            0xCE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB, 0x3C, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2C, 0xD3, 0xE7,
            0x6E, 0xC4, 0x03, 0x56, 0x44, 0x7F, 0xA9, 0x2A, 0xBB, 0xC1, 0x53, 0xDC, 0x0B, 0x9D, 0x6C,
            0x31, 0x74, 0xF6, 0x46, 0xAC, 0x89, 0x14, 0xE1, 0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xD0,
            0xED, 0xCC, 0x42, 0x98, 0xA4, 0x28, 0x5C, 0xF8, 0x86
        };

        static WhirlPool()
        {
            for (uint i = 0; i < 256; i++)
            {
                var v1 = Sbox[i];
                var v2 = MaskWithReductionPolynomial(v1 << 1);
                var v4 = MaskWithReductionPolynomial(v2 << 1);
                var v5 = v4 ^ v1;
                var v8 = MaskWithReductionPolynomial(v4 << 1);
                var v9 = v8 ^ v1;

                C0[i] = PackIntoUInt64(v1, v1, v4, v1, v8, v5, v2, v9);
                C1[i] = PackIntoUInt64(v9, v1, v1, v4, v1, v8, v5, v2);
                C2[i] = PackIntoUInt64(v2, v9, v1, v1, v4, v1, v8, v5);
                C3[i] = PackIntoUInt64(v5, v2, v9, v1, v1, v4, v1, v8);
                C4[i] = PackIntoUInt64(v8, v5, v2, v9, v1, v1, v4, v1);
                C5[i] = PackIntoUInt64(v1, v8, v5, v2, v9, v1, v1, v4);
                C6[i] = PackIntoUInt64(v4, v1, v8, v5, v2, v9, v1, v1);
                C7[i] = PackIntoUInt64(v1, v4, v1, v8, v5, v2, v9, v1);
            }

            Rc[0] = 0;

            for (uint r = 1; r < Rounds + 1; r++)
            {
                var i = 8 * (r - 1);
                Rc[r] = (C0[i] & 0xFF00000000000000)
                        ^ (C1[i + 1] & 0x00FF000000000000)
                        ^ (C2[i + 2] & 0x0000FF0000000000)
                        ^ (C3[i + 3] & 0x000000FF00000000)
                        ^ (C4[i + 4] & 0x00000000FF000000)
                        ^ (C5[i + 5] & 0x0000000000FF0000)
                        ^ (C6[i + 6] & 0x000000000000FF00)
                        ^ (C7[i + 7] & 0x00000000000000FF);
            }
        }

        internal WhirlPool()
            : base(64, 64)
        {
            _state = new ulong[8];
        }

        public override IHash Clone() =>
            new WhirlPool
            {
                _state = ArrayUtils.Clone(_state),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            ArrayUtils.ZeroFill(_state);

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (ulong* statePtr = _state)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.be64_copy(statePtr, 0, resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        }

        protected override void Finish()
        {
            var bits = ProcessedBytesCount * 8;
            var padIndex = Buffer.Position > 31 ? 120 - Buffer.Position : 56 - Buffer.Position;

            Span<byte> pad = stackalloc byte[padIndex + 8];

            pad[0] = 0x80;

            bits = Converters.be2me_64(bits);

            Converters.ReadUInt64AsBytesLE(bits, pad.Slice(padIndex));

            padIndex += 8;

            TransformByteSpan(pad.Slice(0, padIndex));
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = new ulong[8];
            var k = new ulong[8];
            var m = new ulong[8];
            var temp = new ulong[8];

            fixed (ulong* bufferPtr = buffer, kPtr = k, tempPtr = temp, mPtr = m)
            {
                Converters.be64_copy(data, index, bufferPtr, 0, dataLength);

                for (var i = 0; i < 8; i++)
                {
                    k[i] = _state[i];
                    temp[i] = buffer[i] ^ k[i];
                }

                for (var round = 1; round < Rounds + 1; round++)
                {
                    for (var i = 0; i < 8; i++)
                    {
                        m[i] = 0;
                        m[i] = m[i] ^ (C0[(byte)(k[(i - 0) & 7] >> 56)]);
                        m[i] = m[i] ^ (C1[(byte)(k[(i - 1) & 7] >> 48)]);
                        m[i] = m[i] ^ (C2[(byte)(k[(i - 2) & 7] >> 40)]);
                        m[i] = m[i] ^ (C3[(byte)(k[(i - 3) & 7] >> 32)]);
                        m[i] = m[i] ^ (C4[(byte)(k[(i - 4) & 7] >> 24)]);
                        m[i] = m[i] ^ (C5[(byte)(k[(i - 5) & 7] >> 16)]);
                        m[i] = m[i] ^ (C6[(byte)(k[(i - 6) & 7] >> 8)]);
                        m[i] = m[i] ^ (C7[(byte)(k[(i - 7) & 7])]);
                    }

                    PointerUtils.MemMove(kPtr, mPtr, m.Length * sizeof(ulong));

                    k[0] = k[0] ^ Rc[round];

                    for (var i = 0; i < 8; i++)
                    {
                        m[i] = k[i];
                        m[i] = m[i] ^ (C0[(byte)(temp[(i - 0) & 7] >> 56)]);
                        m[i] = m[i] ^ (C1[(byte)(temp[(i - 1) & 7] >> 48)]);
                        m[i] = m[i] ^ (C2[(byte)(temp[(i - 2) & 7] >> 40)]);
                        m[i] = m[i] ^ (C3[(byte)(temp[(i - 3) & 7] >> 32)]);
                        m[i] = m[i] ^ (C4[(byte)(temp[(i - 4) & 7] >> 24)]);
                        m[i] = m[i] ^ (C5[(byte)(temp[(i - 5) & 7] >> 16)]);
                        m[i] = m[i] ^ (C6[(byte)(temp[(i - 6) & 7] >> 8)]);
                        m[i] = m[i] ^ (C7[(byte)(temp[(i - 7) & 7])]);
                    }

                    PointerUtils.MemMove(tempPtr, mPtr, m.Length * sizeof(ulong));
                }

                for (var i = 0; i < 8; i++)
                {
                    _state[i] = _state[i] ^ (temp[i] ^ buffer[i]);
                }
            }

            ArrayUtils.ZeroFill(buffer);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint MaskWithReductionPolynomial(uint input)
        {
            if (input < 0x100) return input;
            input ^= ReductionPolynomial;

            return input;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong PackIntoUInt64(uint b7, uint b6, uint b5, uint b4,
            uint b3, uint b2, uint b1, uint b0)
        {
            return ((ulong)b7 << 56) ^ ((ulong)b6 << 48) ^ ((ulong)b5 << 40)
                   ^ ((ulong)b4 << 32) ^ ((ulong)b3 << 24) ^ ((ulong)b2 << 16)
                   ^ ((ulong)b1 << 8) ^ b0;
        }
    }
}