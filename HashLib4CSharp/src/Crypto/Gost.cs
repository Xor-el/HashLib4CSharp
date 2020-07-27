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
    internal sealed class Gost : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        private static readonly uint[] Sbox1 = new uint[256];
        private static readonly uint[] Sbox2 = new uint[256];
        private static readonly uint[] Sbox3 = new uint[256];
        private static readonly uint[] Sbox4 = new uint[256];
        private uint[] _state, _hash;

        static Gost()
        {
            var sbox = new[]
            {
                new uint[] {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
                new uint[] {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
                new uint[] {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
                new uint[] {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
                new uint[] {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
                new uint[] {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
                new uint[] {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
                new uint[] {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
            };

            var i = 0;
            for (var a = 0; a < 16; a++)
            {
                var ax = sbox[1][a] << 15;
                var bx = sbox[3][a] << 23;
                var cx = sbox[5][a];
                cx = Bits.RotateRight32(cx, 1);
                var dx = sbox[7][a] << 7;

                for (var b = 0; b < 16; b++)
                {
                    Sbox1[i] = ax | (sbox[0][b] << 11);
                    Sbox2[i] = bx | (sbox[2][b] << 19);
                    Sbox3[i] = cx | (sbox[4][b] << 27);
                    Sbox4[i] = dx | (sbox[6][b] << 3);
                    i++;
                }
            }
        }

        internal Gost()
            : base(32, 32)
        {
            _state = new uint[8];
            _hash = new uint[8];
        }

        public override IHash Clone() =>
            new Gost
            {
                _state = ArrayUtils.Clone(_state),
                _hash = ArrayUtils.Clone(_hash),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            ArrayUtils.ZeroFill(_state);
            ArrayUtils.ZeroFill(_hash);

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (uint* hashPtr = _hash)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.le32_copy(hashPtr, 0, resultPtr, 0,
                        result.Length);
                }
            }

            return result;
        }

        protected override unsafe void Finish()
        {
            var bits = ProcessedBytesCount * 8;

            if (Buffer.Position > 0)
            {
                Span<byte> pad = stackalloc byte[32 - Buffer.Position];
                TransformByteSpan(pad.Slice(0, 32 - Buffer.Position));
            }

            var length = stackalloc uint[8];
            length[0] = (uint)bits;
            length[1] = (uint)(bits >> 32);
            length[2] = 0;
            length[3] = 0;
            length[4] = 0;
            length[5] = 0;
            length[6] = 0;
            length[7] = 0;

            Compress(length);
            fixed (uint* ptrState = _state)
            {
                Compress(ptrState);
            }
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var m = stackalloc uint[8];
            var buffer = stackalloc uint[8];

            uint c = 0;
            Converters.le32_copy(data, index, buffer, 0, dataLength);

            for (var i = 0; i < 8; i++)
            {
                var a = buffer[i];
                m[i] = a;
                var b = _state[i];
                c = a + c + _state[i];
                _state[i] = c;

                c = c < a || c < b ? 1 : (uint)0;
            }

            Compress(m);
        }

        private unsafe void Compress(uint* m)
        {
            var s = stackalloc uint[8];

            var u0 = _hash[0];
            var u1 = _hash[1];
            var u2 = _hash[2];
            var u3 = _hash[3];
            var u4 = _hash[4];
            var u5 = _hash[5];
            var u6 = _hash[6];
            var u7 = _hash[7];

            var v0 = m[0];
            var v1 = m[1];
            var v2 = m[2];
            var v3 = m[3];
            var v4 = m[4];
            var v5 = m[5];
            var v6 = m[6];
            var v7 = m[7];

            var i = 0;
            while (i < 8)
            {
                var w0 = u0 ^ v0;
                var w1 = u1 ^ v1;
                var w2 = u2 ^ v2;
                var w3 = u3 ^ v3;
                var w4 = u4 ^ v4;
                var w5 = u5 ^ v5;
                var w6 = u6 ^ v6;
                var w7 = u7 ^ v7;

                var key0 = (byte)w0 | ((uint)(byte)w2 << 8) |
                           ((uint)(byte)w4 << 16) | ((uint)(byte)w6 << 24);
                var key1 = (byte)(w0 >> 8) | (w2 & 0x0000FF00) |
                           ((w4 & 0x0000FF00) << 8) | ((w6 & 0x0000FF00) << 16);
                var key2 = (byte)(w0 >> 16) | ((w2 & 0x00FF0000) >> 8) |
                           (w4 & 0x00FF0000) | ((w6 & 0x00FF0000) << 8);
                var key3 = (w0 >> 24) | ((w2 & 0xFF000000) >> 16) |
                           ((w4 & 0xFF000000) >> 8) | (w6 & 0xFF000000);
                var key4 = (byte)w1 | ((w3 & 0x000000FF) << 8) |
                           ((w5 & 0x000000FF) << 16) | ((w7 & 0x000000FF) << 24);
                var key5 = (byte)(w1 >> 8) | (w3 & 0x0000FF00) |
                           ((w5 & 0x0000FF00) << 8) | ((w7 & 0x0000FF00) << 16);
                var key6 = (byte)(w1 >> 16) | ((w3 & 0x00FF0000) >> 8) |
                           (w5 & 0x00FF0000) | ((w7 & 0x00FF0000) << 8);
                var key7 = (w1 >> 24) | ((w3 & 0xFF000000) >> 16) |
                           ((w5 & 0xFF000000) >> 8) | (w7 & 0xFF000000);

                var r = _hash[i];
                var l = _hash[i + 1];

                var t = key0 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key1 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key2 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key3 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key4 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key5 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key6 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key7 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key0 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key1 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key2 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key3 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key4 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key5 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key6 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key7 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key0 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key1 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key2 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key3 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key4 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key5 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key6 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key7 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key7 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key6 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key5 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key4 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key3 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key2 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key1 + r;
                l = l ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];
                t = key0 + l;
                r = r ^ Sbox1[(byte)t] ^ Sbox2[(byte)(t >> 8)] ^ Sbox3
                    [(byte)(t >> 16)] ^ Sbox4[t >> 24];

                t = r;
                r = l;
                l = t;

                s[i] = r;
                s[i + 1] = l;

                if (i == 6)
                    break;

                l = u0 ^ u2;
                r = u1 ^ u3;
                u0 = u2;
                u1 = u3;
                u2 = u4;
                u3 = u5;
                u4 = u6;
                u5 = u7;
                u6 = l;
                u7 = r;

                if (i == 2)
                {
                    u0 ^= 0xFF00FF00;
                    u1 ^= 0xFF00FF00;
                    u2 ^= 0x00FF00FF;
                    u3 ^= 0x00FF00FF;
                    u4 ^= 0x00FFFF00;
                    u5 ^= 0xFF0000FF;
                    u6 ^= 0x000000FF;
                    u7 ^= 0xFF00FFFF;
                }

                l = v0;
                r = v2;
                v0 = v4;
                v2 = v6;
                v4 = l ^ r;
                v6 = v0 ^ r;
                l = v1;
                r = v3;
                v1 = v5;
                v3 = v7;
                v5 = l ^ r;
                v7 = v1 ^ r;

                i += 2;
            }

            u0 = m[0] ^ s[6];
            u1 = m[1] ^ s[7];
            u2 = m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF)
                 ^ (s[1] & 0xFFFF) ^ (s[1] >> 16) ^ (s[2] << 16)
                 ^ s[6] ^ (s[6] << 16) ^ (s[7] & 0xFFFF0000) ^ (s[7] >> 16);
            u3 = m[3] ^ (s[0] & 0xFFFF) ^ (s[0] << 16) ^ (s[1] & 0xFFFF)
                 ^ (s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16)
                 ^ (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16)
                 ^ (s[7] & 0xFFFF) ^ (s[7] << 16) ^ (s[7] >> 16);
            u4 = m[4] ^ (s[0] & 0xFFFF0000) ^ (s[0] << 16) ^ (s[0] >> 16)
                 ^ (s[1] & 0xFFFF0000) ^ (s[1] >> 16) ^ (s[2] << 16)
                 ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16)
                 ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xFFFF) ^ (s[7] << 16)
                 ^ (s[7] >> 16);
            u5 = m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF0000)
                 ^ (s[1] & 0xFFFF) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16)
                 ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16)
                 ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xFFFF0000)
                 ^ (s[7] << 16) ^ (s[7] >> 16);
            u6 = m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16)
                 ^ s[3] ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16)
                 ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ (s[6] << 16)
                 ^ (s[6] >> 16) ^ (s[7] << 16);
            u7 = m[7] ^ (s[0] & 0xFFFF0000) ^ (s[0] << 16) ^ (s[1] & 0xFFFF)
                 ^ (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16)
                 ^ s[4] ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16)
                 ^ (s[6] >> 16) ^ (s[7] & 0xFFFF) ^ (s[7] << 16) ^ (s[7] >> 16);

            v0 = _hash[0] ^ (u1 << 16) ^ (u0 >> 16);
            v1 = _hash[1] ^ (u2 << 16) ^ (u1 >> 16);
            v2 = _hash[2] ^ (u3 << 16) ^ (u2 >> 16);
            v3 = _hash[3] ^ (u4 << 16) ^ (u3 >> 16);
            v4 = _hash[4] ^ (u5 << 16) ^ (u4 >> 16);
            v5 = _hash[5] ^ (u6 << 16) ^ (u5 >> 16);
            v6 = _hash[6] ^ (u7 << 16) ^ (u6 >> 16);
            v7 = _hash[7] ^ (u0 & 0xFFFF0000) ^ (u0 << 16) ^ (u7 >> 16)
                 ^ (u1 & 0xFFFF0000) ^ (u1 << 16) ^ (u6 << 16)
                 ^ (u7 & 0xFFFF0000);

            _hash[0] = (v0 & 0xFFFF0000) ^ (v0 << 16) ^ (v0 >> 16)
                       ^ (v1 >> 16) ^ (v1 & 0xFFFF0000) ^ (v2 << 16) ^ (v3 >> 16)
                       ^ (v4 << 16) ^ (v5 >> 16) ^ v5 ^ (v6 >> 16) ^ (v7 << 16)
                       ^ (v7 >> 16) ^ (v7 & 0xFFFF);
            _hash[1] = (v0 << 16) ^ (v0 >> 16) ^ (v0 & 0xFFFF0000)
                       ^ (v1 & 0xFFFF) ^ v2 ^ (v2 >> 16) ^ (v3 << 16) ^ (v4 >> 16)
                       ^ (v5 << 16) ^ (v6 << 16) ^ v6 ^ (v7 & 0xFFFF0000)
                       ^ (v7 >> 16);
            _hash[2] = (v0 & 0xFFFF) ^ (v0 << 16) ^ (v1 << 16) ^ (v1 >> 16)
                       ^ (v1 & 0xFFFF0000) ^ (v2 << 16) ^ (v3 >> 16)
                       ^ v3 ^ (v4 << 16) ^ (v5 >> 16) ^ v6 ^ (v6 >> 16)
                       ^ (v7 & 0xFFFF) ^ (v7 << 16) ^ (v7 >> 16);
            _hash[3] = (v0 << 16) ^ (v0 >> 16) ^ (v0 & 0xFFFF0000)
                       ^ (v1 & 0xFFFF0000) ^ (v1 >> 16) ^ (v2 << 16) ^ (v2 >> 16)
                       ^ v2 ^ (v3 << 16) ^ (v4 >> 16) ^ v4 ^ (v5 << 16)
                       ^ (v6 << 16) ^ (v7 & 0xFFFF) ^ (v7 >> 16);
            _hash[4] = (v0 >> 16) ^ (v1 << 16) ^ v1 ^ (v2 >> 16)
                       ^ v2 ^ (v3 << 16) ^ (v3 >> 16) ^ v3 ^ (v4 << 16)
                       ^ (v5 >> 16) ^ v5 ^ (v6 << 16) ^ (v6 >> 16) ^ (v7 << 16);
            _hash[5] = (v0 << 16) ^ (v0 & 0xFFFF0000) ^ (v1 << 16)
                       ^ (v1 >> 16) ^ (v1 & 0xFFFF0000) ^ (v2 << 16)
                       ^ v2 ^ (v3 >> 16) ^ v3 ^ (v4 << 16) ^ (v4 >> 16)
                       ^ v4 ^ (v5 << 16) ^ (v6 << 16) ^ (v6 >> 16)
                       ^ v6 ^ (v7 << 16) ^ (v7 >> 16) ^ (v7 & 0xFFFF0000);
            _hash[6] = v0 ^ v2 ^ (v2 >> 16) ^ v3 ^ (v3 << 16)
                       ^ v4 ^ (v4 >> 16) ^ (v5 << 16) ^ (v5 >> 16)
                       ^ v5 ^ (v6 << 16) ^ (v6 >> 16) ^ v6 ^ (v7 << 16) ^ v7;
            _hash[7] = v0 ^ (v0 >> 16) ^ (v1 << 16) ^ (v1 >> 16)
                       ^ (v2 << 16) ^ (v3 >> 16) ^ v3 ^ (v4 << 16)
                       ^ v4 ^ (v5 >> 16) ^ v5 ^ (v6 << 16) ^ (v6 >> 16)
                       ^ (v7 << 16) ^ v7;
        }
    }
}