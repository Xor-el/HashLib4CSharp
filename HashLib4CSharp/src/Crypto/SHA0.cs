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
    internal class SHA0 : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        private const uint C1 = 0x5A827999;
        private const uint C2 = 0x6ED9EBA1;
        private const uint C3 = 0x8F1BBCDC;
        private const uint C4 = 0xCA62C1D6;
        protected uint[] State;

        internal SHA0()
            : base(20, 64)
        {
            State = new uint[5];
        }

        public override IHash Clone() =>
            new SHA0
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            State[0] = 0x67452301;
            State[1] = 0xEFCDAB89;
            State[2] = 0x98BADCFE;
            State[3] = 0x10325476;
            State[4] = 0xC3D2E1F0;

            base.Initialize();
        }

        protected virtual unsafe void Expand(uint* data)
        {
            data[16] = data[16 - 3] ^ data[16 - 8] ^ data[16 - 14] ^ data[0];
            data[17] = data[17 - 3] ^ data[17 - 8] ^ data[17 - 14] ^ data[17 - 16];
            data[18] = data[18 - 3] ^ data[18 - 8] ^ data[18 - 14] ^ data[18 - 16];
            data[19] = data[19 - 3] ^ data[19 - 8] ^ data[19 - 14] ^ data[19 - 16];
            data[20] = data[20 - 3] ^ data[20 - 8] ^ data[20 - 14] ^ data[20 - 16];
            data[21] = data[21 - 3] ^ data[21 - 8] ^ data[21 - 14] ^ data[21 - 16];
            data[22] = data[22 - 3] ^ data[22 - 8] ^ data[22 - 14] ^ data[22 - 16];
            data[23] = data[23 - 3] ^ data[23 - 8] ^ data[23 - 14] ^ data[23 - 16];
            data[24] = data[24 - 3] ^ data[24 - 8] ^ data[24 - 14] ^ data[24 - 16];
            data[25] = data[25 - 3] ^ data[25 - 8] ^ data[25 - 14] ^ data[25 - 16];
            data[26] = data[26 - 3] ^ data[26 - 8] ^ data[26 - 14] ^ data[26 - 16];
            data[27] = data[27 - 3] ^ data[27 - 8] ^ data[27 - 14] ^ data[27 - 16];
            data[28] = data[28 - 3] ^ data[28 - 8] ^ data[28 - 14] ^ data[28 - 16];
            data[29] = data[29 - 3] ^ data[29 - 8] ^ data[29 - 14] ^ data[29 - 16];
            data[30] = data[30 - 3] ^ data[30 - 8] ^ data[30 - 14] ^ data[30 - 16];
            data[31] = data[31 - 3] ^ data[31 - 8] ^ data[31 - 14] ^ data[31 - 16];
            data[32] = data[32 - 3] ^ data[32 - 8] ^ data[32 - 14] ^ data[32 - 16];
            data[33] = data[33 - 3] ^ data[33 - 8] ^ data[33 - 14] ^ data[33 - 16];
            data[34] = data[34 - 3] ^ data[34 - 8] ^ data[34 - 14] ^ data[34 - 16];
            data[35] = data[35 - 3] ^ data[35 - 8] ^ data[35 - 14] ^ data[35 - 16];
            data[36] = data[36 - 3] ^ data[36 - 8] ^ data[36 - 14] ^ data[36 - 16];
            data[37] = data[37 - 3] ^ data[37 - 8] ^ data[37 - 14] ^ data[37 - 16];
            data[38] = data[38 - 3] ^ data[38 - 8] ^ data[38 - 14] ^ data[38 - 16];
            data[39] = data[39 - 3] ^ data[39 - 8] ^ data[39 - 14] ^ data[39 - 16];
            data[40] = data[40 - 3] ^ data[40 - 8] ^ data[40 - 14] ^ data[40 - 16];
            data[41] = data[41 - 3] ^ data[41 - 8] ^ data[41 - 14] ^ data[41 - 16];
            data[42] = data[42 - 3] ^ data[42 - 8] ^ data[42 - 14] ^ data[42 - 16];
            data[43] = data[43 - 3] ^ data[43 - 8] ^ data[43 - 14] ^ data[43 - 16];
            data[44] = data[44 - 3] ^ data[44 - 8] ^ data[44 - 14] ^ data[44 - 16];
            data[45] = data[45 - 3] ^ data[45 - 8] ^ data[45 - 14] ^ data[45 - 16];
            data[46] = data[46 - 3] ^ data[46 - 8] ^ data[46 - 14] ^ data[46 - 16];
            data[47] = data[47 - 3] ^ data[47 - 8] ^ data[47 - 14] ^ data[47 - 16];
            data[48] = data[48 - 3] ^ data[48 - 8] ^ data[48 - 14] ^ data[48 - 16];
            data[49] = data[49 - 3] ^ data[49 - 8] ^ data[49 - 14] ^ data[49 - 16];
            data[50] = data[50 - 3] ^ data[50 - 8] ^ data[50 - 14] ^ data[50 - 16];
            data[51] = data[51 - 3] ^ data[51 - 8] ^ data[51 - 14] ^ data[51 - 16];
            data[52] = data[52 - 3] ^ data[52 - 8] ^ data[52 - 14] ^ data[52 - 16];
            data[53] = data[53 - 3] ^ data[53 - 8] ^ data[53 - 14] ^ data[53 - 16];
            data[54] = data[54 - 3] ^ data[54 - 8] ^ data[54 - 14] ^ data[54 - 16];
            data[55] = data[55 - 3] ^ data[55 - 8] ^ data[55 - 14] ^ data[55 - 16];
            data[56] = data[56 - 3] ^ data[56 - 8] ^ data[56 - 14] ^ data[56 - 16];
            data[57] = data[57 - 3] ^ data[57 - 8] ^ data[57 - 14] ^ data[57 - 16];
            data[58] = data[58 - 3] ^ data[58 - 8] ^ data[58 - 14] ^ data[58 - 16];
            data[59] = data[59 - 3] ^ data[59 - 8] ^ data[59 - 14] ^ data[59 - 16];
            data[60] = data[60 - 3] ^ data[60 - 8] ^ data[60 - 14] ^ data[60 - 16];
            data[61] = data[61 - 3] ^ data[61 - 8] ^ data[61 - 14] ^ data[61 - 16];
            data[62] = data[62 - 3] ^ data[62 - 8] ^ data[62 - 14] ^ data[62 - 16];
            data[63] = data[63 - 3] ^ data[63 - 8] ^ data[63 - 14] ^ data[63 - 16];
            data[64] = data[64 - 3] ^ data[64 - 8] ^ data[64 - 14] ^ data[64 - 16];
            data[65] = data[65 - 3] ^ data[65 - 8] ^ data[65 - 14] ^ data[65 - 16];
            data[66] = data[66 - 3] ^ data[66 - 8] ^ data[66 - 14] ^ data[66 - 16];
            data[67] = data[67 - 3] ^ data[67 - 8] ^ data[67 - 14] ^ data[67 - 16];
            data[68] = data[68 - 3] ^ data[68 - 8] ^ data[68 - 14] ^ data[68 - 16];
            data[69] = data[69 - 3] ^ data[69 - 8] ^ data[69 - 14] ^ data[69 - 16];
            data[70] = data[70 - 3] ^ data[70 - 8] ^ data[70 - 14] ^ data[70 - 16];
            data[71] = data[71 - 3] ^ data[71 - 8] ^ data[71 - 14] ^ data[71 - 16];
            data[72] = data[72 - 3] ^ data[72 - 8] ^ data[72 - 14] ^ data[72 - 16];
            data[73] = data[73 - 3] ^ data[73 - 8] ^ data[73 - 14] ^ data[73 - 16];
            data[74] = data[74 - 3] ^ data[74 - 8] ^ data[74 - 14] ^ data[74 - 16];
            data[75] = data[75 - 3] ^ data[75 - 8] ^ data[75 - 14] ^ data[75 - 16];
            data[76] = data[76 - 3] ^ data[76 - 8] ^ data[76 - 14] ^ data[76 - 16];
            data[77] = data[77 - 3] ^ data[77 - 8] ^ data[77 - 14] ^ data[77 - 16];
            data[78] = data[78 - 3] ^ data[78 - 8] ^ data[78 - 14] ^ data[78 - 16];
            data[79] = data[79 - 3] ^ data[79 - 8] ^ data[79 - 14] ^ data[79 - 16];
        }

        protected override unsafe byte[] GetResult()
        {
            var result = new byte[HashSize];

            fixed (uint* statePtr = State)
            {
                fixed (byte* resultPtr = result)
                {
                    Converters.be32_copy(statePtr, 0, resultPtr, 0, result.Length);
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

            bits = Converters.be2me_64(bits);

            Converters.ReadUInt64AsBytesLE(bits, pad.Slice(padIndex));

            padIndex += 8;

            TransformByteSpan(pad.Slice(0, padIndex));
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = stackalloc uint[80];

            Converters.be32_copy(data, index, buffer, 0, dataLength);

            Expand(buffer);

            var a = State[0];
            var b = State[1];
            var c = State[2];
            var d = State[3];
            var e = State[4];

            e = buffer[0] + C1 + Bits.RotateLeft32(a, 5) +
                (d ^ (b & (c ^ d))) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[1] + C1 + Bits.RotateLeft32(e, 5) +
                (c ^ (a & (b ^ c))) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[2] + C1 + Bits.RotateLeft32(d, 5) +
                (b ^ (e & (a ^ b))) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[3] + C1 + Bits.RotateLeft32(c, 5) +
                (a ^ (d & (e ^ a))) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[4] + C1 + Bits.RotateLeft32(b, 5) +
                (e ^ (c & (d ^ e))) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[5] + C1 + Bits.RotateLeft32(a, 5) +
                (d ^ (b & (c ^ d))) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[6] + C1 + Bits.RotateLeft32(e, 5) +
                (c ^ (a & (b ^ c))) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[7] + C1 + Bits.RotateLeft32(d, 5) +
                (b ^ (e & (a ^ b))) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[8] + C1 + Bits.RotateLeft32(c, 5) +
                (a ^ (d & (e ^ a))) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[9] + C1 + Bits.RotateLeft32(b, 5) +
                (e ^ (c & (d ^ e))) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[10] + C1 + Bits.RotateLeft32(a, 5) +
                (d ^ (b & (c ^ d))) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[11] + C1 + Bits.RotateLeft32(e, 5) +
                (c ^ (a & (b ^ c))) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[12] + C1 + Bits.RotateLeft32(d, 5) +
                (b ^ (e & (a ^ b))) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[13] + C1 + Bits.RotateLeft32(c, 5) +
                (a ^ (d & (e ^ a))) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[14] + C1 + Bits.RotateLeft32(b, 5) +
                (e ^ (c & (d ^ e))) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[15] + C1 + Bits.RotateLeft32(a, 5) +
                (d ^ (b & (c ^ d))) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[16] + C1 + Bits.RotateLeft32(e, 5) +
                (c ^ (a & (b ^ c))) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[17] + C1 + Bits.RotateLeft32(d, 5) +
                (b ^ (e & (a ^ b))) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[18] + C1 + Bits.RotateLeft32(c, 5) +
                (a ^ (d & (e ^ a))) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[19] + C1 + Bits.RotateLeft32(b, 5) +
                (e ^ (c & (d ^ e))) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[20] + C2 + Bits.RotateLeft32(a, 5) + (b ^ c ^ d) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[21] + C2 + Bits.RotateLeft32(e, 5) + (a ^ b ^ c) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[22] + C2 + Bits.RotateLeft32(d, 5) + (e ^ a ^ b) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[23] + C2 + Bits.RotateLeft32(c, 5) + (d ^ e ^ a) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[24] + C2 + Bits.RotateLeft32(b, 5) + (c ^ d ^ e) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[25] + C2 + Bits.RotateLeft32(a, 5) + (b ^ c ^ d) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[26] + C2 + Bits.RotateLeft32(e, 5) + (a ^ b ^ c) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[27] + C2 + Bits.RotateLeft32(d, 5) + (e ^ a ^ b) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[28] + C2 + Bits.RotateLeft32(c, 5) + (d ^ e ^ a) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[29] + C2 + Bits.RotateLeft32(b, 5) + (c ^ d ^ e) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[30] + C2 + Bits.RotateLeft32(a, 5) + (b ^ c ^ d) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[31] + C2 + Bits.RotateLeft32(e, 5) + (a ^ b ^ c) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[32] + C2 + Bits.RotateLeft32(d, 5) + (e ^ a ^ b) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[33] + C2 + Bits.RotateLeft32(c, 5) + (d ^ e ^ a) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[34] + C2 + Bits.RotateLeft32(b, 5) + (c ^ d ^ e) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[35] + C2 + Bits.RotateLeft32(a, 5) + (b ^ c ^ d) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[36] + C2 + Bits.RotateLeft32(e, 5) + (a ^ b ^ c) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[37] + C2 + Bits.RotateLeft32(d, 5) + (e ^ a ^ b) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[38] + C2 + Bits.RotateLeft32(c, 5) + (d ^ e ^ a) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[39] + C2 + Bits.RotateLeft32(b, 5) + (c ^ d ^ e) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[40] + C3 + Bits.RotateLeft32(a, 5) +
                ((b & c) | (d & (b | c))) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[41] + C3 + Bits.RotateLeft32(e, 5) +
                ((a & b) | (c & (a | b))) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[42] + C3 + Bits.RotateLeft32(d, 5) +
                ((e & a) | (b & (e | a))) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[43] + C3 + Bits.RotateLeft32(c, 5) +
                ((d & e) | (a & (d | e))) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[44] + C3 + Bits.RotateLeft32(b, 5) +
                ((c & d) | (e & (c | d))) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[45] + C3 + Bits.RotateLeft32(a, 5) +
                ((b & c) | (d & (b | c))) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[46] + C3 + Bits.RotateLeft32(e, 5) +
                ((a & b) | (c & (a | b))) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[47] + C3 + Bits.RotateLeft32(d, 5) +
                ((e & a) | (b & (e | a))) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[48] + C3 + Bits.RotateLeft32(c, 5) +
                ((d & e) | (a & (d | e))) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[49] + C3 + Bits.RotateLeft32(b, 5) +
                ((c & d) | (e & (c | d))) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[50] + C3 + Bits.RotateLeft32(a, 5) +
                ((b & c) | (d & (b | c))) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[51] + C3 + Bits.RotateLeft32(e, 5) +
                ((a & b) | (c & (a | b))) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[52] + C3 + Bits.RotateLeft32(d, 5) +
                ((e & a) | (b & (e | a))) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[53] + C3 + Bits.RotateLeft32(c, 5) +
                ((d & e) | (a & (d | e))) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[54] + C3 + Bits.RotateLeft32(b, 5) +
                ((c & d) | (e & (c | d))) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[55] + C3 + Bits.RotateLeft32(a, 5) +
                ((b & c) | (d & (b | c))) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[56] + C3 + Bits.RotateLeft32(e, 5) +
                ((a & b) | (c & (a | b))) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[57] + C3 + Bits.RotateLeft32(d, 5) +
                ((e & a) | (b & (e | a))) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[58] + C3 + Bits.RotateLeft32(c, 5) +
                ((d & e) | (a & (d | e))) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[59] + C3 + Bits.RotateLeft32(b, 5) +
                ((c & d) | (e & (c | d))) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[60] + C4 + Bits.RotateLeft32(a, 5) + (b ^ c ^ d) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[61] + C4 + Bits.RotateLeft32(e, 5) + (a ^ b ^ c) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[62] + C4 + Bits.RotateLeft32(d, 5) + (e ^ a ^ b) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[63] + C4 + Bits.RotateLeft32(c, 5) + (d ^ e ^ a) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[64] + C4 + Bits.RotateLeft32(b, 5) + (c ^ d ^ e) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[65] + C4 + Bits.RotateLeft32(a, 5) + (b ^ c ^ d) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[66] + C4 + Bits.RotateLeft32(e, 5) + (a ^ b ^ c) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[67] + C4 + Bits.RotateLeft32(d, 5) + (e ^ a ^ b) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[68] + C4 + Bits.RotateLeft32(c, 5) + (d ^ e ^ a) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[69] + C4 + Bits.RotateLeft32(b, 5) + (c ^ d ^ e) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[70] + C4 + Bits.RotateLeft32(a, 5) + (b ^ c ^ d) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[71] + C4 + Bits.RotateLeft32(e, 5) + (a ^ b ^ c) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[72] + C4 + Bits.RotateLeft32(d, 5) + (e ^ a ^ b) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[73] + C4 + Bits.RotateLeft32(c, 5) + (d ^ e ^ a) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[74] + C4 + Bits.RotateLeft32(b, 5) + (c ^ d ^ e) + a;

            c = Bits.RotateLeft32(c, 30);
            e = buffer[75] + C4 + Bits.RotateLeft32(a, 5) + (b ^ c ^ d) + e;

            b = Bits.RotateLeft32(b, 30);
            d = buffer[76] + C4 + Bits.RotateLeft32(e, 5) + (a ^ b ^ c) + d;

            a = Bits.RotateLeft32(a, 30);
            c = buffer[77] + C4 + Bits.RotateLeft32(d, 5) + (e ^ a ^ b) + c;

            e = Bits.RotateLeft32(e, 30);
            b = buffer[78] + C4 + Bits.RotateLeft32(c, 5) + (d ^ e ^ a) + b;

            d = Bits.RotateLeft32(d, 30);
            a = buffer[79] + C4 + Bits.RotateLeft32(b, 5) + (c ^ d ^ e) + a;

            c = Bits.RotateLeft32(c, 30);

            State[0] = State[0] + a;
            State[1] = State[1] + b;
            State[2] = State[2] + c;
            State[3] = State[3] + d;
            State[4] = State[4] + e;
        }
    }
}