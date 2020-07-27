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
    internal abstract class SHA2_256Base : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        protected uint[] State;

        protected SHA2_256Base(int hashSize)
            : base(hashSize, 64)
        {
            State = new uint[8];
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

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = stackalloc uint[64];

            Converters.be32_copy(data, index, buffer, 0, dataLength);


            var a = State[0];
            var b = State[1];
            var c = State[2];
            var d = State[3];
            var e = State[4];
            var f = State[5];
            var g = State[6];
            var h = State[7];

            // Step 1

            var t = buffer[14];
            var t2 = buffer[1];
            buffer[16] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[9] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[0];

            t = buffer[15];
            t2 = buffer[2];
            buffer[17] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[10] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[1];

            t = buffer[16];
            t2 = buffer[3];
            buffer[18] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[11] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[2];

            t = buffer[17];
            t2 = buffer[4];
            buffer[19] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[12] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[3];

            t = buffer[18];
            t2 = buffer[5];
            buffer[20] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[13] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[4];

            t = buffer[19];
            t2 = buffer[6];
            buffer[21] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[14] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[5];

            t = buffer[20];
            t2 = buffer[7];
            buffer[22] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[15] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[6];

            t = buffer[21];
            t2 = buffer[8];
            buffer[23] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[16] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[7];

            t = buffer[22];
            t2 = buffer[9];
            buffer[24] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[17] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[8];

            t = buffer[23];
            t2 = buffer[10];
            buffer[25] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[18] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[9];

            t = buffer[24];
            t2 = buffer[11];
            buffer[26] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[19] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[10];

            t = buffer[25];
            t2 = buffer[12];
            buffer[27] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[20] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[11];

            t = buffer[26];
            t2 = buffer[13];
            buffer[28] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[21] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[12];

            t = buffer[27];
            t2 = buffer[14];
            buffer[29] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[22] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[13];

            t = buffer[28];
            t2 = buffer[15];
            buffer[30] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[23] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[14];

            t = buffer[29];
            t2 = buffer[16];
            buffer[31] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[24] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[15];

            t = buffer[30];
            t2 = buffer[17];
            buffer[32] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[25] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[16];

            t = buffer[31];
            t2 = buffer[18];
            buffer[33] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[26] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[17];

            t = buffer[32];
            t2 = buffer[19];
            buffer[34] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[27] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[18];

            t = buffer[33];
            t2 = buffer[20];
            buffer[35] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[28] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[19];

            t = buffer[34];
            t2 = buffer[21];
            buffer[36] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[29] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[20];

            t = buffer[35];
            t2 = buffer[22];
            buffer[37] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[30] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[21];

            t = buffer[36];
            t2 = buffer[23];
            buffer[38] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[31] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[22];

            t = buffer[37];
            t2 = buffer[24];
            buffer[39] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[32] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[23];

            t = buffer[38];
            t2 = buffer[25];
            buffer[40] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[33] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[24];

            t = buffer[39];
            t2 = buffer[26];
            buffer[41] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[34] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[25];

            t = buffer[40];
            t2 = buffer[27];
            buffer[42] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[35] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[26];

            t = buffer[41];
            t2 = buffer[28];
            buffer[43] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[36] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[27];

            t = buffer[42];
            t2 = buffer[29];
            buffer[44] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[37] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[28];

            t = buffer[43];
            t2 = buffer[30];
            buffer[45] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[38] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[29];

            t = buffer[44];
            t2 = buffer[31];
            buffer[46] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[39] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[30];

            t = buffer[45];
            t2 = buffer[32];
            buffer[47] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[40] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[31];

            t = buffer[46];
            t2 = buffer[33];
            buffer[48] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[41] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[32];

            t = buffer[47];
            t2 = buffer[34];
            buffer[49] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[42] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[33];

            t = buffer[48];
            t2 = buffer[35];
            buffer[50] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[43] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[34];

            t = buffer[49];
            t2 = buffer[36];
            buffer[51] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[44] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[35];

            t = buffer[50];
            t2 = buffer[37];
            buffer[52] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[45] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[36];

            t = buffer[51];
            t2 = buffer[38];
            buffer[53] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[46] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[37];

            t = buffer[52];
            t2 = buffer[39];
            buffer[54] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[47] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[38];

            t = buffer[53];
            t2 = buffer[40];
            buffer[55] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[48] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[39];

            t = buffer[54];
            t2 = buffer[41];
            buffer[56] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[49] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[40];

            t = buffer[55];
            t2 = buffer[42];
            buffer[57] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[50] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[41];

            t = buffer[56];
            t2 = buffer[43];
            buffer[58] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[51] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[42];

            t = buffer[57];
            t2 = buffer[44];
            buffer[59] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[52] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[43];

            t = buffer[58];
            t2 = buffer[45];
            buffer[60] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[53] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[44];

            t = buffer[59];
            t2 = buffer[46];
            buffer[61] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[54] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[45];

            t = buffer[60];
            t2 = buffer[47];
            buffer[62] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[55] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[46];

            t = buffer[61];
            t2 = buffer[48];
            buffer[63] = (Bits.RotateRight32(t, 17) ^ Bits.RotateRight32(t, 19)
                                                    ^ (t >> 10)) + buffer[56] +
                         (Bits.RotateRight32(t2, 7) ^ Bits.RotateRight32(t2, 18)
                                                    ^ (t2 >> 3)) + buffer[47];

            // Step 2

            t = h + (Bits.RotateRight32(e, 6) ^ Bits.RotateRight32(e, 11)
                                              ^ Bits.RotateRight32(e, 25)) + ((e & f) ^ (~e & g)) +
                0x428A2F98 + buffer[0];
            t2 = (Bits.RotateRight32(a, 2) ^ Bits.RotateRight32(a, 13) ^ (a >> 22) ^ (a << 10)) +
                 ((a & b) ^ (a & c) ^ (b & c));
            h = t + t2;
            d += t;
            t = g + (Bits.RotateRight32(d, 6) ^ Bits.RotateRight32(d, 11)
                                              ^ Bits.RotateRight32(d, 25)) + ((d & e) ^ (~d & f)) +
                0x71374491 + buffer[1];
            t2 = (Bits.RotateRight32(h, 2) ^ Bits.RotateRight32(h, 13) ^ (h >> 22) ^ (h << 10)) +
                 ((h & a) ^ (h & b) ^ (a & b));
            g = t + t2;
            c += t;
            t = f + (Bits.RotateRight32(c, 6) ^ Bits.RotateRight32(c, 11)
                                              ^ Bits.RotateRight32(c, 25)) + ((c & d) ^ (~c & e)) +
                0xB5C0FBCF + buffer[2];
            t2 = (Bits.RotateRight32(g, 2) ^ Bits.RotateRight32(g, 13) ^ (g >> 22) ^ (g << 10)) +
                 ((g & h) ^ (g & a) ^ (h & a));
            f = t + t2;
            b += t;
            t = e + (Bits.RotateRight32(b, 6) ^ Bits.RotateRight32(b, 11)
                                              ^ Bits.RotateRight32(b, 25)) + ((b & c) ^ (~b & d)) +
                0xE9B5DBA5 + buffer[3];
            t2 = (Bits.RotateRight32(f, 2) ^ Bits.RotateRight32(f, 13) ^ (f >> 22) ^ (f << 10)) +
                 ((f & g) ^ (f & h) ^ (g & h));
            e = t + t2;
            a += t;
            t = d + (Bits.RotateRight32(a, 6) ^ Bits.RotateRight32(a, 11)
                                              ^ Bits.RotateRight32(a, 25)) + ((a & b) ^ (~a & c)) +
                0x3956C25B + buffer[4];
            t2 = (Bits.RotateRight32(e, 2) ^ Bits.RotateRight32(e, 13) ^ (e >> 22) ^ (e << 10)) +
                 ((e & f) ^ (e & g) ^ (f & g));
            d = t + t2;
            h += t;
            t = c + (Bits.RotateRight32(h, 6) ^ Bits.RotateRight32(h, 11)
                                              ^ Bits.RotateRight32(h, 25)) + ((h & a) ^ (~h & b)) +
                0x59F111F1 + buffer[5];
            t2 = (Bits.RotateRight32(d, 2) ^ Bits.RotateRight32(d, 13) ^ (d >> 22) ^ (d << 10)) +
                 ((d & e) ^ (d & f) ^ (e & f));
            c = t + t2;
            g += t;
            t = b + (Bits.RotateRight32(g, 6) ^ Bits.RotateRight32(g, 11)
                                              ^ Bits.RotateRight32(g, 25)) + ((g & h) ^ (~g & a)) +
                0x923F82A4 + buffer[6];
            t2 = (Bits.RotateRight32(c, 2) ^ Bits.RotateRight32(c, 13) ^ (c >> 22) ^ (c << 10)) +
                 ((c & d) ^ (c & e) ^ (d & e));
            b = t + t2;
            f += t;
            t = a + (Bits.RotateRight32(f, 6) ^ Bits.RotateRight32(f, 11)
                                              ^ Bits.RotateRight32(f, 25)) + ((f & g) ^ (~f & h)) +
                0xAB1C5ED5 + buffer[7];
            t2 = (Bits.RotateRight32(b, 2) ^ Bits.RotateRight32(b, 13) ^ (b >> 22) ^ (b << 10)) +
                 ((b & c) ^ (b & d) ^ (c & d));
            a = t + t2;
            e += t;
            t = h + (Bits.RotateRight32(e, 6) ^ Bits.RotateRight32(e, 11)
                                              ^ Bits.RotateRight32(e, 25)) + ((e & f) ^ (~e & g)) +
                0xD807AA98 + buffer[8];
            t2 = (Bits.RotateRight32(a, 2) ^ Bits.RotateRight32(a, 13) ^ (a >> 22) ^ (a << 10)) +
                 ((a & b) ^ (a & c) ^ (b & c));
            h = t + t2;
            d += t;
            t = g + (Bits.RotateRight32(d, 6) ^ Bits.RotateRight32(d, 11)
                                              ^ Bits.RotateRight32(d, 25)) + ((d & e) ^ (~d & f)) +
                0x12835B01 + buffer[9];
            t2 = (Bits.RotateRight32(h, 2) ^ Bits.RotateRight32(h, 13) ^ (h >> 22) ^ (h << 10)) +
                 ((h & a) ^ (h & b) ^ (a & b));
            g = t + t2;
            c += t;
            t = f + (Bits.RotateRight32(c, 6) ^ Bits.RotateRight32(c, 11)
                                              ^ Bits.RotateRight32(c, 25)) + ((c & d) ^ (~c & e)) +
                0x243185BE + buffer[10];
            t2 = (Bits.RotateRight32(g, 2) ^ Bits.RotateRight32(g, 13) ^ (g >> 22) ^ (g << 10)) +
                 ((g & h) ^ (g & a) ^ (h & a));
            f = t + t2;
            b += t;
            t = e + (Bits.RotateRight32(b, 6) ^ Bits.RotateRight32(b, 11)
                                              ^ Bits.RotateRight32(b, 25)) + ((b & c) ^ (~b & d)) +
                0x550C7DC3 + buffer[11];
            t2 = (Bits.RotateRight32(f, 2) ^ Bits.RotateRight32(f, 13) ^ (f >> 22) ^ (f << 10)) +
                 ((f & g) ^ (f & h) ^ (g & h));
            e = t + t2;
            a += t;
            t = d + (Bits.RotateRight32(a, 6) ^ Bits.RotateRight32(a, 11)
                                              ^ Bits.RotateRight32(a, 25)) + ((a & b) ^ (~a & c)) +
                0x72BE5D74 + buffer[12];
            t2 = (Bits.RotateRight32(e, 2) ^ Bits.RotateRight32(e, 13) ^ (e >> 22) ^ (e << 10)) +
                 ((e & f) ^ (e & g) ^ (f & g));
            d = t + t2;
            h += t;
            t = c + (Bits.RotateRight32(h, 6) ^ Bits.RotateRight32(h, 11)
                                              ^ Bits.RotateRight32(h, 25)) + ((h & a) ^ (~h & b)) +
                0x80DEB1FE + buffer[13];
            t2 = (Bits.RotateRight32(d, 2) ^ Bits.RotateRight32(d, 13) ^ (d >> 22) ^ (d << 10)) +
                 ((d & e) ^ (d & f) ^ (e & f));
            c = t + t2;
            g += t;
            t = b + (Bits.RotateRight32(g, 6) ^ Bits.RotateRight32(g, 11)
                                              ^ Bits.RotateRight32(g, 25)) + ((g & h) ^ (~g & a)) +
                0x9BDC06A7 + buffer[14];
            t2 = (Bits.RotateRight32(c, 2) ^ Bits.RotateRight32(c, 13) ^ (c >> 22) ^ (c << 10)) +
                 ((c & d) ^ (c & e) ^ (d & e));
            b = t + t2;
            f += t;
            t = a + (Bits.RotateRight32(f, 6) ^ Bits.RotateRight32(f, 11)
                                              ^ Bits.RotateRight32(f, 25)) + ((f & g) ^ (~f & h)) +
                0xC19BF174 + buffer[15];
            t2 = (Bits.RotateRight32(b, 2) ^ Bits.RotateRight32(b, 13) ^ (b >> 22) ^ (b << 10)) +
                 ((b & c) ^ (b & d) ^ (c & d));
            a = t + t2;
            e += t;
            t = h + (Bits.RotateRight32(e, 6) ^ Bits.RotateRight32(e, 11)
                                              ^ Bits.RotateRight32(e, 25)) + ((e & f) ^ (~e & g)) +
                0xE49B69C1 + buffer[16];
            t2 = (Bits.RotateRight32(a, 2) ^ Bits.RotateRight32(a, 13) ^ (a >> 22) ^ (a << 10)) +
                 ((a & b) ^ (a & c) ^ (b & c));
            h = t + t2;
            d += t;
            t = g + (Bits.RotateRight32(d, 6) ^ Bits.RotateRight32(d, 11)
                                              ^ Bits.RotateRight32(d, 25)) + ((d & e) ^ (~d & f)) +
                0xEFBE4786 + buffer[17];
            t2 = (Bits.RotateRight32(h, 2) ^ Bits.RotateRight32(h, 13) ^ (h >> 22) ^ (h << 10)) +
                 ((h & a) ^ (h & b) ^ (a & b));
            g = t + t2;
            c += t;
            t = f + (Bits.RotateRight32(c, 6) ^ Bits.RotateRight32(c, 11)
                                              ^ Bits.RotateRight32(c, 25)) + ((c & d) ^ (~c & e)) +
                0x0FC19DC6 + buffer[18];
            t2 = (Bits.RotateRight32(g, 2) ^ Bits.RotateRight32(g, 13) ^ (g >> 22) ^ (g << 10)) +
                 ((g & h) ^ (g & a) ^ (h & a));
            f = t + t2;
            b += t;
            t = e + (Bits.RotateRight32(b, 6) ^ Bits.RotateRight32(b, 11)
                                              ^ Bits.RotateRight32(b, 25)) + ((b & c) ^ (~b & d)) +
                0x240CA1CC + buffer[19];
            t2 = (Bits.RotateRight32(f, 2) ^ Bits.RotateRight32(f, 13) ^ (f >> 22) ^ (f << 10)) +
                 ((f & g) ^ (f & h) ^ (g & h));
            e = t + t2;
            a += t;
            t = d + (Bits.RotateRight32(a, 6) ^ Bits.RotateRight32(a, 11)
                                              ^ Bits.RotateRight32(a, 25)) + ((a & b) ^ (~a & c)) +
                0x2DE92C6F + buffer[20];
            t2 = (Bits.RotateRight32(e, 2) ^ Bits.RotateRight32(e, 13) ^ (e >> 22) ^ (e << 10)) +
                 ((e & f) ^ (e & g) ^ (f & g));
            d = t + t2;
            h += t;
            t = c + (Bits.RotateRight32(h, 6) ^ Bits.RotateRight32(h, 11)
                                              ^ Bits.RotateRight32(h, 25)) + ((h & a) ^ (~h & b)) +
                0x4A7484AA + buffer[21];
            t2 = (Bits.RotateRight32(d, 2) ^ Bits.RotateRight32(d, 13) ^ (d >> 22) ^ (d << 10)) +
                 ((d & e) ^ (d & f) ^ (e & f));
            c = t + t2;
            g += t;
            t = b + (Bits.RotateRight32(g, 6) ^ Bits.RotateRight32(g, 11)
                                              ^ Bits.RotateRight32(g, 25)) + ((g & h) ^ (~g & a)) +
                0x5CB0A9DC + buffer[22];
            t2 = (Bits.RotateRight32(c, 2) ^ Bits.RotateRight32(c, 13) ^ (c >> 22) ^ (c << 10)) +
                 ((c & d) ^ (c & e) ^ (d & e));
            b = t + t2;
            f += t;
            t = a + (Bits.RotateRight32(f, 6) ^ Bits.RotateRight32(f, 11)
                                              ^ Bits.RotateRight32(f, 25)) + ((f & g) ^ (~f & h)) +
                0x76F988DA + buffer[23];
            t2 = (Bits.RotateRight32(b, 2) ^ Bits.RotateRight32(b, 13) ^ (b >> 22) ^ (b << 10)) +
                 ((b & c) ^ (b & d) ^ (c & d));
            a = t + t2;
            e += t;
            t = h + (Bits.RotateRight32(e, 6) ^ Bits.RotateRight32(e, 11)
                                              ^ Bits.RotateRight32(e, 25)) + ((e & f) ^ (~e & g)) +
                0x983E5152 + buffer[24];
            t2 = (Bits.RotateRight32(a, 2) ^ Bits.RotateRight32(a, 13) ^ (a >> 22) ^ (a << 10)) +
                 ((a & b) ^ (a & c) ^ (b & c));
            h = t + t2;
            d += t;
            t = g + (Bits.RotateRight32(d, 6) ^ Bits.RotateRight32(d, 11)
                                              ^ Bits.RotateRight32(d, 25)) + ((d & e) ^ (~d & f)) +
                0xA831C66D + buffer[25];
            t2 = (Bits.RotateRight32(h, 2) ^ Bits.RotateRight32(h, 13) ^ (h >> 22) ^ (h << 10)) +
                 ((h & a) ^ (h & b) ^ (a & b));
            g = t + t2;
            c += t;
            t = f + (Bits.RotateRight32(c, 6) ^ Bits.RotateRight32(c, 11)
                                              ^ Bits.RotateRight32(c, 25)) + ((c & d) ^ (~c & e)) +
                0xB00327C8 + buffer[26];
            t2 = (Bits.RotateRight32(g, 2) ^ Bits.RotateRight32(g, 13) ^ (g >> 22) ^ (g << 10)) +
                 ((g & h) ^ (g & a) ^ (h & a));
            f = t + t2;
            b += t;
            t = e + (Bits.RotateRight32(b, 6) ^ Bits.RotateRight32(b, 11)
                                              ^ Bits.RotateRight32(b, 25)) + ((b & c) ^ (~b & d)) +
                0xBF597FC7 + buffer[27];
            t2 = (Bits.RotateRight32(f, 2) ^ Bits.RotateRight32(f, 13) ^ (f >> 22) ^ (f << 10)) +
                 ((f & g) ^ (f & h) ^ (g & h));
            e = t + t2;
            a += t;
            t = d + (Bits.RotateRight32(a, 6) ^ Bits.RotateRight32(a, 11)
                                              ^ Bits.RotateRight32(a, 25)) + ((a & b) ^ (~a & c)) +
                0xC6E00BF3 + buffer[28];
            t2 = (Bits.RotateRight32(e, 2) ^ Bits.RotateRight32(e, 13) ^ (e >> 22) ^ (e << 10)) +
                 ((e & f) ^ (e & g) ^ (f & g));
            d = t + t2;
            h += t;
            t = c + (Bits.RotateRight32(h, 6) ^ Bits.RotateRight32(h, 11)
                                              ^ Bits.RotateRight32(h, 25)) + ((h & a) ^ (~h & b)) +
                0xD5A79147 + buffer[29];
            t2 = (Bits.RotateRight32(d, 2) ^ Bits.RotateRight32(d, 13) ^ (d >> 22) ^ (d << 10)) +
                 ((d & e) ^ (d & f) ^ (e & f));
            c = t + t2;
            g += t;
            t = b + (Bits.RotateRight32(g, 6) ^ Bits.RotateRight32(g, 11)
                                              ^ Bits.RotateRight32(g, 25)) + ((g & h) ^ (~g & a)) +
                0x06CA6351 + buffer[30];
            t2 = (Bits.RotateRight32(c, 2) ^ Bits.RotateRight32(c, 13) ^ (c >> 22) ^ (c << 10)) +
                 ((c & d) ^ (c & e) ^ (d & e));
            b = t + t2;
            f += t;
            t = a + (Bits.RotateRight32(f, 6) ^ Bits.RotateRight32(f, 11)
                                              ^ Bits.RotateRight32(f, 25)) + ((f & g) ^ (~f & h)) +
                0x14292967 + buffer[31];
            t2 = (Bits.RotateRight32(b, 2) ^ Bits.RotateRight32(b, 13) ^ (b >> 22) ^ (b << 10)) +
                 ((b & c) ^ (b & d) ^ (c & d));
            a = t + t2;
            e += t;
            t = h + (Bits.RotateRight32(e, 6) ^ Bits.RotateRight32(e, 11)
                                              ^ Bits.RotateRight32(e, 25)) + ((e & f) ^ (~e & g)) +
                0x27B70A85 + buffer[32];
            t2 = (Bits.RotateRight32(a, 2) ^ Bits.RotateRight32(a, 13) ^ (a >> 22) ^ (a << 10)) +
                 ((a & b) ^ (a & c) ^ (b & c));
            h = t + t2;
            d += t;
            t = g + (Bits.RotateRight32(d, 6) ^ Bits.RotateRight32(d, 11)
                                              ^ Bits.RotateRight32(d, 25)) + ((d & e) ^ (~d & f)) +
                0x2E1B2138 + buffer[33];
            t2 = (Bits.RotateRight32(h, 2) ^ Bits.RotateRight32(h, 13) ^ (h >> 22) ^ (h << 10)) +
                 ((h & a) ^ (h & b) ^ (a & b));
            g = t + t2;
            c += t;
            t = f + (Bits.RotateRight32(c, 6) ^ Bits.RotateRight32(c, 11)
                                              ^ Bits.RotateRight32(c, 25)) + ((c & d) ^ (~c & e)) +
                0x4D2C6DFC + buffer[34];
            t2 = (Bits.RotateRight32(g, 2) ^ Bits.RotateRight32(g, 13) ^ (g >> 22) ^ (g << 10)) +
                 ((g & h) ^ (g & a) ^ (h & a));
            f = t + t2;
            b += t;
            t = e + (Bits.RotateRight32(b, 6) ^ Bits.RotateRight32(b, 11)
                                              ^ Bits.RotateRight32(b, 25)) + ((b & c) ^ (~b & d)) +
                0x53380D13 + buffer[35];
            t2 = (Bits.RotateRight32(f, 2) ^ Bits.RotateRight32(f, 13) ^ (f >> 22) ^ (f << 10)) +
                 ((f & g) ^ (f & h) ^ (g & h));
            e = t + t2;
            a += t;
            t = d + (Bits.RotateRight32(a, 6) ^ Bits.RotateRight32(a, 11)
                                              ^ Bits.RotateRight32(a, 25)) + ((a & b) ^ (~a & c)) +
                0x650A7354 + buffer[36];
            t2 = (Bits.RotateRight32(e, 2) ^ Bits.RotateRight32(e, 13) ^ (e >> 22) ^ (e << 10)) +
                 ((e & f) ^ (e & g) ^ (f & g));
            d = t + t2;
            h += t;
            t = c + (Bits.RotateRight32(h, 6) ^ Bits.RotateRight32(h, 11)
                                              ^ Bits.RotateRight32(h, 25)) + ((h & a) ^ (~h & b)) +
                0x766A0ABB + buffer[37];
            t2 = (Bits.RotateRight32(d, 2) ^ Bits.RotateRight32(d, 13) ^ (d >> 22) ^ (d << 10)) +
                 ((d & e) ^ (d & f) ^ (e & f));
            c = t + t2;
            g += t;
            t = b + (Bits.RotateRight32(g, 6) ^ Bits.RotateRight32(g, 11)
                                              ^ Bits.RotateRight32(g, 25)) + ((g & h) ^ (~g & a)) +
                0x81C2C92E + buffer[38];
            t2 = (Bits.RotateRight32(c, 2) ^ Bits.RotateRight32(c, 13) ^ (c >> 22) ^ (c << 10)) +
                 ((c & d) ^ (c & e) ^ (d & e));
            b = t + t2;
            f += t;
            t = a + (Bits.RotateRight32(f, 6) ^ Bits.RotateRight32(f, 11)
                                              ^ Bits.RotateRight32(f, 25)) + ((f & g) ^ (~f & h)) +
                0x92722C85 + buffer[39];
            t2 = (Bits.RotateRight32(b, 2) ^ Bits.RotateRight32(b, 13) ^ (b >> 22) ^ (b << 10)) +
                 ((b & c) ^ (b & d) ^ (c & d));
            a = t + t2;
            e += t;
            t = h + (Bits.RotateRight32(e, 6) ^ Bits.RotateRight32(e, 11)
                                              ^ Bits.RotateRight32(e, 25)) + ((e & f) ^ (~e & g)) +
                0xA2BFE8A1 + buffer[40];
            t2 = (Bits.RotateRight32(a, 2) ^ Bits.RotateRight32(a, 13) ^ (a >> 22) ^ (a << 10)) +
                 ((a & b) ^ (a & c) ^ (b & c));
            h = t + t2;
            d += t;
            t = g + (Bits.RotateRight32(d, 6) ^ Bits.RotateRight32(d, 11)
                                              ^ Bits.RotateRight32(d, 25)) + ((d & e) ^ (~d & f)) +
                0xA81A664B + buffer[41];
            t2 = (Bits.RotateRight32(h, 2) ^ Bits.RotateRight32(h, 13) ^ (h >> 22) ^ (h << 10)) +
                 ((h & a) ^ (h & b) ^ (a & b));
            g = t + t2;
            c += t;
            t = f + (Bits.RotateRight32(c, 6) ^ Bits.RotateRight32(c, 11)
                                              ^ Bits.RotateRight32(c, 25)) + ((c & d) ^ (~c & e)) +
                0xC24B8B70 + buffer[42];
            t2 = (Bits.RotateRight32(g, 2) ^ Bits.RotateRight32(g, 13) ^ (g >> 22) ^ (g << 10)) +
                 ((g & h) ^ (g & a) ^ (h & a));
            f = t + t2;
            b += t;
            t = e + (Bits.RotateRight32(b, 6) ^ Bits.RotateRight32(b, 11)
                                              ^ Bits.RotateRight32(b, 25)) + ((b & c) ^ (~b & d)) +
                0xC76C51A3 + buffer[43];
            t2 = (Bits.RotateRight32(f, 2) ^ Bits.RotateRight32(f, 13) ^ (f >> 22) ^ (f << 10)) +
                 ((f & g) ^ (f & h) ^ (g & h));
            e = t + t2;
            a += t;
            t = d + (Bits.RotateRight32(a, 6) ^ Bits.RotateRight32(a, 11)
                                              ^ Bits.RotateRight32(a, 25)) + ((a & b) ^ (~a & c)) +
                0xD192E819 + buffer[44];
            t2 = (Bits.RotateRight32(e, 2) ^ Bits.RotateRight32(e, 13) ^ (e >> 22) ^ (e << 10)) +
                 ((e & f) ^ (e & g) ^ (f & g));
            d = t + t2;
            h += t;
            t = c + (Bits.RotateRight32(h, 6) ^ Bits.RotateRight32(h, 11)
                                              ^ Bits.RotateRight32(h, 25)) + ((h & a) ^ (~h & b)) +
                0xD6990624 + buffer[45];
            t2 = (Bits.RotateRight32(d, 2) ^ Bits.RotateRight32(d, 13) ^ (d >> 22) ^ (d << 10)) +
                 ((d & e) ^ (d & f) ^ (e & f));
            c = t + t2;
            g += t;
            t = b + (Bits.RotateRight32(g, 6) ^ Bits.RotateRight32(g, 11)
                                              ^ Bits.RotateRight32(g, 25)) + ((g & h) ^ (~g & a)) +
                0xF40E3585 + buffer[46];
            t2 = (Bits.RotateRight32(c, 2) ^ Bits.RotateRight32(c, 13) ^ (c >> 22) ^ (c << 10)) +
                 ((c & d) ^ (c & e) ^ (d & e));
            b = t + t2;
            f += t;
            t = a + (Bits.RotateRight32(f, 6) ^ Bits.RotateRight32(f, 11)
                                              ^ Bits.RotateRight32(f, 25)) + ((f & g) ^ (~f & h)) +
                0x106AA070 + buffer[47];
            t2 = (Bits.RotateRight32(b, 2) ^ Bits.RotateRight32(b, 13) ^ (b >> 22) ^ (b << 10)) +
                 ((b & c) ^ (b & d) ^ (c & d));
            a = t + t2;
            e += t;
            t = h + (Bits.RotateRight32(e, 6) ^ Bits.RotateRight32(e, 11)
                                              ^ Bits.RotateRight32(e, 25)) + ((e & f) ^ (~e & g)) +
                0x19A4C116 + buffer[48];
            t2 = (Bits.RotateRight32(a, 2) ^ Bits.RotateRight32(a, 13) ^ (a >> 22) ^ (a << 10)) +
                 ((a & b) ^ (a & c) ^ (b & c));
            h = t + t2;
            d += t;
            t = g + (Bits.RotateRight32(d, 6) ^ Bits.RotateRight32(d, 11)
                                              ^ Bits.RotateRight32(d, 25)) + ((d & e) ^ (~d & f)) +
                0x1E376C08 + buffer[49];
            t2 = (Bits.RotateRight32(h, 2) ^ Bits.RotateRight32(h, 13) ^ (h >> 22) ^ (h << 10)) +
                 ((h & a) ^ (h & b) ^ (a & b));
            g = t + t2;
            c += t;
            t = f + (Bits.RotateRight32(c, 6) ^ Bits.RotateRight32(c, 11)
                                              ^ Bits.RotateRight32(c, 25)) + ((c & d) ^ (~c & e)) +
                0x2748774C + buffer[50];
            t2 = (Bits.RotateRight32(g, 2) ^ Bits.RotateRight32(g, 13) ^ (g >> 22) ^ (g << 10)) +
                 ((g & h) ^ (g & a) ^ (h & a));
            f = t + t2;
            b += t;
            t = e + (Bits.RotateRight32(b, 6) ^ Bits.RotateRight32(b, 11)
                                              ^ Bits.RotateRight32(b, 25)) + ((b & c) ^ (~b & d)) +
                0x34B0BCB5 + buffer[51];
            t2 = (Bits.RotateRight32(f, 2) ^ Bits.RotateRight32(f, 13) ^ (f >> 22) ^ (f << 10)) +
                 ((f & g) ^ (f & h) ^ (g & h));
            e = t + t2;
            a += t;
            t = d + (Bits.RotateRight32(a, 6) ^ Bits.RotateRight32(a, 11)
                                              ^ Bits.RotateRight32(a, 25)) + ((a & b) ^ (~a & c)) +
                0x391C0CB3 + buffer[52];
            t2 = (Bits.RotateRight32(e, 2) ^ Bits.RotateRight32(e, 13) ^ (e >> 22) ^ (e << 10)) +
                 ((e & f) ^ (e & g) ^ (f & g));
            d = t + t2;
            h += t;
            t = c + (Bits.RotateRight32(h, 6) ^ Bits.RotateRight32(h, 11)
                                              ^ Bits.RotateRight32(h, 25)) + ((h & a) ^ (~h & b)) +
                0x4ED8AA4A + buffer[53];
            t2 = (Bits.RotateRight32(d, 2) ^ Bits.RotateRight32(d, 13) ^ (d >> 22) ^ (d << 10)) +
                 ((d & e) ^ (d & f) ^ (e & f));
            c = t + t2;
            g += t;
            t = b + (Bits.RotateRight32(g, 6) ^ Bits.RotateRight32(g, 11)
                                              ^ Bits.RotateRight32(g, 25)) + ((g & h) ^ (~g & a)) +
                0x5B9CCA4F + buffer[54];
            t2 = (Bits.RotateRight32(c, 2) ^ Bits.RotateRight32(c, 13) ^ (c >> 22) ^ (c << 10)) +
                 ((c & d) ^ (c & e) ^ (d & e));
            b = t + t2;
            f += t;
            t = a + (Bits.RotateRight32(f, 6) ^ Bits.RotateRight32(f, 11)
                                              ^ Bits.RotateRight32(f, 25)) + ((f & g) ^ (~f & h)) +
                0x682E6FF3 + buffer[55];
            t2 = (Bits.RotateRight32(b, 2) ^ Bits.RotateRight32(b, 13) ^ (b >> 22) ^ (b << 10)) +
                 ((b & c) ^ (b & d) ^ (c & d));
            a = t + t2;
            e += t;
            t = h + (Bits.RotateRight32(e, 6) ^ Bits.RotateRight32(e, 11)
                                              ^ Bits.RotateRight32(e, 25)) + ((e & f) ^ (~e & g)) +
                0x748F82EE + buffer[56];
            t2 = (Bits.RotateRight32(a, 2) ^ Bits.RotateRight32(a, 13) ^ (a >> 22) ^ (a << 10)) +
                 ((a & b) ^ (a & c) ^ (b & c));
            h = t + t2;
            d += t;
            t = g + (Bits.RotateRight32(d, 6) ^ Bits.RotateRight32(d, 11)
                                              ^ Bits.RotateRight32(d, 25)) + ((d & e) ^ (~d & f)) +
                0x78A5636F + buffer[57];
            t2 = (Bits.RotateRight32(h, 2) ^ Bits.RotateRight32(h, 13) ^ (h >> 22) ^ (h << 10)) +
                 ((h & a) ^ (h & b) ^ (a & b));
            g = t + t2;
            c += t;
            t = f + (Bits.RotateRight32(c, 6) ^ Bits.RotateRight32(c, 11)
                                              ^ Bits.RotateRight32(c, 25)) + ((c & d) ^ (~c & e)) +
                0x84C87814 + buffer[58];
            t2 = (Bits.RotateRight32(g, 2) ^ Bits.RotateRight32(g, 13) ^ (g >> 22) ^ (g << 10)) +
                 ((g & h) ^ (g & a) ^ (h & a));
            f = t + t2;
            b += t;
            t = e + (Bits.RotateRight32(b, 6) ^ Bits.RotateRight32(b, 11)
                                              ^ Bits.RotateRight32(b, 25)) + ((b & c) ^ (~b & d)) +
                0x8CC70208 + buffer[59];
            t2 = (Bits.RotateRight32(f, 2) ^ Bits.RotateRight32(f, 13) ^ (f >> 22) ^ (f << 10)) +
                 ((f & g) ^ (f & h) ^ (g & h));
            e = t + t2;
            a += t;
            t = d + (Bits.RotateRight32(a, 6) ^ Bits.RotateRight32(a, 11)
                                              ^ Bits.RotateRight32(a, 25)) + ((a & b) ^ (~a & c)) +
                0x90BEFFFA + buffer[60];
            t2 = (Bits.RotateRight32(e, 2) ^ Bits.RotateRight32(e, 13) ^ (e >> 22) ^ (e << 10)) +
                 ((e & f) ^ (e & g) ^ (f & g));
            d = t + t2;
            h += t;
            t = c + (Bits.RotateRight32(h, 6) ^ Bits.RotateRight32(h, 11)
                                              ^ Bits.RotateRight32(h, 25)) + ((h & a) ^ (~h & b)) +
                0xA4506CEB + buffer[61];
            t2 = (Bits.RotateRight32(d, 2) ^ Bits.RotateRight32(d, 13) ^ (d >> 22) ^ (d << 10)) +
                 ((d & e) ^ (d & f) ^ (e & f));
            c = t + t2;
            g += t;
            t = b + (Bits.RotateRight32(g, 6) ^ Bits.RotateRight32(g, 11)
                                              ^ Bits.RotateRight32(g, 25)) + ((g & h) ^ (~g & a)) +
                0xBEF9A3F7 + buffer[62];
            t2 = (Bits.RotateRight32(c, 2) ^ Bits.RotateRight32(c, 13) ^ (c >> 22) ^ (c << 10)) +
                 ((c & d) ^ (c & e) ^ (d & e));
            b = t + t2;
            f += t;
            t = a + (Bits.RotateRight32(f, 6) ^ Bits.RotateRight32(f, 11)
                                              ^ Bits.RotateRight32(f, 25)) + ((f & g) ^ (~f & h)) +
                0xC67178F2 + buffer[63];
            t2 = (Bits.RotateRight32(b, 2) ^ Bits.RotateRight32(b, 13) ^ (b >> 22) ^ (b << 10)) +
                 ((b & c) ^ (b & d) ^ (c & d));
            a = t + t2;
            e += t;

            State[0] = State[0] + a;
            State[1] = State[1] + b;
            State[2] = State[2] + c;
            State[3] = State[3] + d;
            State[4] = State[4] + e;
            State[5] = State[5] + f;
            State[6] = State[6] + g;
            State[7] = State[7] + h;
        }
    }
}