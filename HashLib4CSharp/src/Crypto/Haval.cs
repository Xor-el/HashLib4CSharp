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
using HashLib4CSharp.Enum;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal abstract class Haval : BlockHash, ICryptoNotBuiltIn, ITransformBlock
    {
        protected int Rounds;
        protected uint[] State;

        private const int HavalVersion = 1;

        protected Haval(HashRounds rounds, HashSize hashSize)
            : base((int)hashSize, 128)
        {
            Rounds = (int)rounds;
            State = new uint[8];
        }

        public override void Initialize()
        {
            State[0] = 0x243F6A88;
            State[1] = 0x85A308D3;
            State[2] = 0x13198A2E;
            State[3] = 0x03707344;
            State[4] = 0xA4093822;
            State[5] = 0x299F31D0;
            State[6] = 0x082EFA98;
            State[7] = 0xEC4E6C89;

            base.Initialize();
        }

        protected override unsafe byte[] GetResult()
        {
            TailorDigestBits();

            var result = new byte[HashSize];

            fixed (uint* statePtr = State)
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
            var padIndex = Buffer.Position < 118 ? 118 - Buffer.Position : 246 - Buffer.Position;

            Span<byte> pad = stackalloc byte[padIndex + 10];

            pad[0] = 0x01;

            pad[padIndex] = (byte)((Rounds << 3) | (HavalVersion & 0x07));
            padIndex++;
            pad[padIndex] = (byte)(HashSize << 1);
            padIndex++;

            bits = Converters.le2me_64(bits);

            Converters.ReadUInt64AsBytesLE(bits, pad.Slice(padIndex));

            padIndex += 8;

            TransformByteSpan(pad.Slice(0, padIndex));
        }

        private void TailorDigestBits()
        {
            uint t;

            switch (HashSize)
            {
                case 16:
                    t = (State[7] & 0x000000FF) | (State[6] & 0xFF000000) |
                        (State[5] & 0x00FF0000) | (State[4] & 0x0000FF00);
                    State[0] = State[0] + Bits.RotateRight32(t, 8);
                    t = (State[7] & 0x0000FF00) | (State[6] & 0x000000FF) |
                        (State[5] & 0xFF000000) | (State[4] & 0x00FF0000);
                    State[1] = State[1] + Bits.RotateRight32(t, 16);
                    t = (State[7] & 0x00FF0000) | (State[6] & 0x0000FF00) |
                        (State[5] & 0x000000FF) | (State[4] & 0xFF000000);
                    State[2] = State[2] + Bits.RotateRight32(t, 24);
                    t = (State[7] & 0xFF000000) | (State[6] & 0x00FF0000) |
                        (State[5] & 0x0000FF00) | (State[4] & 0x000000FF);
                    State[3] = State[3] + t;
                    break;
                case 20:
                    t = State[7] & 0x3F | (uint)(State[6] & (0x7F << 25))
                                        | State[5] & (0x3F << 19);
                    State[0] = State[0] + Bits.RotateRight32(t, 19);
                    t = State[7] & (0x3F << 6) | State[6] & 0x3F |
                        (uint)(State[5] & (0x7F << 25));
                    State[1] = State[1] + Bits.RotateRight32(t, 25);
                    t = (State[7] & (0x7F << 12)) | (State[6] & (0x3F << 6)) |
                        (State[5] & 0x3F);
                    State[2] = State[2] + t;
                    t = (State[7] & (0x3F << 19)) | (State[6] & (0x7F << 12)) |
                        (State[5] & (0x3F << 6));
                    State[3] = State[3] + (t >> 6);
                    t = (State[7] & ((uint)(0x7F) << 25)) |
                        State[6] & (0x3F << 19) |
                        State[5] & (0x7F << 12);
                    State[4] = State[4] + (t >> 12);
                    break;
                case 24:
                    t = State[7] & 0x1F | (uint)(State[6] & (0x3F << 26));
                    State[0] = State[0] + Bits.RotateRight32(t, 26);
                    t = (State[7] & (0x1F << 5)) | (State[6] & 0x1F);
                    State[1] = State[1] + t;
                    t = (State[7] & (0x3F << 10)) | (State[6] & (0x1F << 5));
                    State[2] = State[2] + (t >> 5);
                    t = (State[7] & (0x1F << 16)) | (State[6] & (0x3F << 10));
                    State[3] = State[3] + (t >> 10);
                    t = (State[7] & (0x1F << 21)) | (State[6] & (0x1F << 16));
                    State[4] = State[4] + (t >> 16);
                    t = (uint)(State[7] & (0x3F << 26)) |
                        State[6] & (0x1F << 21);
                    State[5] = State[5] + (t >> 21);
                    break;
                case 28:
                    State[0] = State[0] + ((State[7] >> 27) & 0x1F);
                    State[1] = State[1] + ((State[7] >> 22) & 0x1F);
                    State[2] = State[2] + ((State[7] >> 18) & 0x0F);
                    State[3] = State[3] + ((State[7] >> 13) & 0x1F);
                    State[4] = State[4] + ((State[7] >> 9) & 0x0F);
                    State[5] = State[5] + ((State[7] >> 4) & 0x1F);
                    State[6] = State[6] + (State[7] & 0x0F);
                    break;
            }
        }
    }

    internal abstract class Haval3 : Haval
    {
        protected Haval3(HashSize hashSize)
            : base(HashRounds.Rounds3, hashSize)
        {
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = stackalloc uint[32];

            Converters.le32_copy(data, index, buffer, 0, dataLength);

            var a = State[0];
            var b = State[1];
            var c = State[2];
            var d = State[3];
            var e = State[4];
            var f = State[5];
            var g = State[6];
            var h = State[7];

            var t = c & (e ^ d) ^ g & a ^ f & b ^ e;
            h = buffer[0] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = b & (d ^ c) ^ f & h ^ e & a ^ d;
            g = buffer[1] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = a & (c ^ b) ^ e & g ^ d & h ^ c;
            f = buffer[2] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = h & (b ^ a) ^ d & f ^ c & g ^ b;
            e = buffer[3] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = g & (a ^ h) ^ c & e ^ b & f ^ a;
            d = buffer[4] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = f & (h ^ g) ^ b & d ^ a & e ^ h;
            c = buffer[5] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = e & (g ^ f) ^ a & c ^ h & d ^ g;
            b = buffer[6] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = d & (f ^ e) ^ h & b ^ g & c ^ f;
            a = buffer[7] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = c & (e ^ d) ^ g & a ^ f & b ^ e;
            h = buffer[8] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = b & (d ^ c) ^ f & h ^ e & a ^ d;
            g = buffer[9] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = a & (c ^ b) ^ e & g ^ d & h ^ c;
            f = buffer[10] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = h & (b ^ a) ^ d & f ^ c & g ^ b;
            e = buffer[11] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = g & (a ^ h) ^ c & e ^ b & f ^ a;
            d = buffer[12] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = f & (h ^ g) ^ b & d ^ a & e ^ h;
            c = buffer[13] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = e & (g ^ f) ^ a & c ^ h & d ^ g;
            b = buffer[14] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = d & (f ^ e) ^ h & b ^ g & c ^ f;
            a = buffer[15] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = c & (e ^ d) ^ g & a ^ f & b ^ e;
            h = buffer[16] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = b & (d ^ c) ^ f & h ^ e & a ^ d;
            g = buffer[17] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = a & (c ^ b) ^ e & g ^ d & h ^ c;
            f = buffer[18] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = h & (b ^ a) ^ d & f ^ c & g ^ b;
            e = buffer[19] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = g & (a ^ h) ^ c & e ^ b & f ^ a;
            d = buffer[20] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = f & (h ^ g) ^ b & d ^ a & e ^ h;
            c = buffer[21] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = e & (g ^ f) ^ a & c ^ h & d ^ g;
            b = buffer[22] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = d & (f ^ e) ^ h & b ^ g & c ^ f;
            a = buffer[23] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = c & (e ^ d) ^ g & a ^ f & b ^ e;
            h = buffer[24] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = b & (d ^ c) ^ f & h ^ e & a ^ d;
            g = buffer[25] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = a & (c ^ b) ^ e & g ^ d & h ^ c;
            f = buffer[26] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = h & (b ^ a) ^ d & f ^ c & g ^ b;
            e = buffer[27] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = g & (a ^ h) ^ c & e ^ b & f ^ a;
            d = buffer[28] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = f & (h ^ g) ^ b & d ^ a & e ^ h;
            c = buffer[29] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = e & (g ^ f) ^ a & c ^ h & d ^ g;
            b = buffer[30] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = d & (f ^ e) ^ h & b ^ g & c ^ f;
            a = buffer[31] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = f & (d & ~a ^ b & c ^ e ^ g) ^ b & (d ^ c)
                                             ^ a & c ^ g;
            h = buffer[5] + 0x452821E6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = e & (c & ~h ^ a & b ^ d ^ f) ^ a & (c ^ b)
                                             ^ h & b ^ f;
            g = buffer[14] + 0x38D01377 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = d & (b & ~g ^ h & a ^ c ^ e) ^ h & (b ^ a)
                                             ^ g & a ^ e;
            f = buffer[26] + 0xBE5466CF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = c & (a & ~f ^ g & h ^ b ^ d) ^ g & (a ^ h)
                                             ^ f & h ^ d;
            e = buffer[18] + 0x34E90C6C + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = b & (h & ~e ^ f & g ^ a ^ c) ^ f & (h ^ g)
                                             ^ e & g ^ c;
            d = buffer[11] + 0xC0AC29B7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = a & (g & ~d ^ e & f ^ h ^ b) ^ e & (g ^ f)
                                             ^ d & f ^ b;
            c = buffer[28] + 0xC97C50DD + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = h & (f & ~c ^ d & e ^ g ^ a) ^ d & (f ^ e)
                                             ^ c & e ^ a;
            b = buffer[7] + 0x3F84D5B5 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = g & (e & ~b ^ c & d ^ f ^ h) ^ c & (e ^ d)
                                             ^ b & d ^ h;
            a = buffer[16] + 0xB5470917 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = f & (d & ~a ^ b & c ^ e ^ g) ^ b & (d ^ c)
                                             ^ a & c ^ g;
            h = buffer[0] + 0x9216D5D9 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = e & (c & ~h ^ a & b ^ d ^ f) ^ a & (c ^ b)
                                             ^ h & b ^ f;
            g = buffer[23] + 0x8979FB1B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = d & (b & ~g ^ h & a ^ c ^ e) ^ h & (b ^ a)
                                             ^ g & a ^ e;
            f = buffer[20] + 0xD1310BA6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = c & (a & ~f ^ g & h ^ b ^ d) ^ g & (a ^ h)
                                             ^ f & h ^ d;
            e = buffer[22] + 0x98DFB5AC + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = b & (h & ~e ^ f & g ^ a ^ c) ^ f & (h ^ g)
                                             ^ e & g ^ c;
            d = buffer[1] + 0x2FFD72DB + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = a & (g & ~d ^ e & f ^ h ^ b) ^ e & (g ^ f)
                                             ^ d & f ^ b;
            c = buffer[10] + 0xD01ADFB7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = h & (f & ~c ^ d & e ^ g ^ a) ^ d & (f ^ e)
                                             ^ c & e ^ a;
            b = buffer[4] + 0xB8E1AFED + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = g & (e & ~b ^ c & d ^ f ^ h) ^ c & (e ^ d)
                                             ^ b & d ^ h;
            a = buffer[8] + 0x6A267E96 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = f & (d & ~a ^ b & c ^ e ^ g) ^ b & (d ^ c)
                                             ^ a & c ^ g;
            h = buffer[30] + 0xBA7C9045 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = e & (c & ~h ^ a & b ^ d ^ f) ^ a & (c ^ b)
                                             ^ h & b ^ f;
            g = buffer[3] + 0xF12C7F99 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = d & (b & ~g ^ h & a ^ c ^ e) ^ h & (b ^ a)
                                             ^ g & a ^ e;
            f = buffer[21] + 0x24A19947 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = c & (a & ~f ^ g & h ^ b ^ d) ^ g & (a ^ h)
                                             ^ f & h ^ d;
            e = buffer[9] + 0xB3916CF7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = b & (h & ~e ^ f & g ^ a ^ c) ^ f & (h ^ g)
                                             ^ e & g ^ c;
            d = buffer[17] + 0x0801F2E2 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = a & (g & ~d ^ e & f ^ h ^ b) ^ e & (g ^ f)
                                             ^ d & f ^ b;
            c = buffer[24] + 0x858EFC16 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = h & (f & ~c ^ d & e ^ g ^ a) ^ d & (f ^ e)
                                             ^ c & e ^ a;
            b = buffer[29] + 0x636920D8 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = g & (e & ~b ^ c & d ^ f ^ h) ^ c & (e ^ d)
                                             ^ b & d ^ h;
            a = buffer[6] + 0x71574E69 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = f & (d & ~a ^ b & c ^ e ^ g) ^ b & (d ^ c)
                                             ^ a & c ^ g;
            h = buffer[19] + 0xA458FEA3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = e & (c & ~h ^ a & b ^ d ^ f) ^ a & (c ^ b)
                                             ^ h & b ^ f;
            g = buffer[12] + 0xF4933D7E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = d & (b & ~g ^ h & a ^ c ^ e) ^ h & (b ^ a)
                                             ^ g & a ^ e;
            f = buffer[15] + 0x0D95748F + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = c & (a & ~f ^ g & h ^ b ^ d) ^ g & (a ^ h)
                                             ^ f & h ^ d;
            e = buffer[13] + 0x728EB658 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = b & (h & ~e ^ f & g ^ a ^ c) ^ f & (h ^ g)
                                             ^ e & g ^ c;
            d = buffer[2] + 0x718BCD58 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = a & (g & ~d ^ e & f ^ h ^ b) ^ e & (g ^ f)
                                             ^ d & f ^ b;
            c = buffer[25] + 0x82154AEE + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = h & (f & ~c ^ d & e ^ g ^ a) ^ d & (f ^ e)
                                             ^ c & e ^ a;
            b = buffer[31] + 0x7B54A41D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = g & (e & ~b ^ c & d ^ f ^ h) ^ c & (e ^ d)
                                             ^ b & d ^ h;
            a = buffer[27] + 0xC25A59B5 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (f & e ^ g ^ a) ^ f & c ^ e & b ^ a;
            h = buffer[19] + 0x9C30D539 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (e & d ^ f ^ h) ^ e & b ^ d & a ^ h;
            g = buffer[9] + 0x2AF26013 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (d & c ^ e ^ g) ^ d & a ^ c & h ^ g;
            f = buffer[4] + 0xC5D1B023 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (c & b ^ d ^ f) ^ c & h ^ b & g ^ f;
            e = buffer[20] + 0x286085F0 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (b & a ^ c ^ e) ^ b & g ^ a & f ^ e;
            d = buffer[28] + 0xCA417918 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (a & h ^ b ^ d) ^ a & f ^ h & e ^ d;
            c = buffer[17] + 0xB8DB38EF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (h & g ^ a ^ c) ^ h & e ^ g & d ^ c;
            b = buffer[8] + 0x8E79DCB0 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (g & f ^ h ^ b) ^ g & d ^ f & c ^ b;
            a = buffer[22] + 0x603A180E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (f & e ^ g ^ a) ^ f & c ^ e & b ^ a;
            h = buffer[29] + 0x6C9E0E8B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (e & d ^ f ^ h) ^ e & b ^ d & a ^ h;
            g = buffer[14] + 0xB01E8A3E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (d & c ^ e ^ g) ^ d & a ^ c & h ^ g;
            f = buffer[25] + 0xD71577C1 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (c & b ^ d ^ f) ^ c & h ^ b & g ^ f;
            e = buffer[12] + 0xBD314B27 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (b & a ^ c ^ e) ^ b & g ^ a & f ^ e;
            d = buffer[24] + 0x78AF2FDA + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (a & h ^ b ^ d) ^ a & f ^ h & e ^ d;
            c = buffer[30] + 0x55605C60 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (h & g ^ a ^ c) ^ h & e ^ g & d ^ c;
            b = buffer[16] + 0xE65525F3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (g & f ^ h ^ b) ^ g & d ^ f & c ^ b;
            a = buffer[26] + 0xAA55AB94 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (f & e ^ g ^ a) ^ f & c ^ e & b ^ a;
            h = buffer[31] + 0x57489862 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (e & d ^ f ^ h) ^ e & b ^ d & a ^ h;
            g = buffer[15] + 0x63E81440 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (d & c ^ e ^ g) ^ d & a ^ c & h ^ g;
            f = buffer[7] + 0x55CA396A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (c & b ^ d ^ f) ^ c & h ^ b & g ^ f;
            e = buffer[3] + 0x2AAB10B6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (b & a ^ c ^ e) ^ b & g ^ a & f ^ e;
            d = buffer[1] + 0xB4CC5C34 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (a & h ^ b ^ d) ^ a & f ^ h & e ^ d;
            c = buffer[0] + 0x1141E8CE + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (h & g ^ a ^ c) ^ h & e ^ g & d ^ c;
            b = buffer[18] + 0xA15486AF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (g & f ^ h ^ b) ^ g & d ^ f & c ^ b;
            a = buffer[27] + 0x7C72E993 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (f & e ^ g ^ a) ^ f & c ^ e & b ^ a;
            h = buffer[13] + 0xB3EE1411 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (e & d ^ f ^ h) ^ e & b ^ d & a ^ h;
            g = buffer[6] + 0x636FBC2A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (d & c ^ e ^ g) ^ d & a ^ c & h ^ g;
            f = buffer[21] + 0x2BA9C55D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (c & b ^ d ^ f) ^ c & h ^ b & g ^ f;
            e = buffer[10] + 0x741831F6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (b & a ^ c ^ e) ^ b & g ^ a & f ^ e;
            d = buffer[23] + 0xCE5C3E16 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (a & h ^ b ^ d) ^ a & f ^ h & e ^ d;
            c = buffer[11] + 0x9B87931E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (h & g ^ a ^ c) ^ h & e ^ g & d ^ c;
            b = buffer[5] + 0xAFD6BA33 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (g & f ^ h ^ b) ^ g & d ^ f & c ^ b;
            a = buffer[2] + 0x6C24CF5C + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

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

    internal abstract class Haval4 : Haval
    {
        protected Haval4(HashSize hashSize)
            : base(HashRounds.Rounds4, hashSize)
        {
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = new uint[32];

            fixed (uint* bufferPtr = buffer)
            {
                Converters.le32_copy(data, index, bufferPtr, 0, dataLength);
            }

            var a = State[0];
            var b = State[1];
            var c = State[2];
            var d = State[3];
            var e = State[4];
            var f = State[5];
            var g = State[6];
            var h = State[7];

            var t = d & (a ^ b) ^ f & g ^ e & c ^ a;
            h = buffer[0] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = c & (h ^ a) ^ e & f ^ d & b ^ h;
            g = buffer[1] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = b & (g ^ h) ^ d & e ^ c & a ^ g;
            f = buffer[2] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = a & (f ^ g) ^ c & d ^ b & h ^ f;
            e = buffer[3] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = h & (e ^ f) ^ b & c ^ a & g ^ e;
            d = buffer[4] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = g & (d ^ e) ^ a & b ^ h & f ^ d;
            c = buffer[5] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = f & (c ^ d) ^ h & a ^ g & e ^ c;
            b = buffer[6] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = e & (b ^ c) ^ g & h ^ f & d ^ b;
            a = buffer[7] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = d & (a ^ b) ^ f & g ^ e & c ^ a;
            h = buffer[8] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = c & (h ^ a) ^ e & f ^ d & b ^ h;
            g = buffer[9] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = b & (g ^ h) ^ d & e ^ c & a ^ g;
            f = buffer[10] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = a & (f ^ g) ^ c & d ^ b & h ^ f;
            e = buffer[11] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = h & (e ^ f) ^ b & c ^ a & g ^ e;
            d = buffer[12] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = g & (d ^ e) ^ a & b ^ h & f ^ d;
            c = buffer[13] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = f & (c ^ d) ^ h & a ^ g & e ^ c;
            b = buffer[14] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = e & (b ^ c) ^ g & h ^ f & d ^ b;
            a = buffer[15] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = d & (a ^ b) ^ f & g ^ e & c ^ a;
            h = buffer[16] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = c & (h ^ a) ^ e & f ^ d & b ^ h;
            g = buffer[17] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = b & (g ^ h) ^ d & e ^ c & a ^ g;
            f = buffer[18] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = a & (f ^ g) ^ c & d ^ b & h ^ f;
            e = buffer[19] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = h & (e ^ f) ^ b & c ^ a & g ^ e;
            d = buffer[20] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = g & (d ^ e) ^ a & b ^ h & f ^ d;
            c = buffer[21] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = f & (c ^ d) ^ h & a ^ g & e ^ c;
            b = buffer[22] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = e & (b ^ c) ^ g & h ^ f & d ^ b;
            a = buffer[23] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = d & (a ^ b) ^ f & g ^ e & c ^ a;
            h = buffer[24] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = c & (h ^ a) ^ e & f ^ d & b ^ h;
            g = buffer[25] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = b & (g ^ h) ^ d & e ^ c & a ^ g;
            f = buffer[26] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = a & (f ^ g) ^ c & d ^ b & h ^ f;
            e = buffer[27] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = h & (e ^ f) ^ b & c ^ a & g ^ e;
            d = buffer[28] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = g & (d ^ e) ^ a & b ^ h & f ^ d;
            c = buffer[29] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = f & (c ^ d) ^ h & a ^ g & e ^ c;
            b = buffer[30] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = e & (b ^ c) ^ g & h ^ f & d ^ b;
            a = buffer[31] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = b & (g & ~a ^ c & f ^ d ^ e) ^ c & (g ^ f)
                                             ^ a & f ^ e;
            h = buffer[5] + 0x452821E6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = a & (f & ~h ^ b & e ^ c ^ d) ^ b & (f ^ e)
                                             ^ h & e ^ d;
            g = buffer[14] + 0x38D01377 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = h & (e & ~g ^ a & d ^ b ^ c) ^ a & (e ^ d)
                                             ^ g & d ^ c;
            f = buffer[26] + 0xBE5466CF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = g & (d & ~f ^ h & c ^ a ^ b) ^ h & (d ^ c)
                                             ^ f & c ^ b;
            e = buffer[18] + 0x34E90C6C + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = f & (c & ~e ^ g & b ^ h ^ a) ^ g & (c ^ b)
                                             ^ e & b ^ a;
            d = buffer[11] + 0xC0AC29B7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = e & (b & ~d ^ f & a ^ g ^ h) ^ f & (b ^ a)
                                             ^ d & a ^ h;
            c = buffer[28] + 0xC97C50DD + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = d & (a & ~c ^ e & h ^ f ^ g) ^ e & (a ^ h)
                                             ^ c & h ^ g;
            b = buffer[7] + 0x3F84D5B5 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = c & (h & ~b ^ d & g ^ e ^ f) ^ d & (h ^ g)
                                             ^ b & g ^ f;
            a = buffer[16] + 0xB5470917 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = b & (g & ~a ^ c & f ^ d ^ e) ^ c & (g ^ f)
                                             ^ a & f ^ e;
            h = buffer[0] + 0x9216D5D9 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = a & (f & ~h ^ b & e ^ c ^ d) ^ b & (f ^ e)
                                             ^ h & e ^ d;
            g = buffer[23] + 0x8979FB1B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = h & (e & ~g ^ a & d ^ b ^ c) ^ a & (e ^ d)
                                             ^ g & d ^ c;
            f = buffer[20] + 0xD1310BA6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = g & (d & ~f ^ h & c ^ a ^ b) ^ h & (d ^ c)
                                             ^ f & c ^ b;
            e = buffer[22] + 0x98DFB5AC + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = f & (c & ~e ^ g & b ^ h ^ a) ^ g & (c ^ b)
                                             ^ e & b ^ a;
            d = buffer[1] + 0x2FFD72DB + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = e & (b & ~d ^ f & a ^ g ^ h) ^ f & (b ^ a)
                                             ^ d & a ^ h;
            c = buffer[10] + 0xD01ADFB7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = d & (a & ~c ^ e & h ^ f ^ g) ^ e & (a ^ h)
                                             ^ c & h ^ g;
            b = buffer[4] + 0xB8E1AFED + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = c & (h & ~b ^ d & g ^ e ^ f) ^ d & (h ^ g)
                                             ^ b & g ^ f;
            a = buffer[8] + 0x6A267E96 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = b & (g & ~a ^ c & f ^ d ^ e) ^ c & (g ^ f)
                                             ^ a & f ^ e;
            h = buffer[30] + 0xBA7C9045 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = a & (f & ~h ^ b & e ^ c ^ d) ^ b & (f ^ e)
                                             ^ h & e ^ d;
            g = buffer[3] + 0xF12C7F99 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = h & (e & ~g ^ a & d ^ b ^ c) ^ a & (e ^ d)
                                             ^ g & d ^ c;
            f = buffer[21] + 0x24A19947 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = g & (d & ~f ^ h & c ^ a ^ b) ^ h & (d ^ c)
                                             ^ f & c ^ b;
            e = buffer[9] + 0xB3916CF7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = f & (c & ~e ^ g & b ^ h ^ a) ^ g & (c ^ b)
                                             ^ e & b ^ a;
            d = buffer[17] + 0x0801F2E2 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = e & (b & ~d ^ f & a ^ g ^ h) ^ f & (b ^ a)
                                             ^ d & a ^ h;
            c = buffer[24] + 0x858EFC16 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = d & (a & ~c ^ e & h ^ f ^ g) ^ e & (a ^ h)
                                             ^ c & h ^ g;
            b = buffer[29] + 0x636920D8 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = c & (h & ~b ^ d & g ^ e ^ f) ^ d & (h ^ g)
                                             ^ b & g ^ f;
            a = buffer[6] + 0x71574E69 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = b & (g & ~a ^ c & f ^ d ^ e) ^ c & (g ^ f)
                                             ^ a & f ^ e;
            h = buffer[19] + 0xA458FEA3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = a & (f & ~h ^ b & e ^ c ^ d) ^ b & (f ^ e)
                                             ^ h & e ^ d;
            g = buffer[12] + 0xF4933D7E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = h & (e & ~g ^ a & d ^ b ^ c) ^ a & (e ^ d)
                                             ^ g & d ^ c;
            f = buffer[15] + 0x0D95748F + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = g & (d & ~f ^ h & c ^ a ^ b) ^ h & (d ^ c)
                                             ^ f & c ^ b;
            e = buffer[13] + 0x728EB658 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = f & (c & ~e ^ g & b ^ h ^ a) ^ g & (c ^ b)
                                             ^ e & b ^ a;
            d = buffer[2] + 0x718BCD58 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = e & (b & ~d ^ f & a ^ g ^ h) ^ f & (b ^ a)
                                             ^ d & a ^ h;
            c = buffer[25] + 0x82154AEE + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = d & (a & ~c ^ e & h ^ f ^ g) ^ e & (a ^ h)
                                             ^ c & h ^ g;
            b = buffer[31] + 0x7B54A41D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = c & (h & ~b ^ d & g ^ e ^ f) ^ d & (h ^ g)
                                             ^ b & g ^ f;
            a = buffer[27] + 0xC25A59B5 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = g & (c & a ^ b ^ f) ^ c & d ^ a & e ^ f;
            h = buffer[19] + 0x9C30D539 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = f & (b & h ^ a ^ e) ^ b & c ^ h & d ^ e;
            g = buffer[9] + 0x2AF26013 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = e & (a & g ^ h ^ d) ^ a & b ^ g & c ^ d;
            f = buffer[4] + 0xC5D1B023 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = d & (h & f ^ g ^ c) ^ h & a ^ f & b ^ c;
            e = buffer[20] + 0x286085F0 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = c & (g & e ^ f ^ b) ^ g & h ^ e & a ^ b;
            d = buffer[28] + 0xCA417918 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = b & (f & d ^ e ^ a) ^ f & g ^ d & h ^ a;
            c = buffer[17] + 0xB8DB38EF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = a & (e & c ^ d ^ h) ^ e & f ^ c & g ^ h;
            b = buffer[8] + 0x8E79DCB0 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = h & (d & b ^ c ^ g) ^ d & e ^ b & f ^ g;
            a = buffer[22] + 0x603A180E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = g & (c & a ^ b ^ f) ^ c & d ^ a & e ^ f;
            h = buffer[29] + 0x6C9E0E8B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = f & (b & h ^ a ^ e) ^ b & c ^ h & d ^ e;
            g = buffer[14] + 0xB01E8A3E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = e & (a & g ^ h ^ d) ^ a & b ^ g & c ^ d;
            f = buffer[25] + 0xD71577C1 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = d & (h & f ^ g ^ c) ^ h & a ^ f & b ^ c;
            e = buffer[12] + 0xBD314B27 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = c & (g & e ^ f ^ b) ^ g & h ^ e & a ^ b;
            d = buffer[24] + 0x78AF2FDA + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = b & (f & d ^ e ^ a) ^ f & g ^ d & h ^ a;
            c = buffer[30] + 0x55605C60 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = a & (e & c ^ d ^ h) ^ e & f ^ c & g ^ h;
            b = buffer[16] + 0xE65525F3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = h & (d & b ^ c ^ g) ^ d & e ^ b & f ^ g;
            a = buffer[26] + 0xAA55AB94 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = g & (c & a ^ b ^ f) ^ c & d ^ a & e ^ f;
            h = buffer[31] + 0x57489862 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = f & (b & h ^ a ^ e) ^ b & c ^ h & d ^ e;
            g = buffer[15] + 0x63E81440 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = e & (a & g ^ h ^ d) ^ a & b ^ g & c ^ d;
            f = buffer[7] + 0x55CA396A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = d & (h & f ^ g ^ c) ^ h & a ^ f & b ^ c;
            e = buffer[3] + 0x2AAB10B6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = c & (g & e ^ f ^ b) ^ g & h ^ e & a ^ b;
            d = buffer[1] + 0xB4CC5C34 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = b & (f & d ^ e ^ a) ^ f & g ^ d & h ^ a;
            c = buffer[0] + 0x1141E8CE + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = a & (e & c ^ d ^ h) ^ e & f ^ c & g ^ h;
            b = buffer[18] + 0xA15486AF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = h & (d & b ^ c ^ g) ^ d & e ^ b & f ^ g;
            a = buffer[27] + 0x7C72E993 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = g & (c & a ^ b ^ f) ^ c & d ^ a & e ^ f;
            h = buffer[13] + 0xB3EE1411 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = f & (b & h ^ a ^ e) ^ b & c ^ h & d ^ e;
            g = buffer[6] + 0x636FBC2A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = e & (a & g ^ h ^ d) ^ a & b ^ g & c ^ d;
            f = buffer[21] + 0x2BA9C55D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = d & (h & f ^ g ^ c) ^ h & a ^ f & b ^ c;
            e = buffer[10] + 0x741831F6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = c & (g & e ^ f ^ b) ^ g & h ^ e & a ^ b;
            d = buffer[23] + 0xCE5C3E16 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = b & (f & d ^ e ^ a) ^ f & g ^ d & h ^ a;
            c = buffer[11] + 0x9B87931E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = a & (e & c ^ d ^ h) ^ e & f ^ c & g ^ h;
            b = buffer[5] + 0xAFD6BA33 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = h & (d & b ^ c ^ g) ^ d & e ^ b & f ^ g;
            a = buffer[2] + 0x6C24CF5C + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = a & (e & ~c ^ f & ~g ^ b ^ g ^ d) ^ f &
                (b & c ^ e ^ g) ^ c & g ^ d;
            h = buffer[24] + 0x7A325381 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = h & (d & ~b ^ e & ~f ^ a ^ f ^ c) ^ e &
                (a & b ^ d ^ f) ^ b & f ^ c;
            g = buffer[4] + 0x28958677 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = g & (c & ~a ^ d & ~e ^ h ^ e ^ b) ^ d &
                (h & a ^ c ^ e) ^ a & e ^ b;
            f = buffer[0] + 0x3B8F4898 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = f & (b & ~h ^ c & ~d ^ g ^ d ^ a) ^ c &
                (g & h ^ b ^ d) ^ h & d ^ a;
            e = buffer[14] + 0x6B4BB9AF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = e & (a & ~g ^ b & ~c ^ f ^ c ^ h) ^ b &
                (f & g ^ a ^ c) ^ g & c ^ h;
            d = buffer[2] + 0xC4BFE81B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = d & (h & ~f ^ a & ~b ^ e ^ b ^ g) ^ a &
                (e & f ^ h ^ b) ^ f & b ^ g;
            c = buffer[7] + 0x66282193 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = c & (g & ~e ^ h & ~a ^ d ^ a ^ f) ^ h &
                (d & e ^ g ^ a) ^ e & a ^ f;
            b = buffer[28] + 0x61D809CC + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = b & (f & ~d ^ g & ~h ^ c ^ h ^ e) ^ g &
                (c & d ^ f ^ h) ^ d & h ^ e;
            a = buffer[23] + 0xFB21A991 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = a & (e & ~c ^ f & ~g ^ b ^ g ^ d) ^ f &
                (b & c ^ e ^ g) ^ c & g ^ d;
            h = buffer[26] + 0x487CAC60 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = h & (d & ~b ^ e & ~f ^ a ^ f ^ c) ^ e &
                (a & b ^ d ^ f) ^ b & f ^ c;
            g = buffer[6] + 0x5DEC8032 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = g & (c & ~a ^ d & ~e ^ h ^ e ^ b) ^ d &
                (h & a ^ c ^ e) ^ a & e ^ b;
            f = buffer[30] + 0xEF845D5D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = f & (b & ~h ^ c & ~d ^ g ^ d ^ a) ^ c &
                (g & h ^ b ^ d) ^ h & d ^ a;
            e = buffer[20] + 0xE98575B1 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = e & (a & ~g ^ b & ~c ^ f ^ c ^ h) ^ b &
                (f & g ^ a ^ c) ^ g & c ^ h;
            d = buffer[18] + 0xDC262302 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = d & (h & ~f ^ a & ~b ^ e ^ b ^ g) ^ a &
                (e & f ^ h ^ b) ^ f & b ^ g;
            c = buffer[25] + 0xEB651B88 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = c & (g & ~e ^ h & ~a ^ d ^ a ^ f) ^ h &
                (d & e ^ g ^ a) ^ e & a ^ f;
            b = buffer[19] + 0x23893E81 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = b & (f & ~d ^ g & ~h ^ c ^ h ^ e) ^ g &
                (c & d ^ f ^ h) ^ d & h ^ e;
            a = buffer[3] + 0xD396ACC5 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = a & (e & ~c ^ f & ~g ^ b ^ g ^ d) ^ f &
                (b & c ^ e ^ g) ^ c & g ^ d;
            h = buffer[22] + 0x0F6D6FF3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = h & (d & ~b ^ e & ~f ^ a ^ f ^ c) ^ e &
                (a & b ^ d ^ f) ^ b & f ^ c;
            g = buffer[11] + 0x83F44239 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = g & (c & ~a ^ d & ~e ^ h ^ e ^ b) ^ d &
                (h & a ^ c ^ e) ^ a & e ^ b;
            f = buffer[31] + 0x2E0B4482 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = f & (b & ~h ^ c & ~d ^ g ^ d ^ a) ^ c &
                (g & h ^ b ^ d) ^ h & d ^ a;
            e = buffer[21] + 0xA4842004 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = e & (a & ~g ^ b & ~c ^ f ^ c ^ h) ^ b &
                (f & g ^ a ^ c) ^ g & c ^ h;
            d = buffer[8] + 0x69C8F04A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = d & (h & ~f ^ a & ~b ^ e ^ b ^ g) ^ a &
                (e & f ^ h ^ b) ^ f & b ^ g;
            c = buffer[27] + 0x9E1F9B5E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = c & (g & ~e ^ h & ~a ^ d ^ a ^ f) ^ h &
                (d & e ^ g ^ a) ^ e & a ^ f;
            b = buffer[12] + 0x21C66842 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = b & (f & ~d ^ g & ~h ^ c ^ h ^ e) ^ g &
                (c & d ^ f ^ h) ^ d & h ^ e;
            a = buffer[9] + 0xF6E96C9A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = a & (e & ~c ^ f & ~g ^ b ^ g ^ d) ^ f &
                (b & c ^ e ^ g) ^ c & g ^ d;
            h = buffer[1] + 0x670C9C61 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = h & (d & ~b ^ e & ~f ^ a ^ f ^ c) ^ e &
                (a & b ^ d ^ f) ^ b & f ^ c;
            g = buffer[29] + 0xABD388F0 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = g & (c & ~a ^ d & ~e ^ h ^ e ^ b) ^ d &
                (h & a ^ c ^ e) ^ a & e ^ b;
            f = buffer[5] + 0x6A51A0D2 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = f & (b & ~h ^ c & ~d ^ g ^ d ^ a) ^ c &
                (g & h ^ b ^ d) ^ h & d ^ a;
            e = buffer[15] + 0xD8542F68 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = e & (a & ~g ^ b & ~c ^ f ^ c ^ h) ^ b &
                (f & g ^ a ^ c) ^ g & c ^ h;
            d = buffer[17] + 0x960FA728 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = d & (h & ~f ^ a & ~b ^ e ^ b ^ g) ^ a &
                (e & f ^ h ^ b) ^ f & b ^ g;
            c = buffer[10] + 0xAB5133A3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = c & (g & ~e ^ h & ~a ^ d ^ a ^ f) ^ h &
                (d & e ^ g ^ a) ^ e & a ^ f;
            b = buffer[16] + 0x6EEF0B6C + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = b & (f & ~d ^ g & ~h ^ c ^ h ^ e) ^ g &
                (c & d ^ f ^ h) ^ d & h ^ e;
            a = buffer[13] + 0x137A3BE4 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            State[0] = State[0] + a;
            State[1] = State[1] + b;
            State[2] = State[2] + c;
            State[3] = State[3] + d;
            State[4] = State[4] + e;
            State[5] = State[5] + f;
            State[6] = State[6] + g;
            State[7] = State[7] + h;

            ArrayUtils.ZeroFill(buffer);
        }
    }

    internal abstract class Haval5 : Haval
    {
        protected Haval5(HashSize hashSize)
            : base(HashRounds.Rounds5, hashSize)
        {
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = new uint[32];

            fixed (uint* bufferPtr = buffer)
            {
                Converters.le32_copy(data, index, bufferPtr, 0, dataLength);
            }

            var a = State[0];
            var b = State[1];
            var c = State[2];
            var d = State[3];
            var e = State[4];
            var f = State[5];
            var g = State[6];
            var h = State[7];

            var t = c & (g ^ b) ^ f & e ^ a & d ^ g;
            h = buffer[0] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);
            t = b & (f ^ a) ^ e & d ^ h & c ^ f;
            g = buffer[1] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = a & (e ^ h) ^ d & c ^ g & b ^ e;
            f = buffer[2] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = h & (d ^ g) ^ c & b ^ f & a ^ d;
            e = buffer[3] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = g & (c ^ f) ^ b & a ^ e & h ^ c;
            d = buffer[4] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = f & (b ^ e) ^ a & h ^ d & g ^ b;
            c = buffer[5] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = e & (a ^ d) ^ h & g ^ c & f ^ a;
            b = buffer[6] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = d & (h ^ c) ^ g & f ^ b & e ^ h;
            a = buffer[7] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = c & (g ^ b) ^ f & e ^ a & d ^ g;
            h = buffer[8] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = b & (f ^ a) ^ e & d ^ h & c ^ f;
            g = buffer[9] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = a & (e ^ h) ^ d & c ^ g & b ^ e;
            f = buffer[10] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = h & (d ^ g) ^ c & b ^ f & a ^ d;
            e = buffer[11] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = g & (c ^ f) ^ b & a ^ e & h ^ c;
            d = buffer[12] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = f & (b ^ e) ^ a & h ^ d & g ^ b;
            c = buffer[13] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = e & (a ^ d) ^ h & g ^ c & f ^ a;
            b = buffer[14] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = d & (h ^ c) ^ g & f ^ b & e ^ h;
            a = buffer[15] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = c & (g ^ b) ^ f & e ^ a & d ^ g;
            h = buffer[16] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = b & (f ^ a) ^ e & d ^ h & c ^ f;
            g = buffer[17] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = a & (e ^ h) ^ d & c ^ g & b ^ e;
            f = buffer[18] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = h & (d ^ g) ^ c & b ^ f & a ^ d;
            e = buffer[19] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = g & (c ^ f) ^ b & a ^ e & h ^ c;
            d = buffer[20] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = f & (b ^ e) ^ a & h ^ d & g ^ b;
            c = buffer[21] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = e & (a ^ d) ^ h & g ^ c & f ^ a;
            b = buffer[22] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = d & (h ^ c) ^ g & f ^ b & e ^ h;
            a = buffer[23] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = c & (g ^ b) ^ f & e ^ a & d ^ g;
            h = buffer[24] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(h, 11);

            t = b & (f ^ a) ^ e & d ^ h & c ^ f;
            g = buffer[25] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(g, 11);

            t = a & (e ^ h) ^ d & c ^ g & b ^ e;
            f = buffer[26] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(f, 11);

            t = h & (d ^ g) ^ c & b ^ f & a ^ d;
            e = buffer[27] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(e, 11);

            t = g & (c ^ f) ^ b & a ^ e & h ^ c;
            d = buffer[28] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(d, 11);

            t = f & (b ^ e) ^ a & h ^ d & g ^ b;
            c = buffer[29] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(c, 11);

            t = e & (a ^ d) ^ h & g ^ c & f ^ a;
            b = buffer[30] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(b, 11);

            t = d & (h ^ c) ^ g & f ^ b & e ^ h;
            a = buffer[31] + Bits.RotateRight32(t, 7) + Bits.RotateRight32(a, 11);

            t = d & (e & ~a ^ b & c ^ g ^ f) ^ b & (e ^ c)
                                             ^ a & c ^ f;
            h = buffer[5] + 0x452821E6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (d & ~h ^ a & b ^ f ^ e) ^ a & (d ^ b)
                                             ^ h & b ^ e;
            g = buffer[14] + 0x38D01377 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (c & ~g ^ h & a ^ e ^ d) ^ h & (c ^ a)
                                             ^ g & a ^ d;
            f = buffer[26] + 0xBE5466CF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (b & ~f ^ g & h ^ d ^ c) ^ g & (b ^ h)
                                             ^ f & h ^ c;
            e = buffer[18] + 0x34E90C6C + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (a & ~e ^ f & g ^ c ^ b) ^ f & (a ^ g)
                                             ^ e & g ^ b;
            d = buffer[11] + 0xC0AC29B7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (h & ~d ^ e & f ^ b ^ a) ^ e & (h ^ f)
                                             ^ d & f ^ a;
            c = buffer[28] + 0xC97C50DD + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (g & ~c ^ d & e ^ a ^ h) ^ d & (g ^ e)
                                             ^ c & e ^ h;
            b = buffer[7] + 0x3F84D5B5 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (f & ~b ^ c & d ^ h ^ g) ^ c & (f ^ d)
                                             ^ b & d ^ g;
            a = buffer[16] + 0xB5470917 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (e & ~a ^ b & c ^ g ^ f) ^ b & (e ^ c)
                                             ^ a & c ^ f;
            h = buffer[0] + 0x9216D5D9 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (d & ~h ^ a & b ^ f ^ e) ^ a & (d ^ b)
                                             ^ h & b ^ e;
            g = buffer[23] + 0x8979FB1B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (c & ~g ^ h & a ^ e ^ d) ^ h & (c ^ a)
                                             ^ g & a ^ d;
            f = buffer[20] + 0xD1310BA6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (b & ~f ^ g & h ^ d ^ c) ^ g & (b ^ h)
                                             ^ f & h ^ c;
            e = buffer[22] + 0x98DFB5AC + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (a & ~e ^ f & g ^ c ^ b) ^ f & (a ^ g)
                                             ^ e & g ^ b;
            d = buffer[1] + 0x2FFD72DB + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (h & ~d ^ e & f ^ b ^ a) ^ e & (h ^ f)
                                             ^ d & f ^ a;
            c = buffer[10] + 0xD01ADFB7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (g & ~c ^ d & e ^ a ^ h) ^ d & (g ^ e)
                                             ^ c & e ^ h;
            b = buffer[4] + 0xB8E1AFED + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (f & ~b ^ c & d ^ h ^ g) ^ c & (f ^ d)
                                             ^ b & d ^ g;
            a = buffer[8] + 0x6A267E96 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (e & ~a ^ b & c ^ g ^ f) ^ b & (e ^ c)
                                             ^ a & c ^ f;
            h = buffer[30] + 0xBA7C9045 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (d & ~h ^ a & b ^ f ^ e) ^ a & (d ^ b)
                                             ^ h & b ^ e;
            g = buffer[3] + 0xF12C7F99 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (c & ~g ^ h & a ^ e ^ d) ^ h & (c ^ a)
                                             ^ g & a ^ d;
            f = buffer[21] + 0x24A19947 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (b & ~f ^ g & h ^ d ^ c) ^ g & (b ^ h)
                                             ^ f & h ^ c;
            e = buffer[9] + 0xB3916CF7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (a & ~e ^ f & g ^ c ^ b) ^ f & (a ^ g)
                                             ^ e & g ^ b;
            d = buffer[17] + 0x0801F2E2 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (h & ~d ^ e & f ^ b ^ a) ^ e & (h ^ f)
                                             ^ d & f ^ a;
            c = buffer[24] + 0x858EFC16 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (g & ~c ^ d & e ^ a ^ h) ^ d & (g ^ e)
                                             ^ c & e ^ h;
            b = buffer[29] + 0x636920D8 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (f & ~b ^ c & d ^ h ^ g) ^ c & (f ^ d)
                                             ^ b & d ^ g;
            a = buffer[6] + 0x71574E69 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (e & ~a ^ b & c ^ g ^ f) ^ b & (e ^ c)
                                             ^ a & c ^ f;
            h = buffer[19] + 0xA458FEA3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (d & ~h ^ a & b ^ f ^ e) ^ a & (d ^ b)
                                             ^ h & b ^ e;
            g = buffer[12] + 0xF4933D7E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (c & ~g ^ h & a ^ e ^ d) ^ h & (c ^ a)
                                             ^ g & a ^ d;
            f = buffer[15] + 0x0D95748F + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (b & ~f ^ g & h ^ d ^ c) ^ g & (b ^ h)
                                             ^ f & h ^ c;
            e = buffer[13] + 0x728EB658 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (a & ~e ^ f & g ^ c ^ b) ^ f & (a ^ g)
                                             ^ e & g ^ b;
            d = buffer[2] + 0x718BCD58 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (h & ~d ^ e & f ^ b ^ a) ^ e & (h ^ f)
                                             ^ d & f ^ a;
            c = buffer[25] + 0x82154AEE + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (g & ~c ^ d & e ^ a ^ h) ^ d & (g ^ e)
                                             ^ c & e ^ h;
            b = buffer[31] + 0x7B54A41D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (f & ~b ^ c & d ^ h ^ g) ^ c & (f ^ d)
                                             ^ b & d ^ g;
            a = buffer[27] + 0xC25A59B5 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = e & (b & d ^ c ^ f) ^ b & a ^ d & g ^ f;
            h = buffer[19] + 0x9C30D539 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = d & (a & c ^ b ^ e) ^ a & h ^ c & f ^ e;
            g = buffer[9] + 0x2AF26013 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = c & (h & b ^ a ^ d) ^ h & g ^ b & e ^ d;
            f = buffer[4] + 0xC5D1B023 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = b & (g & a ^ h ^ c) ^ g & f ^ a & d ^ c;
            e = buffer[20] + 0x286085F0 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = a & (f & h ^ g ^ b) ^ f & e ^ h & c ^ b;
            d = buffer[28] + 0xCA417918 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = h & (e & g ^ f ^ a) ^ e & d ^ g & b ^ a;
            c = buffer[17] + 0xB8DB38EF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = g & (d & f ^ e ^ h) ^ d & c ^ f & a ^ h;
            b = buffer[8] + 0x8E79DCB0 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = f & (c & e ^ d ^ g) ^ c & b ^ e & h ^ g;
            a = buffer[22] + 0x603A180E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = e & (b & d ^ c ^ f) ^ b & a ^ d & g ^ f;
            h = buffer[29] + 0x6C9E0E8B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = d & (a & c ^ b ^ e) ^ a & h ^ c & f ^ e;
            g = buffer[14] + 0xB01E8A3E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = c & (h & b ^ a ^ d) ^ h & g ^ b & e ^ d;
            f = buffer[25] + 0xD71577C1 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = b & (g & a ^ h ^ c) ^ g & f ^ a & d ^ c;
            e = buffer[12] + 0xBD314B27 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = a & (f & h ^ g ^ b) ^ f & e ^ h & c ^ b;
            d = buffer[24] + 0x78AF2FDA + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = h & (e & g ^ f ^ a) ^ e & d ^ g & b ^ a;
            c = buffer[30] + 0x55605C60 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = g & (d & f ^ e ^ h) ^ d & c ^ f & a ^ h;
            b = buffer[16] + 0xE65525F3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = f & (c & e ^ d ^ g) ^ c & b ^ e & h ^ g;
            a = buffer[26] + 0xAA55AB94 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = e & (b & d ^ c ^ f) ^ b & a ^ d & g ^ f;
            h = buffer[31] + 0x57489862 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = d & (a & c ^ b ^ e) ^ a & h ^ c & f ^ e;
            g = buffer[15] + 0x63E81440 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = c & (h & b ^ a ^ d) ^ h & g ^ b & e ^ d;
            f = buffer[7] + 0x55CA396A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = b & (g & a ^ h ^ c) ^ g & f ^ a & d ^ c;
            e = buffer[3] + 0x2AAB10B6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = a & (f & h ^ g ^ b) ^ f & e ^ h & c ^ b;
            d = buffer[1] + 0xB4CC5C34 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = h & (e & g ^ f ^ a) ^ e & d ^ g & b ^ a;
            c = buffer[0] + 0x1141E8CE + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = g & (d & f ^ e ^ h) ^ d & c ^ f & a ^ h;
            b = buffer[18] + 0xA15486AF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = f & (c & e ^ d ^ g) ^ c & b ^ e & h ^ g;
            a = buffer[27] + 0x7C72E993 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = e & (b & d ^ c ^ f) ^ b & a ^ d & g ^ f;
            h = buffer[13] + 0xB3EE1411 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = d & (a & c ^ b ^ e) ^ a & h ^ c & f ^ e;
            g = buffer[6] + 0x636FBC2A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = c & (h & b ^ a ^ d) ^ h & g ^ b & e ^ d;
            f = buffer[21] + 0x2BA9C55D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = b & (g & a ^ h ^ c) ^ g & f ^ a & d ^ c;
            e = buffer[10] + 0x741831F6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = a & (f & h ^ g ^ b) ^ f & e ^ h & c ^ b;
            d = buffer[23] + 0xCE5C3E16 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = h & (e & g ^ f ^ a) ^ e & d ^ g & b ^ a;
            c = buffer[11] + 0x9B87931E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = g & (d & f ^ e ^ h) ^ d & c ^ f & a ^ h;
            b = buffer[5] + 0xAFD6BA33 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = f & (c & e ^ d ^ g) ^ c & b ^ e & h ^ g;
            a = buffer[2] + 0x6C24CF5C + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (f & ~a ^ c & ~b ^ e ^ b ^ g) ^ c &
                (e & a ^ f ^ b) ^ a & b ^ g;
            h = buffer[24] + 0x7A325381 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (e & ~h ^ b & ~a ^ d ^ a ^ f) ^ b &
                (d & h ^ e ^ a) ^ h & a ^ f;
            g = buffer[4] + 0x28958677 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (d & ~g ^ a & ~h ^ c ^ h ^ e) ^ a &
                (c & g ^ d ^ h) ^ g & h ^ e;
            f = buffer[0] + 0x3B8F4898 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (c & ~f ^ h & ~g ^ b ^ g ^ d) ^ h &
                (b & f ^ c ^ g) ^ f & g ^ d;
            e = buffer[14] + 0x6B4BB9AF + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (b & ~e ^ g & ~f ^ a ^ f ^ c) ^ g &
                (a & e ^ b ^ f) ^ e & f ^ c;
            d = buffer[2] + 0xC4BFE81B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (a & ~d ^ f & ~e ^ h ^ e ^ b) ^ f &
                (h & d ^ a ^ e) ^ d & e ^ b;
            c = buffer[7] + 0x66282193 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (h & ~c ^ e & ~d ^ g ^ d ^ a) ^ e &
                (g & c ^ h ^ d) ^ c & d ^ a;
            b = buffer[28] + 0x61D809CC + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (g & ~b ^ d & ~c ^ f ^ c ^ h) ^ d &
                (f & b ^ g ^ c) ^ b & c ^ h;
            a = buffer[23] + 0xFB21A991 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (f & ~a ^ c & ~b ^ e ^ b ^ g) ^ c &
                (e & a ^ f ^ b) ^ a & b ^ g;
            h = buffer[26] + 0x487CAC60 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (e & ~h ^ b & ~a ^ d ^ a ^ f) ^ b &
                (d & h ^ e ^ a) ^ h & a ^ f;
            g = buffer[6] + 0x5DEC8032 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (d & ~g ^ a & ~h ^ c ^ h ^ e) ^ a &
                (c & g ^ d ^ h) ^ g & h ^ e;
            f = buffer[30] + 0xEF845D5D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (c & ~f ^ h & ~g ^ b ^ g ^ d) ^ h &
                (b & f ^ c ^ g) ^ f & g ^ d;
            e = buffer[20] + 0xE98575B1 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (b & ~e ^ g & ~f ^ a ^ f ^ c) ^ g &
                (a & e ^ b ^ f) ^ e & f ^ c;
            d = buffer[18] + 0xDC262302 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (a & ~d ^ f & ~e ^ h ^ e ^ b) ^ f &
                (h & d ^ a ^ e) ^ d & e ^ b;
            c = buffer[25] + 0xEB651B88 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (h & ~c ^ e & ~d ^ g ^ d ^ a) ^ e &
                (g & c ^ h ^ d) ^ c & d ^ a;
            b = buffer[19] + 0x23893E81 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (g & ~b ^ d & ~c ^ f ^ c ^ h) ^ d &
                (f & b ^ g ^ c) ^ b & c ^ h;
            a = buffer[3] + 0xD396ACC5 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (f & ~a ^ c & ~b ^ e ^ b ^ g) ^ c &
                (e & a ^ f ^ b) ^ a & b ^ g;
            h = buffer[22] + 0x0F6D6FF3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (e & ~h ^ b & ~a ^ d ^ a ^ f) ^ b &
                (d & h ^ e ^ a) ^ h & a ^ f;
            g = buffer[11] + 0x83F44239 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (d & ~g ^ a & ~h ^ c ^ h ^ e) ^ a &
                (c & g ^ d ^ h) ^ g & h ^ e;
            f = buffer[31] + 0x2E0B4482 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (c & ~f ^ h & ~g ^ b ^ g ^ d) ^ h &
                (b & f ^ c ^ g) ^ f & g ^ d;
            e = buffer[21] + 0xA4842004 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (b & ~e ^ g & ~f ^ a ^ f ^ c) ^ g &
                (a & e ^ b ^ f) ^ e & f ^ c;
            d = buffer[8] + 0x69C8F04A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (a & ~d ^ f & ~e ^ h ^ e ^ b) ^ f &
                (h & d ^ a ^ e) ^ d & e ^ b;
            c = buffer[27] + 0x9E1F9B5E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (h & ~c ^ e & ~d ^ g ^ d ^ a) ^ e &
                (g & c ^ h ^ d) ^ c & d ^ a;
            b = buffer[12] + 0x21C66842 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (g & ~b ^ d & ~c ^ f ^ c ^ h) ^ d &
                (f & b ^ g ^ c) ^ b & c ^ h;
            a = buffer[9] + 0xF6E96C9A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = d & (f & ~a ^ c & ~b ^ e ^ b ^ g) ^ c &
                (e & a ^ f ^ b) ^ a & b ^ g;
            h = buffer[1] + 0x670C9C61 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = c & (e & ~h ^ b & ~a ^ d ^ a ^ f) ^ b &
                (d & h ^ e ^ a) ^ h & a ^ f;
            g = buffer[29] + 0xABD388F0 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = b & (d & ~g ^ a & ~h ^ c ^ h ^ e) ^ a &
                (c & g ^ d ^ h) ^ g & h ^ e;
            f = buffer[5] + 0x6A51A0D2 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = a & (c & ~f ^ h & ~g ^ b ^ g ^ d) ^ h &
                (b & f ^ c ^ g) ^ f & g ^ d;
            e = buffer[15] + 0xD8542F68 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = h & (b & ~e ^ g & ~f ^ a ^ f ^ c) ^ g &
                (a & e ^ b ^ f) ^ e & f ^ c;
            d = buffer[17] + 0x960FA728 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = g & (a & ~d ^ f & ~e ^ h ^ e ^ b) ^ f &
                (h & d ^ a ^ e) ^ d & e ^ b;
            c = buffer[10] + 0xAB5133A3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = f & (h & ~c ^ e & ~d ^ g ^ d ^ a) ^ e &
                (g & c ^ h ^ d) ^ c & d ^ a;
            b = buffer[16] + 0x6EEF0B6C + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = e & (g & ~b ^ d & ~c ^ f ^ c ^ h) ^ d &
                (f & b ^ g ^ c) ^ b & c ^ h;
            a = buffer[13] + 0x137A3BE4 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = b & (d & e & g ^ ~f) ^ d & a ^ e & f ^ g & c;
            h = buffer[27] + 0xBA3BF050 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = a & (c & d & f ^ ~e) ^ c & h ^ d & e ^ f & b;
            g = buffer[3] + 0x7EFB2A98 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = h & (b & c & e ^ ~d) ^ b & g ^ c & d ^ e & a;
            f = buffer[21] + 0xA1F1651D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = g & (a & b & d ^ ~c) ^ a & f ^ b & c ^ d & h;
            e = buffer[26] + 0x39AF0176 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = f & (h & a & c ^ ~b) ^ h & e ^ a & b ^ c & g;
            d = buffer[17] + 0x66CA593E + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = e & (g & h & b ^ ~a) ^ g & d ^ h & a ^ b & f;
            c = buffer[11] + 0x82430E88 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = d & (f & g & a ^ ~h) ^ f & c ^ g & h ^ a & e;
            b = buffer[20] + 0x8CEE8619 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = c & (e & f & h ^ ~g) ^ e & b ^ f & g ^ h & d;
            a = buffer[29] + 0x456F9FB4 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = b & (d & e & g ^ ~f) ^ d & a ^ e & f ^ g & c;
            h = buffer[19] + 0x7D84A5C3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = a & (c & d & f ^ ~e) ^ c & h ^ d & e ^ f & b;
            g = buffer[0] + 0x3B8B5EBE + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = h & (b & c & e ^ ~d) ^ b & g ^ c & d ^ e & a;
            f = buffer[12] + 0xE06F75D8 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = g & (a & b & d ^ ~c) ^ a & f ^ b & c ^ d & h;
            e = buffer[7] + 0x85C12073 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = f & (h & a & c ^ ~b) ^ h & e ^ a & b ^ c & g;
            d = buffer[13] + 0x401A449F + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = e & (g & h & b ^ ~a) ^ g & d ^ h & a ^ b & f;
            c = buffer[8] + 0x56C16AA6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = d & (f & g & a ^ ~h) ^ f & c ^ g & h ^ a & e;
            b = buffer[31] + 0x4ED3AA62 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = c & (e & f & h ^ ~g) ^ e & b ^ f & g ^ h & d;
            a = buffer[10] + 0x363F7706 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = b & (d & e & g ^ ~f) ^ d & a ^ e & f ^ g & c;
            h = buffer[5] + 0x1BFEDF72 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = a & (c & d & f ^ ~e) ^ c & h ^ d & e ^ f & b;
            g = buffer[9] + 0x429B023D + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = h & (b & c & e ^ ~d) ^ b & g ^ c & d ^ e & a;
            f = buffer[14] + 0x37D0D724 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = g & (a & b & d ^ ~c) ^ a & f ^ b & c ^ d & h;
            e = buffer[30] + 0xD00A1248 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = f & (h & a & c ^ ~b) ^ h & e ^ a & b ^ c & g;
            d = buffer[18] + 0xDB0FEAD3 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = e & (g & h & b ^ ~a) ^ g & d ^ h & a ^ b & f;
            c = buffer[6] + 0x49F1C09B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = d & (f & g & a ^ ~h) ^ f & c ^ g & h ^ a & e;
            b = buffer[28] + 0x075372C9 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = c & (e & f & h ^ ~g) ^ e & b ^ f & g ^ h & d;
            a = buffer[24] + 0x80991B7B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            t = b & (d & e & g ^ ~f) ^ d & a ^ e & f ^ g & c;
            h = buffer[2] + 0x25D479D8 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(h, 11);

            t = a & (c & d & f ^ ~e) ^ c & h ^ d & e ^ f & b;
            g = buffer[23] + 0xF6E8DEF7 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(g, 11);

            t = h & (b & c & e ^ ~d) ^ b & g ^ c & d ^ e & a;
            f = buffer[16] + 0xE3FE501A + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(f, 11);

            t = g & (a & b & d ^ ~c) ^ a & f ^ b & c ^ d & h;
            e = buffer[22] + 0xB6794C3B + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(e, 11);

            t = f & (h & a & c ^ ~b) ^ h & e ^ a & b ^ c & g;
            d = buffer[4] + 0x976CE0BD + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(d, 11);

            t = e & (g & h & b ^ ~a) ^ g & d ^ h & a ^ b & f;
            c = buffer[1] + 0x04C006BA + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(c, 11);

            t = d & (f & g & a ^ ~h) ^ f & c ^ g & h ^ a & e;
            b = buffer[25] + 0xC1A94FB6 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(b, 11);

            t = c & (e & f & h ^ ~g) ^ e & b ^ f & g ^ h & d;
            a = buffer[15] + 0x409F60C4 + Bits.RotateRight32(t, 7) +
                Bits.RotateRight32(a, 11);

            State[0] = State[0] + a;
            State[1] = State[1] + b;
            State[2] = State[2] + c;
            State[3] = State[3] + d;
            State[4] = State[4] + e;
            State[5] = State[5] + f;
            State[6] = State[6] + g;
            State[7] = State[7] + h;

            ArrayUtils.ZeroFill(buffer);
        }
    }

    internal sealed class Haval_3_128 : Haval3
    {
        internal Haval_3_128()
            : base(Enum.HashSize.HashSize128)
        {
        }

        public override IHash Clone() =>
            new Haval_3_128
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_4_128 : Haval4
    {
        internal Haval_4_128()
            : base(Enum.HashSize.HashSize128)
        {
        }

        public override IHash Clone() =>
            new Haval_4_128
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_5_128 : Haval5
    {
        internal Haval_5_128()
            : base(Enum.HashSize.HashSize128)
        {
        }

        public override IHash Clone() =>
            new Haval_5_128
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_3_160 : Haval3
    {
        internal Haval_3_160()
            : base(Enum.HashSize.HashSize160)
        {
        }

        public override IHash Clone() =>
            new Haval_3_160
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_4_160 : Haval4
    {
        internal Haval_4_160()
            : base(Enum.HashSize.HashSize160)
        {
        }

        public override IHash Clone() =>
            new Haval_4_160
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_5_160 : Haval5
    {
        internal Haval_5_160()
            : base(Enum.HashSize.HashSize160)
        {
        }

        public override IHash Clone() =>
            new Haval_5_160
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_3_192 : Haval3
    {
        internal Haval_3_192()
            : base(Enum.HashSize.HashSize192)
        {
        }

        public override IHash Clone() =>
            new Haval_3_192
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_4_192 : Haval4
    {
        internal Haval_4_192()
            : base(Enum.HashSize.HashSize192)
        {
        }

        public override IHash Clone() =>
            new Haval_4_192
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_5_192 : Haval5
    {
        internal Haval_5_192()
            : base(Enum.HashSize.HashSize192)
        {
        }

        public override IHash Clone() =>
            new Haval_5_192
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_3_224 : Haval3
    {
        internal Haval_3_224()
            : base(Enum.HashSize.HashSize224)
        {
        }

        public override IHash Clone() =>
            new Haval_3_224
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_4_224 : Haval4
    {
        internal Haval_4_224()
            : base(Enum.HashSize.HashSize224)
        {
        }

        public override IHash Clone() =>
            new Haval_4_224
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_5_224 : Haval5
    {
        internal Haval_5_224()
            : base(Enum.HashSize.HashSize224)
        {
        }

        public override IHash Clone() =>
            new Haval_5_224
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_3_256 : Haval3
    {
        internal Haval_3_256()
            : base(Enum.HashSize.HashSize256)
        {
        }

        public override IHash Clone() =>
            new Haval_3_256
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_4_256 : Haval4
    {
        internal Haval_4_256()
            : base(Enum.HashSize.HashSize256)
        {
        }

        public override IHash Clone() =>
            new Haval_4_256
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }

    internal sealed class Haval_5_256 : Haval5
    {
        internal Haval_5_256()
            : base(Enum.HashSize.HashSize256)
        {
        }

        public override IHash Clone() =>
            new Haval_5_256
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize,
                Rounds = Rounds
            };
    }
}