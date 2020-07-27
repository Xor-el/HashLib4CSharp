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

using System.Runtime.CompilerServices;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class RIPEMD : MDBase, ITransformBlock
    {
        internal RIPEMD()
            : base(4, 16)
        {
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint P1(uint a, uint b, uint c) => (a & b) | (~a & c);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint P2(uint a, uint b, uint c) => (a & b) | (a & c) | (b & c);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint P3(uint a, uint b, uint c) => a ^ b ^ c;

        public override IHash Clone() =>
            new RIPEMD
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = stackalloc uint[16];

            Converters.le32_copy(data, index, buffer, 0, dataLength);

            var a = State[0];
            var b = State[1];
            var c = State[2];
            var d = State[3];
            var aa = a;
            var bb = b;
            var cc = c;
            var dd = d;

            a = Bits.RotateLeft32(P1(b, c, d) + a + buffer[0], 11);
            d = Bits.RotateLeft32(P1(a, b, c) + d + buffer[1], 14);
            c = Bits.RotateLeft32(P1(d, a, b) + c + buffer[2], 15);
            b = Bits.RotateLeft32(P1(c, d, a) + b + buffer[3], 12);
            a = Bits.RotateLeft32(P1(b, c, d) + a + buffer[4], 5);
            d = Bits.RotateLeft32(P1(a, b, c) + d + buffer[5], 8);
            c = Bits.RotateLeft32(P1(d, a, b) + c + buffer[6], 7);
            b = Bits.RotateLeft32(P1(c, d, a) + b + buffer[7], 9);
            a = Bits.RotateLeft32(P1(b, c, d) + a + buffer[8], 11);
            d = Bits.RotateLeft32(P1(a, b, c) + d + buffer[9], 13);
            c = Bits.RotateLeft32(P1(d, a, b) + c + buffer[10], 14);
            b = Bits.RotateLeft32(P1(c, d, a) + b + buffer[11], 15);
            a = Bits.RotateLeft32(P1(b, c, d) + a + buffer[12], 6);
            d = Bits.RotateLeft32(P1(a, b, c) + d + buffer[13], 7);
            c = Bits.RotateLeft32(P1(d, a, b) + c + buffer[14], 9);
            b = Bits.RotateLeft32(P1(c, d, a) + b + buffer[15], 8);

            a = Bits.RotateLeft32(P2(b, c, d) + a + buffer[7] + C2, 7);
            d = Bits.RotateLeft32(P2(a, b, c) + d + buffer[4] + C2, 6);
            c = Bits.RotateLeft32(P2(d, a, b) + c + buffer[13] + C2, 8);
            b = Bits.RotateLeft32(P2(c, d, a) + b + buffer[1] + C2, 13);
            a = Bits.RotateLeft32(P2(b, c, d) + a + buffer[10] + C2, 11);
            d = Bits.RotateLeft32(P2(a, b, c) + d + buffer[6] + C2, 9);
            c = Bits.RotateLeft32(P2(d, a, b) + c + buffer[15] + C2, 7);
            b = Bits.RotateLeft32(P2(c, d, a) + b + buffer[3] + C2, 15);
            a = Bits.RotateLeft32(P2(b, c, d) + a + buffer[12] + C2, 7);
            d = Bits.RotateLeft32(P2(a, b, c) + d + buffer[0] + C2, 12);
            c = Bits.RotateLeft32(P2(d, a, b) + c + buffer[9] + C2, 15);
            b = Bits.RotateLeft32(P2(c, d, a) + b + buffer[5] + C2, 9);
            a = Bits.RotateLeft32(P2(b, c, d) + a + buffer[14] + C2, 7);
            d = Bits.RotateLeft32(P2(a, b, c) + d + buffer[2] + C2, 11);
            c = Bits.RotateLeft32(P2(d, a, b) + c + buffer[11] + C2, 13);
            b = Bits.RotateLeft32(P2(c, d, a) + b + buffer[8] + C2, 12);

            a = Bits.RotateLeft32(P3(b, c, d) + a + buffer[3] + C4, 11);
            d = Bits.RotateLeft32(P3(a, b, c) + d + buffer[10] + C4, 13);
            c = Bits.RotateLeft32(P3(d, a, b) + c + buffer[2] + C4, 14);
            b = Bits.RotateLeft32(P3(c, d, a) + b + buffer[4] + C4, 7);
            a = Bits.RotateLeft32(P3(b, c, d) + a + buffer[9] + C4, 14);
            d = Bits.RotateLeft32(P3(a, b, c) + d + buffer[15] + C4, 9);
            c = Bits.RotateLeft32(P3(d, a, b) + c + buffer[8] + C4, 13);
            b = Bits.RotateLeft32(P3(c, d, a) + b + buffer[1] + C4, 15);
            a = Bits.RotateLeft32(P3(b, c, d) + a + buffer[14] + C4, 6);
            d = Bits.RotateLeft32(P3(a, b, c) + d + buffer[7] + C4, 8);
            c = Bits.RotateLeft32(P3(d, a, b) + c + buffer[0] + C4, 13);
            b = Bits.RotateLeft32(P3(c, d, a) + b + buffer[6] + C4, 6);
            a = Bits.RotateLeft32(P3(b, c, d) + a + buffer[11] + C4, 12);
            d = Bits.RotateLeft32(P3(a, b, c) + d + buffer[13] + C4, 5);
            c = Bits.RotateLeft32(P3(d, a, b) + c + buffer[5] + C4, 7);
            b = Bits.RotateLeft32(P3(c, d, a) + b + buffer[12] + C4, 5);

            aa = Bits.RotateLeft32(P1(bb, cc, dd) + aa + buffer[0] + C1, 11);
            dd = Bits.RotateLeft32(P1(aa, bb, cc) + dd + buffer[1] + C1, 14);
            cc = Bits.RotateLeft32(P1(dd, aa, bb) + cc + buffer[2] + C1, 15);
            bb = Bits.RotateLeft32(P1(cc, dd, aa) + bb + buffer[3] + C1, 12);
            aa = Bits.RotateLeft32(P1(bb, cc, dd) + aa + buffer[4] + C1, 5);
            dd = Bits.RotateLeft32(P1(aa, bb, cc) + dd + buffer[5] + C1, 8);
            cc = Bits.RotateLeft32(P1(dd, aa, bb) + cc + buffer[6] + C1, 7);
            bb = Bits.RotateLeft32(P1(cc, dd, aa) + bb + buffer[7] + C1, 9);
            aa = Bits.RotateLeft32(P1(bb, cc, dd) + aa + buffer[8] + C1, 11);
            dd = Bits.RotateLeft32(P1(aa, bb, cc) + dd + buffer[9] + C1, 13);
            cc = Bits.RotateLeft32(P1(dd, aa, bb) + cc + buffer[10] + C1, 14);
            bb = Bits.RotateLeft32(P1(cc, dd, aa) + bb + buffer[11] + C1, 15);
            aa = Bits.RotateLeft32(P1(bb, cc, dd) + aa + buffer[12] + C1, 6);
            dd = Bits.RotateLeft32(P1(aa, bb, cc) + dd + buffer[13] + C1, 7);
            cc = Bits.RotateLeft32(P1(dd, aa, bb) + cc + buffer[14] + C1, 9);
            bb = Bits.RotateLeft32(P1(cc, dd, aa) + bb + buffer[15] + C1, 8);

            aa = Bits.RotateLeft32(P2(bb, cc, dd) + aa + buffer[7], 7);
            dd = Bits.RotateLeft32(P2(aa, bb, cc) + dd + buffer[4], 6);
            cc = Bits.RotateLeft32(P2(dd, aa, bb) + cc + buffer[13], 8);
            bb = Bits.RotateLeft32(P2(cc, dd, aa) + bb + buffer[1], 13);
            aa = Bits.RotateLeft32(P2(bb, cc, dd) + aa + buffer[10], 11);
            dd = Bits.RotateLeft32(P2(aa, bb, cc) + dd + buffer[6], 9);
            cc = Bits.RotateLeft32(P2(dd, aa, bb) + cc + buffer[15], 7);
            bb = Bits.RotateLeft32(P2(cc, dd, aa) + bb + buffer[3], 15);
            aa = Bits.RotateLeft32(P2(bb, cc, dd) + aa + buffer[12], 7);
            dd = Bits.RotateLeft32(P2(aa, bb, cc) + dd + buffer[0], 12);
            cc = Bits.RotateLeft32(P2(dd, aa, bb) + cc + buffer[9], 15);
            bb = Bits.RotateLeft32(P2(cc, dd, aa) + bb + buffer[5], 9);
            aa = Bits.RotateLeft32(P2(bb, cc, dd) + aa + buffer[14], 7);
            dd = Bits.RotateLeft32(P2(aa, bb, cc) + dd + buffer[2], 11);
            cc = Bits.RotateLeft32(P2(dd, aa, bb) + cc + buffer[11], 13);
            bb = Bits.RotateLeft32(P2(cc, dd, aa) + bb + buffer[8], 12);

            aa = Bits.RotateLeft32(P3(bb, cc, dd) + aa + buffer[3] + C3, 11);
            dd = Bits.RotateLeft32(P3(aa, bb, cc) + dd + buffer[10] + C3, 13);
            cc = Bits.RotateLeft32(P3(dd, aa, bb) + cc + buffer[2] + C3, 14);
            bb = Bits.RotateLeft32(P3(cc, dd, aa) + bb + buffer[4] + C3, 7);
            aa = Bits.RotateLeft32(P3(bb, cc, dd) + aa + buffer[9] + C3, 14);
            dd = Bits.RotateLeft32(P3(aa, bb, cc) + dd + buffer[15] + C3, 9);
            cc = Bits.RotateLeft32(P3(dd, aa, bb) + cc + buffer[8] + C3, 13);
            bb = Bits.RotateLeft32(P3(cc, dd, aa) + bb + buffer[1] + C3, 15);
            aa = Bits.RotateLeft32(P3(bb, cc, dd) + aa + buffer[14] + C3, 6);
            dd = Bits.RotateLeft32(P3(aa, bb, cc) + dd + buffer[7] + C3, 8);
            cc = Bits.RotateLeft32(P3(dd, aa, bb) + cc + buffer[0] + C3, 13);
            bb = Bits.RotateLeft32(P3(cc, dd, aa) + bb + buffer[6] + C3, 6);
            aa = Bits.RotateLeft32(P3(bb, cc, dd) + aa + buffer[11] + C3, 12);
            dd = Bits.RotateLeft32(P3(aa, bb, cc) + dd + buffer[13] + C3, 5);
            cc = Bits.RotateLeft32(P3(dd, aa, bb) + cc + buffer[5] + C3, 7);
            bb = Bits.RotateLeft32(P3(cc, dd, aa) + bb + buffer[12] + C3, 5);

            cc = cc + State[0] + b;
            State[0] = State[1] + c + dd;
            State[1] = State[2] + d + aa;
            State[2] = State[3] + a + bb;
            State[3] = cc;
        }
    }
}