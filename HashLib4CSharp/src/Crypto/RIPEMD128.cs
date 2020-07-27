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

using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal sealed class RIPEMD128 : MDBase, ITransformBlock
    {
        internal RIPEMD128()
            : base(4, 16)
        {
        }

        public override IHash Clone() =>
            new RIPEMD128
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

            a += buffer[0] + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 11);
            d += buffer[1] + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 14);
            c += buffer[2] + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 15);
            b += buffer[3] + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 12);
            a += buffer[4] + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 5);
            d += buffer[5] + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 8);
            c += buffer[6] + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 7);
            b += buffer[7] + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 9);
            a += buffer[8] + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 11);
            d += buffer[9] + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 13);
            c += buffer[10] + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 14);
            b += buffer[11] + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 15);
            a += buffer[12] + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 6);
            d += buffer[13] + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 7);
            c += buffer[14] + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 9);
            b += buffer[15] + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 8);

            a += buffer[7] + C2 + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 7);
            d += buffer[4] + C2 + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 6);
            c += buffer[13] + C2 + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 8);
            b += buffer[1] + C2 + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 13);
            a += buffer[10] + C2 + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 11);
            d += buffer[6] + C2 + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 9);
            c += buffer[15] + C2 + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 7);
            b += buffer[3] + C2 + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 15);
            a += buffer[12] + C2 + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 7);
            d += buffer[0] + C2 + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 12);
            c += buffer[9] + C2 + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 15);
            b += buffer[5] + C2 + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 9);
            a += buffer[2] + C2 + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 11);
            d += buffer[14] + C2 + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 7);
            c += buffer[11] + C2 + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 13);
            b += buffer[8] + C2 + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 12);

            a += buffer[3] + C4 + ((b | ~c) ^ d);
            a = Bits.RotateLeft32(a, 11);
            d += buffer[10] + C4 + ((a | ~b) ^ c);
            d = Bits.RotateLeft32(d, 13);
            c += buffer[14] + C4 + ((d | ~a) ^ b);
            c = Bits.RotateLeft32(c, 6);
            b += buffer[4] + C4 + ((c | ~d) ^ a);
            b = Bits.RotateLeft32(b, 7);
            a += buffer[9] + C4 + ((b | ~c) ^ d);
            a = Bits.RotateLeft32(a, 14);
            d += buffer[15] + C4 + ((a | ~b) ^ c);
            d = Bits.RotateLeft32(d, 9);
            c += buffer[8] + C4 + ((d | ~a) ^ b);
            c = Bits.RotateLeft32(c, 13);
            b += buffer[1] + C4 + ((c | ~d) ^ a);
            b = Bits.RotateLeft32(b, 15);
            a += buffer[2] + C4 + ((b | ~c) ^ d);
            a = Bits.RotateLeft32(a, 14);
            d += buffer[7] + C4 + ((a | ~b) ^ c);
            d = Bits.RotateLeft32(d, 8);
            c += buffer[0] + C4 + ((d | ~a) ^ b);
            c = Bits.RotateLeft32(c, 13);
            b += buffer[6] + C4 + ((c | ~d) ^ a);
            b = Bits.RotateLeft32(b, 6);
            a += buffer[13] + C4 + ((b | ~c) ^ d);
            a = Bits.RotateLeft32(a, 5);
            d += buffer[11] + C4 + ((a | ~b) ^ c);
            d = Bits.RotateLeft32(d, 12);
            c += buffer[5] + C4 + ((d | ~a) ^ b);
            c = Bits.RotateLeft32(c, 7);
            b += buffer[12] + C4 + ((c | ~d) ^ a);
            b = Bits.RotateLeft32(b, 5);

            a += buffer[1] + C6 + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 11);
            d += buffer[9] + C6 + ((a & c) | (b & ~c));
            d = Bits.RotateLeft32(d, 12);
            c += buffer[11] + C6 + ((d & b) | (a & ~b));
            c = Bits.RotateLeft32(c, 14);
            b += buffer[10] + C6 + ((c & a) | (d & ~a));
            b = Bits.RotateLeft32(b, 15);
            a += buffer[0] + C6 + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 14);
            d += buffer[8] + C6 + ((a & c) | (b & ~c));
            d = Bits.RotateLeft32(d, 15);
            c += buffer[12] + C6 + ((d & b) | (a & ~b));
            c = Bits.RotateLeft32(c, 9);
            b += buffer[4] + C6 + ((c & a) | (d & ~a));
            b = Bits.RotateLeft32(b, 8);
            a += buffer[13] + C6 + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 9);
            d += buffer[3] + C6 + ((a & c) | (b & ~c));
            d = Bits.RotateLeft32(d, 14);
            c += buffer[7] + C6 + ((d & b) | (a & ~b));
            c = Bits.RotateLeft32(c, 5);
            b += buffer[15] + C6 + ((c & a) | (d & ~a));
            b = Bits.RotateLeft32(b, 6);
            a += buffer[14] + C6 + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 8);
            d += buffer[5] + C6 + ((a & c) | (b & ~c));
            d = Bits.RotateLeft32(d, 6);
            c += buffer[6] + C6 + ((d & b) | (a & ~b));
            c = Bits.RotateLeft32(c, 5);
            b += buffer[2] + C6 + ((c & a) | (d & ~a));
            b = Bits.RotateLeft32(b, 12);

            aa += buffer[5] + C1 + ((bb & dd) | (cc & ~dd));
            aa = Bits.RotateLeft32(aa, 8);
            dd += buffer[14] + C1 + ((aa & cc) | (bb & ~cc));
            dd = Bits.RotateLeft32(dd, 9);
            cc += buffer[7] + C1 + ((dd & bb) | (aa & ~bb));
            cc = Bits.RotateLeft32(cc, 9);
            bb += buffer[0] + C1 + ((cc & aa) | (dd & ~aa));
            bb = Bits.RotateLeft32(bb, 11);
            aa += buffer[9] + C1 + ((bb & dd) | (cc & ~dd));
            aa = Bits.RotateLeft32(aa, 13);
            dd += buffer[2] + C1 + ((aa & cc) | (bb & ~cc));
            dd = Bits.RotateLeft32(dd, 15);
            cc += buffer[11] + C1 + ((dd & bb) | (aa & ~bb));
            cc = Bits.RotateLeft32(cc, 15);
            bb += buffer[4] + C1 + ((cc & aa) | (dd & ~aa));
            bb = Bits.RotateLeft32(bb, 5);
            aa += buffer[13] + C1 + ((bb & dd) | (cc & ~dd));
            aa = Bits.RotateLeft32(aa, 7);
            dd += buffer[6] + C1 + ((aa & cc) | (bb & ~cc));
            dd = Bits.RotateLeft32(dd, 7);
            cc += buffer[15] + C1 + ((dd & bb) | (aa & ~bb));
            cc = Bits.RotateLeft32(cc, 8);
            bb += buffer[8] + C1 + ((cc & aa) | (dd & ~aa));
            bb = Bits.RotateLeft32(bb, 11);
            aa += buffer[1] + C1 + ((bb & dd) | (cc & ~dd));
            aa = Bits.RotateLeft32(aa, 14);
            dd += buffer[10] + C1 + ((aa & cc) | (bb & ~cc));
            dd = Bits.RotateLeft32(dd, 14);
            cc += buffer[3] + C1 + ((dd & bb) | (aa & ~bb));
            cc = Bits.RotateLeft32(cc, 12);
            bb += buffer[12] + C1 + ((cc & aa) | (dd & ~aa));
            bb = Bits.RotateLeft32(bb, 6);

            aa += buffer[6] + C3 + ((bb | ~cc) ^ dd);
            aa = Bits.RotateLeft32(aa, 9);
            dd += buffer[11] + C3 + ((aa | ~bb) ^ cc);
            dd = Bits.RotateLeft32(dd, 13);
            cc += buffer[3] + C3 + ((dd | ~aa) ^ bb);
            cc = Bits.RotateLeft32(cc, 15);
            bb += buffer[7] + C3 + ((cc | ~dd) ^ aa);
            bb = Bits.RotateLeft32(bb, 7);
            aa += buffer[0] + C3 + ((bb | ~cc) ^ dd);
            aa = Bits.RotateLeft32(aa, 12);
            dd += buffer[13] + C3 + ((aa | ~bb) ^ cc);
            dd = Bits.RotateLeft32(dd, 8);
            cc += buffer[5] + C3 + ((dd | ~aa) ^ bb);
            cc = Bits.RotateLeft32(cc, 9);
            bb += buffer[10] + C3 + ((cc | ~dd) ^ aa);
            bb = Bits.RotateLeft32(bb, 11);
            aa += buffer[14] + C3 + ((bb | ~cc) ^ dd);
            aa = Bits.RotateLeft32(aa, 7);
            dd += buffer[15] + C3 + ((aa | ~bb) ^ cc);
            dd = Bits.RotateLeft32(dd, 7);
            cc += buffer[8] + C3 + ((dd | ~aa) ^ bb);
            cc = Bits.RotateLeft32(cc, 12);
            bb += buffer[12] + C3 + ((cc | ~dd) ^ aa);
            bb = Bits.RotateLeft32(bb, 7);
            aa += buffer[4] + C3 + ((bb | ~cc) ^ dd);
            aa = Bits.RotateLeft32(aa, 6);
            dd += buffer[9] + C3 + ((aa | ~bb) ^ cc);
            dd = Bits.RotateLeft32(dd, 15);
            cc += buffer[1] + C3 + ((dd | ~aa) ^ bb);
            cc = Bits.RotateLeft32(cc, 13);
            bb += buffer[2] + C3 + ((cc | ~dd) ^ aa);
            bb = Bits.RotateLeft32(bb, 11);

            aa += buffer[15] + C5 + ((bb & cc) | (~bb & dd));
            aa = Bits.RotateLeft32(aa, 9);
            dd += buffer[5] + C5 + ((aa & bb) | (~aa & cc));
            dd = Bits.RotateLeft32(dd, 7);
            cc += buffer[1] + C5 + ((dd & aa) | (~dd & bb));
            cc = Bits.RotateLeft32(cc, 15);
            bb += buffer[3] + C5 + ((cc & dd) | (~cc & aa));
            bb = Bits.RotateLeft32(bb, 11);
            aa += buffer[7] + C5 + ((bb & cc) | (~bb & dd));
            aa = Bits.RotateLeft32(aa, 8);
            dd += buffer[14] + C5 + ((aa & bb) | (~aa & cc));
            dd = Bits.RotateLeft32(dd, 6);
            cc += buffer[6] + C5 + ((dd & aa) | (~dd & bb));
            cc = Bits.RotateLeft32(cc, 6);
            bb += buffer[9] + C5 + ((cc & dd) | (~cc & aa));
            bb = Bits.RotateLeft32(bb, 14);
            aa += buffer[11] + C5 + ((bb & cc) | (~bb & dd));
            aa = Bits.RotateLeft32(aa, 12);
            dd += buffer[8] + C5 + ((aa & bb) | (~aa & cc));
            dd = Bits.RotateLeft32(dd, 13);
            cc += buffer[12] + C5 + ((dd & aa) | (~dd & bb));
            cc = Bits.RotateLeft32(cc, 5);
            bb += buffer[2] + C5 + ((cc & dd) | (~cc & aa));
            bb = Bits.RotateLeft32(bb, 14);
            aa += buffer[10] + C5 + ((bb & cc) | (~bb & dd));
            aa = Bits.RotateLeft32(aa, 13);
            dd += buffer[0] + C5 + ((aa & bb) | (~aa & cc));
            dd = Bits.RotateLeft32(dd, 13);
            cc += buffer[4] + C5 + ((dd & aa) | (~dd & bb));
            cc = Bits.RotateLeft32(cc, 7);
            bb += buffer[13] + C5 + ((cc & dd) | (~cc & aa));
            bb = Bits.RotateLeft32(bb, 5);

            aa += buffer[8] + (bb ^ cc ^ dd);
            aa = Bits.RotateLeft32(aa, 15);
            dd += buffer[6] + (aa ^ bb ^ cc);
            dd = Bits.RotateLeft32(dd, 5);
            cc += buffer[4] + (dd ^ aa ^ bb);
            cc = Bits.RotateLeft32(cc, 8);
            bb += buffer[1] + (cc ^ dd ^ aa);
            bb = Bits.RotateLeft32(bb, 11);
            aa += buffer[3] + (bb ^ cc ^ dd);
            aa = Bits.RotateLeft32(aa, 14);
            dd += buffer[11] + (aa ^ bb ^ cc);
            dd = Bits.RotateLeft32(dd, 14);
            cc += buffer[15] + (dd ^ aa ^ bb);
            cc = Bits.RotateLeft32(cc, 6);
            bb += buffer[0] + (cc ^ dd ^ aa);
            bb = Bits.RotateLeft32(bb, 14);
            aa += buffer[5] + (bb ^ cc ^ dd);
            aa = Bits.RotateLeft32(aa, 6);
            dd += buffer[12] + (aa ^ bb ^ cc);
            dd = Bits.RotateLeft32(dd, 9);
            cc += buffer[2] + (dd ^ aa ^ bb);
            cc = Bits.RotateLeft32(cc, 12);
            bb += buffer[13] + (cc ^ dd ^ aa);
            bb = Bits.RotateLeft32(bb, 9);
            aa += buffer[9] + (bb ^ cc ^ dd);
            aa = Bits.RotateLeft32(aa, 12);
            dd += buffer[7] + (aa ^ bb ^ cc);
            dd = Bits.RotateLeft32(dd, 5);
            cc += buffer[10] + (dd ^ aa ^ bb);
            cc = Bits.RotateLeft32(cc, 15);
            bb += buffer[14] + (cc ^ dd ^ aa);
            bb = Bits.RotateLeft32(bb, 8);

            dd = dd + c + State[1];
            State[1] = State[2] + d + aa;
            State[2] = State[3] + a + bb;
            State[3] = State[0] + b + cc;
            State[0] = dd;
        }
    }
}