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
    internal sealed class RIPEMD160 : MDBase, ITransformBlock
    {
        internal RIPEMD160()
            : base(5, 20)
        {
        }

        public override IHash Clone() =>
            new RIPEMD160
            {
                State = ArrayUtils.Clone(State),
                Buffer = Buffer.Clone(),
                ProcessedBytesCount = ProcessedBytesCount,
                BufferSize = BufferSize
            };

        public override void Initialize()
        {
            State[4] = 0xC3D2E1F0;

            base.Initialize();
        }

        protected override unsafe void TransformBlock(void* data,
            int dataLength, int index)
        {
            var buffer = stackalloc uint[16];

            Converters.le32_copy(data, index, buffer, 0, dataLength);

            var a = State[0];
            var b = State[1];
            var c = State[2];
            var d = State[3];
            var e = State[4];
            var aa = a;
            var bb = b;
            var cc = c;
            var dd = d;
            var ee = e;

            a += buffer[0] + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 11) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[1] + (a ^ b ^ c);
            e = Bits.RotateLeft32(e, 14) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[2] + (e ^ a ^ b);
            d = Bits.RotateLeft32(d, 15) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[3] + (d ^ e ^ a);
            c = Bits.RotateLeft32(c, 12) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[4] + (c ^ d ^ e);
            b = Bits.RotateLeft32(b, 5) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[5] + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 8) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[6] + (a ^ b ^ c);
            e = Bits.RotateLeft32(e, 7) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[7] + (e ^ a ^ b);
            d = Bits.RotateLeft32(d, 9) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[8] + (d ^ e ^ a);
            c = Bits.RotateLeft32(c, 11) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[9] + (c ^ d ^ e);
            b = Bits.RotateLeft32(b, 13) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[10] + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 14) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[11] + (a ^ b ^ c);
            e = Bits.RotateLeft32(e, 15) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[12] + (e ^ a ^ b);
            d = Bits.RotateLeft32(d, 6) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[13] + (d ^ e ^ a);
            c = Bits.RotateLeft32(c, 7) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[14] + (c ^ d ^ e);
            b = Bits.RotateLeft32(b, 9) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[15] + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 8) + e;
            c = Bits.RotateLeft32(c, 10);

            aa += buffer[5] + C1 + (bb ^ (cc | ~dd));
            aa = Bits.RotateLeft32(aa, 8) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[14] + C1 + (aa ^ (bb | ~cc));
            ee = Bits.RotateLeft32(ee, 9) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[7] + C1 + (ee ^ (aa | ~bb));
            dd = Bits.RotateLeft32(dd, 9) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[0] + C1 + (dd ^ (ee | ~aa));
            cc = Bits.RotateLeft32(cc, 11) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[9] + C1 + (cc ^ (dd | ~ee));
            bb = Bits.RotateLeft32(bb, 13) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[2] + C1 + (bb ^ (cc | ~dd));
            aa = Bits.RotateLeft32(aa, 15) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[11] + C1 + (aa ^ (bb | ~cc));
            ee = Bits.RotateLeft32(ee, 15) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[4] + C1 + (ee ^ (aa | ~bb));
            dd = Bits.RotateLeft32(dd, 5) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[13] + C1 + (dd ^ (ee | ~aa));
            cc = Bits.RotateLeft32(cc, 7) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[6] + C1 + (cc ^ (dd | ~ee));
            bb = Bits.RotateLeft32(bb, 7) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[15] + C1 + (bb ^ (cc | ~dd));
            aa = Bits.RotateLeft32(aa, 8) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[8] + C1 + (aa ^ (bb | ~cc));
            ee = Bits.RotateLeft32(ee, 11) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[1] + C1 + (ee ^ (aa | ~bb));
            dd = Bits.RotateLeft32(dd, 14) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[10] + C1 + (dd ^ (ee | ~aa));
            cc = Bits.RotateLeft32(cc, 14) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[3] + C1 + (cc ^ (dd | ~ee));
            bb = Bits.RotateLeft32(bb, 12) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[12] + C1 + (bb ^ (cc | ~dd));
            aa = Bits.RotateLeft32(aa, 6) + ee;
            cc = Bits.RotateLeft32(cc, 10);

            e += buffer[7] + C2 + ((a & b) | (~a & c));
            e = Bits.RotateLeft32(e, 7) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[4] + C2 + ((e & a) | (~e & b));
            d = Bits.RotateLeft32(d, 6) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[13] + C2 + ((d & e) | (~d & a));
            c = Bits.RotateLeft32(c, 8) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[1] + C2 + ((c & d) | (~c & e));
            b = Bits.RotateLeft32(b, 13) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[10] + C2 + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 11) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[6] + C2 + ((a & b) | (~a & c));
            e = Bits.RotateLeft32(e, 9) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[15] + C2 + ((e & a) | (~e & b));
            d = Bits.RotateLeft32(d, 7) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[3] + C2 + ((d & e) | (~d & a));
            c = Bits.RotateLeft32(c, 15) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[12] + C2 + ((c & d) | (~c & e));
            b = Bits.RotateLeft32(b, 7) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[0] + C2 + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 12) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[9] + C2 + ((a & b) | (~a & c));
            e = Bits.RotateLeft32(e, 15) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[5] + C2 + ((e & a) | (~e & b));
            d = Bits.RotateLeft32(d, 9) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[2] + C2 + ((d & e) | (~d & a));
            c = Bits.RotateLeft32(c, 11) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[14] + C2 + ((c & d) | (~c & e));
            b = Bits.RotateLeft32(b, 7) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[11] + C2 + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 13) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[8] + C2 + ((a & b) | (~a & c));
            e = Bits.RotateLeft32(e, 12) + d;
            b = Bits.RotateLeft32(b, 10);

            ee += buffer[6] + C3 + ((aa & cc) | (bb & ~cc));
            ee = Bits.RotateLeft32(ee, 9) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[11] + C3 + ((ee & bb) | (aa & ~bb));
            dd = Bits.RotateLeft32(dd, 13) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[3] + C3 + ((dd & aa) | (ee & ~aa));
            cc = Bits.RotateLeft32(cc, 15) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[7] + C3 + ((cc & ee) | (dd & ~ee));
            bb = Bits.RotateLeft32(bb, 7) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[0] + C3 + ((bb & dd) | (cc & ~dd));
            aa = Bits.RotateLeft32(aa, 12) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[13] + C3 + ((aa & cc) | (bb & ~cc));
            ee = Bits.RotateLeft32(ee, 8) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[5] + C3 + ((ee & bb) | (aa & ~bb));
            dd = Bits.RotateLeft32(dd, 9) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[10] + C3 + ((dd & aa) | (ee & ~aa));
            cc = Bits.RotateLeft32(cc, 11) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[14] + C3 + ((cc & ee) | (dd & ~ee));
            bb = Bits.RotateLeft32(bb, 7) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[15] + C3 + ((bb & dd) | (cc & ~dd));
            aa = Bits.RotateLeft32(aa, 7) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[8] + C3 + ((aa & cc) | (bb & ~cc));
            ee = Bits.RotateLeft32(ee, 12) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[12] + C3 + ((ee & bb) | (aa & ~bb));
            dd = Bits.RotateLeft32(dd, 7) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[4] + C3 + ((dd & aa) | (ee & ~aa));
            cc = Bits.RotateLeft32(cc, 6) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[9] + C3 + ((cc & ee) | (dd & ~ee));
            bb = Bits.RotateLeft32(bb, 15) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[1] + C3 + ((bb & dd) | (cc & ~dd));
            aa = Bits.RotateLeft32(aa, 13) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[2] + C3 + ((aa & cc) | (bb & ~cc));
            ee = Bits.RotateLeft32(ee, 11) + dd;
            bb = Bits.RotateLeft32(bb, 10);

            d += buffer[3] + C4 + ((e | ~a) ^ b);
            d = Bits.RotateLeft32(d, 11) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[10] + C4 + ((d | ~e) ^ a);
            c = Bits.RotateLeft32(c, 13) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[14] + C4 + ((c | ~d) ^ e);
            b = Bits.RotateLeft32(b, 6) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[4] + C4 + ((b | ~c) ^ d);
            a = Bits.RotateLeft32(a, 7) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[9] + C4 + ((a | ~b) ^ c);
            e = Bits.RotateLeft32(e, 14) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[15] + C4 + ((e | ~a) ^ b);
            d = Bits.RotateLeft32(d, 9) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[8] + C4 + ((d | ~e) ^ a);
            c = Bits.RotateLeft32(c, 13) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[1] + C4 + ((c | ~d) ^ e);
            b = Bits.RotateLeft32(b, 15) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[2] + C4 + ((b | ~c) ^ d);
            a = Bits.RotateLeft32(a, 14) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[7] + C4 + ((a | ~b) ^ c);
            e = Bits.RotateLeft32(e, 8) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[0] + C4 + ((e | ~a) ^ b);
            d = Bits.RotateLeft32(d, 13) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[6] + C4 + ((d | ~e) ^ a);
            c = Bits.RotateLeft32(c, 6) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[13] + C4 + ((c | ~d) ^ e);
            b = Bits.RotateLeft32(b, 5) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[11] + C4 + ((b | ~c) ^ d);
            a = Bits.RotateLeft32(a, 12) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[5] + C4 + ((a | ~b) ^ c);
            e = Bits.RotateLeft32(e, 7) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[12] + C4 + ((e | ~a) ^ b);
            d = Bits.RotateLeft32(d, 5) + c;
            a = Bits.RotateLeft32(a, 10);

            dd += buffer[15] + C5 + ((ee | ~aa) ^ bb);
            dd = Bits.RotateLeft32(dd, 9) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[5] + C5 + ((dd | ~ee) ^ aa);
            cc = Bits.RotateLeft32(cc, 7) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[1] + C5 + ((cc | ~dd) ^ ee);
            bb = Bits.RotateLeft32(bb, 15) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[3] + C5 + ((bb | ~cc) ^ dd);
            aa = Bits.RotateLeft32(aa, 11) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[7] + C5 + ((aa | ~bb) ^ cc);
            ee = Bits.RotateLeft32(ee, 8) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[14] + C5 + ((ee | ~aa) ^ bb);
            dd = Bits.RotateLeft32(dd, 6) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[6] + C5 + ((dd | ~ee) ^ aa);
            cc = Bits.RotateLeft32(cc, 6) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[9] + C5 + ((cc | ~dd) ^ ee);
            bb = Bits.RotateLeft32(bb, 14) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[11] + C5 + ((bb | ~cc) ^ dd);
            aa = Bits.RotateLeft32(aa, 12) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[8] + C5 + ((aa | ~bb) ^ cc);
            ee = Bits.RotateLeft32(ee, 13) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[12] + C5 + ((ee | ~aa) ^ bb);
            dd = Bits.RotateLeft32(dd, 5) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[2] + C5 + ((dd | ~ee) ^ aa);
            cc = Bits.RotateLeft32(cc, 14) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[10] + C5 + ((cc | ~dd) ^ ee);
            bb = Bits.RotateLeft32(bb, 13) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[0] + C5 + ((bb | ~cc) ^ dd);
            aa = Bits.RotateLeft32(aa, 13) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[4] + C5 + ((aa | ~bb) ^ cc);
            ee = Bits.RotateLeft32(ee, 7) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[13] + C5 + ((ee | ~aa) ^ bb);
            dd = Bits.RotateLeft32(dd, 5) + cc;
            aa = Bits.RotateLeft32(aa, 10);

            c += buffer[1] + C6 + ((d & a) | (e & ~a));
            c = Bits.RotateLeft32(c, 11) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[9] + C6 + ((c & e) | (d & ~e));
            b = Bits.RotateLeft32(b, 12) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[11] + C6 + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 14) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[10] + C6 + ((a & c) | (b & ~c));
            e = Bits.RotateLeft32(e, 15) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[0] + C6 + ((e & b) | (a & ~b));
            d = Bits.RotateLeft32(d, 14) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[8] + C6 + ((d & a) | (e & ~a));
            c = Bits.RotateLeft32(c, 15) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[12] + C6 + ((c & e) | (d & ~e));
            b = Bits.RotateLeft32(b, 9) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[4] + C6 + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 8) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[13] + C6 + ((a & c) | (b & ~c));
            e = Bits.RotateLeft32(e, 9) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[3] + C6 + ((e & b) | (a & ~b));
            d = Bits.RotateLeft32(d, 14) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[7] + C6 + ((d & a) | (e & ~a));
            c = Bits.RotateLeft32(c, 5) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[15] + C6 + ((c & e) | (d & ~e));
            b = Bits.RotateLeft32(b, 6) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[14] + C6 + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 8) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[5] + C6 + ((a & c) | (b & ~c));
            e = Bits.RotateLeft32(e, 6) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[6] + C6 + ((e & b) | (a & ~b));
            d = Bits.RotateLeft32(d, 5) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[2] + C6 + ((d & a) | (e & ~a));
            c = Bits.RotateLeft32(c, 12) + b;
            e = Bits.RotateLeft32(e, 10);

            cc += buffer[8] + C7 + ((dd & ee) | (~dd & aa));
            cc = Bits.RotateLeft32(cc, 15) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[6] + C7 + ((cc & dd) | (~cc & ee));
            bb = Bits.RotateLeft32(bb, 5) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[4] + C7 + ((bb & cc) | (~bb & dd));
            aa = Bits.RotateLeft32(aa, 8) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[1] + C7 + ((aa & bb) | (~aa & cc));
            ee = Bits.RotateLeft32(ee, 11) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[3] + C7 + ((ee & aa) | (~ee & bb));
            dd = Bits.RotateLeft32(dd, 14) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[11] + C7 + ((dd & ee) | (~dd & aa));
            cc = Bits.RotateLeft32(cc, 14) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[15] + C7 + ((cc & dd) | (~cc & ee));
            bb = Bits.RotateLeft32(bb, 6) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[0] + C7 + ((bb & cc) | (~bb & dd));
            aa = Bits.RotateLeft32(aa, 14) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[5] + C7 + ((aa & bb) | (~aa & cc));
            ee = Bits.RotateLeft32(ee, 6) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[12] + C7 + ((ee & aa) | (~ee & bb));
            dd = Bits.RotateLeft32(dd, 9) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[2] + C7 + ((dd & ee) | (~dd & aa));
            cc = Bits.RotateLeft32(cc, 12) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[13] + C7 + ((cc & dd) | (~cc & ee));
            bb = Bits.RotateLeft32(bb, 9) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[9] + C7 + ((bb & cc) | (~bb & dd));
            aa = Bits.RotateLeft32(aa, 12) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[7] + C7 + ((aa & bb) | (~aa & cc));
            ee = Bits.RotateLeft32(ee, 5) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[10] + C7 + ((ee & aa) | (~ee & bb));
            dd = Bits.RotateLeft32(dd, 15) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[14] + C7 + ((dd & ee) | (~dd & aa));
            cc = Bits.RotateLeft32(cc, 8) + bb;
            ee = Bits.RotateLeft32(ee, 10);

            b += buffer[4] + C8 + (c ^ (d | ~e));
            b = Bits.RotateLeft32(b, 9) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[0] + C8 + (b ^ (c | ~d));
            a = Bits.RotateLeft32(a, 15) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[5] + C8 + (a ^ (b | ~c));
            e = Bits.RotateLeft32(e, 5) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[9] + C8 + (e ^ (a | ~b));
            d = Bits.RotateLeft32(d, 11) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[7] + C8 + (d ^ (e | ~a));
            c = Bits.RotateLeft32(c, 6) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[12] + C8 + (c ^ (d | ~e));
            b = Bits.RotateLeft32(b, 8) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[2] + C8 + (b ^ (c | ~d));
            a = Bits.RotateLeft32(a, 13) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[10] + C8 + (a ^ (b | ~c));
            e = Bits.RotateLeft32(e, 12) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[14] + C8 + (e ^ (a | ~b));
            d = Bits.RotateLeft32(d, 5) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[1] + C8 + (d ^ (e | ~a));
            c = Bits.RotateLeft32(c, 12) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[3] + C8 + (c ^ (d | ~e));
            b = Bits.RotateLeft32(b, 13) + a;
            d = Bits.RotateLeft32(d, 10);
            a += buffer[8] + C8 + (b ^ (c | ~d));
            a = Bits.RotateLeft32(a, 14) + e;
            c = Bits.RotateLeft32(c, 10);
            e += buffer[11] + C8 + (a ^ (b | ~c));
            e = Bits.RotateLeft32(e, 11) + d;
            b = Bits.RotateLeft32(b, 10);
            d += buffer[6] + C8 + (e ^ (a | ~b));
            d = Bits.RotateLeft32(d, 8) + c;
            a = Bits.RotateLeft32(a, 10);
            c += buffer[15] + C8 + (d ^ (e | ~a));
            c = Bits.RotateLeft32(c, 5) + b;
            e = Bits.RotateLeft32(e, 10);
            b += buffer[13] + C8 + (c ^ (d | ~e));
            b = Bits.RotateLeft32(b, 6) + a;
            d = Bits.RotateLeft32(d, 10);

            bb += buffer[12] + (cc ^ dd ^ ee);
            bb = Bits.RotateLeft32(bb, 8) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[15] + (bb ^ cc ^ dd);
            aa = Bits.RotateLeft32(aa, 5) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[10] + (aa ^ bb ^ cc);
            ee = Bits.RotateLeft32(ee, 12) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[4] + (ee ^ aa ^ bb);
            dd = Bits.RotateLeft32(dd, 9) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[1] + (dd ^ ee ^ aa);
            cc = Bits.RotateLeft32(cc, 12) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[5] + (cc ^ dd ^ ee);
            bb = Bits.RotateLeft32(bb, 5) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[8] + (bb ^ cc ^ dd);
            aa = Bits.RotateLeft32(aa, 14) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[7] + (aa ^ bb ^ cc);
            ee = Bits.RotateLeft32(ee, 6) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[6] + (ee ^ aa ^ bb);
            dd = Bits.RotateLeft32(dd, 8) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[2] + (dd ^ ee ^ aa);
            cc = Bits.RotateLeft32(cc, 13) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[13] + (cc ^ dd ^ ee);
            bb = Bits.RotateLeft32(bb, 6) + aa;
            dd = Bits.RotateLeft32(dd, 10);
            aa += buffer[14] + (bb ^ cc ^ dd);
            aa = Bits.RotateLeft32(aa, 5) + ee;
            cc = Bits.RotateLeft32(cc, 10);
            ee += buffer[0] + (aa ^ bb ^ cc);
            ee = Bits.RotateLeft32(ee, 15) + dd;
            bb = Bits.RotateLeft32(bb, 10);
            dd += buffer[3] + (ee ^ aa ^ bb);
            dd = Bits.RotateLeft32(dd, 13) + cc;
            aa = Bits.RotateLeft32(aa, 10);
            cc += buffer[9] + (dd ^ ee ^ aa);
            cc = Bits.RotateLeft32(cc, 11) + bb;
            ee = Bits.RotateLeft32(ee, 10);
            bb += buffer[11] + (cc ^ dd ^ ee);
            bb = Bits.RotateLeft32(bb, 11) + aa;
            dd = Bits.RotateLeft32(dd, 10);

            dd = dd + c + State[1];
            State[1] = State[2] + d + ee;
            State[2] = State[3] + e + aa;
            State[3] = State[4] + a + bb;
            State[4] = State[0] + b + cc;
            State[0] = dd;
        }
    }
}