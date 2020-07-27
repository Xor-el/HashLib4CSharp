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
    internal sealed class MD5 : MDBase, ITransformBlock
    {
        internal MD5()
            : base(4, 16)
        {
        }
        public override IHash Clone() =>
            new MD5
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

            a = buffer[0] + 0xD76AA478 + a + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 7) + b;
            d = buffer[1] + 0xE8C7B756 + d + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 12) + a;
            c = buffer[2] + 0x242070DB + c + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 17) + d;
            b = buffer[3] + 0xC1BDCEEE + b + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 22) + c;
            a = buffer[4] + 0xF57C0FAF + a + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 7) + b;
            d = buffer[5] + 0x4787C62A + d + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 12) + a;
            c = buffer[6] + 0xA8304613 + c + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 17) + d;
            b = buffer[7] + 0xFD469501 + b + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 22) + c;
            a = buffer[8] + 0x698098D8 + a + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 7) + b;
            d = buffer[9] + 0x8B44F7AF + d + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 12) + a;
            c = buffer[10] + 0xFFFF5BB1 + c + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 17) + d;
            b = buffer[11] + 0x895CD7BE + b + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 22) + c;
            a = buffer[12] + 0x6B901122 + a + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 7) + b;
            d = buffer[13] + 0xFD987193 + d + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 12) + a;
            c = buffer[14] + 0xA679438E + c + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 17) + d;
            b = buffer[15] + 0x49B40821 + b + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 22) + c;

            a = buffer[1] + 0xF61E2562 + a + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 5) + b;
            d = buffer[6] + 0xC040B340 + d + ((a & c) | (b & ~c));
            d = Bits.RotateLeft32(d, 9) + a;
            c = buffer[11] + 0x265E5A51 + c + ((d & b) | (a & ~b));
            c = Bits.RotateLeft32(c, 14) + d;
            b = buffer[0] + 0xE9B6C7AA + b + ((c & a) | (d & ~a));
            b = Bits.RotateLeft32(b, 20) + c;
            a = buffer[5] + 0xD62F105D + a + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 5) + b;
            d = buffer[10] + 0x2441453 + d + ((a & c) | (b & ~c));
            d = Bits.RotateLeft32(d, 9) + a;
            c = buffer[15] + 0xD8A1E681 + c + ((d & b) | (a & ~b));
            c = Bits.RotateLeft32(c, 14) + d;
            b = buffer[4] + 0xE7D3FBC8 + b + ((c & a) | (d & ~a));
            b = Bits.RotateLeft32(b, 20) + c;
            a = buffer[9] + 0x21E1CDE6 + a + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 5) + b;
            d = buffer[14] + 0xC33707D6 + d + ((a & c) | (b & ~c));
            d = Bits.RotateLeft32(d, 9) + a;
            c = buffer[3] + 0xF4D50D87 + c + ((d & b) | (a & ~b));
            c = Bits.RotateLeft32(c, 14) + d;
            b = buffer[8] + 0x455A14ED + b + ((c & a) | (d & ~a));
            b = Bits.RotateLeft32(b, 20) + c;
            a = buffer[13] + 0xA9E3E905 + a + ((b & d) | (c & ~d));
            a = Bits.RotateLeft32(a, 5) + b;
            d = buffer[2] + 0xFCEFA3F8 + d + ((a & c) | (b & ~c));
            d = Bits.RotateLeft32(d, 9) + a;
            c = buffer[7] + 0x676F02D9 + c + ((d & b) | (a & ~b));
            c = Bits.RotateLeft32(c, 14) + d;
            b = buffer[12] + 0x8D2A4C8A + b + ((c & a) | (d & ~a));
            b = Bits.RotateLeft32(b, 20) + c;

            a = buffer[5] + 0xFFFA3942 + a + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 4) + b;
            d = buffer[8] + 0x8771F681 + d + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 11) + a;
            c = buffer[11] + 0x6D9D6122 + c + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 16) + d;
            b = buffer[14] + 0xFDE5380C + b + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 23) + c;
            a = buffer[1] + 0xA4BEEA44 + a + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 4) + b;
            d = buffer[4] + 0x4BDECFA9 + d + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 11) + a;
            c = buffer[7] + 0xF6BB4B60 + c + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 16) + d;
            b = buffer[10] + 0xBEBFBC70 + b + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 23) + c;
            a = buffer[13] + 0x289B7EC6 + a + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 4) + b;
            d = buffer[0] + 0xEAA127FA + d + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 11) + a;
            c = buffer[3] + 0xD4EF3085 + c + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 16) + d;
            b = buffer[6] + 0x4881D05 + b + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 23) + c;
            a = buffer[9] + 0xD9D4D039 + a + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 4) + b;
            d = buffer[12] + 0xE6DB99E5 + d + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 11) + a;
            c = buffer[15] + 0x1FA27CF8 + c + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 16) + d;
            b = buffer[2] + 0xC4AC5665 + b + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 23) + c;

            a = buffer[0] + 0xF4292244 + a + (c ^ (b | ~d));
            a = Bits.RotateLeft32(a, 6) + b;
            d = buffer[7] + 0x432AFF97 + d + (b ^ (a | ~c));
            d = Bits.RotateLeft32(d, 10) + a;
            c = buffer[14] + 0xAB9423A7 + c + (a ^ (d | ~b));
            c = Bits.RotateLeft32(c, 15) + d;
            b = buffer[5] + 0xFC93A039 + b + (d ^ (c | ~a));
            b = Bits.RotateLeft32(b, 21) + c;
            a = buffer[12] + 0x655B59C3 + a + (c ^ (b | ~d));
            a = Bits.RotateLeft32(a, 6) + b;
            d = buffer[3] + 0x8F0CCC92 + d + (b ^ (a | ~c));
            d = Bits.RotateLeft32(d, 10) + a;
            c = buffer[10] + 0xFFEFF47D + c + (a ^ (d | ~b));
            c = Bits.RotateLeft32(c, 15) + d;
            b = buffer[1] + 0x85845DD1 + b + (d ^ (c | ~a));
            b = Bits.RotateLeft32(b, 21) + c;
            a = buffer[8] + 0x6FA87E4F + a + (c ^ (b | ~d));
            a = Bits.RotateLeft32(a, 6) + b;
            d = buffer[15] + 0xFE2CE6E0 + d + (b ^ (a | ~c));
            d = Bits.RotateLeft32(d, 10) + a;
            c = buffer[6] + 0xA3014314 + c + (a ^ (d | ~b));
            c = Bits.RotateLeft32(c, 15) + d;
            b = buffer[13] + 0x4E0811A1 + b + (d ^ (c | ~a));
            b = Bits.RotateLeft32(b, 21) + c;
            a = buffer[4] + 0xF7537E82 + a + (c ^ (b | ~d));
            a = Bits.RotateLeft32(a, 6) + b;
            d = buffer[11] + 0xBD3AF235 + d + (b ^ (a | ~c));
            d = Bits.RotateLeft32(d, 10) + a;
            c = buffer[2] + 0x2AD7D2BB + c + (a ^ (d | ~b));
            c = Bits.RotateLeft32(c, 15) + d;
            b = buffer[9] + 0xEB86D391 + b + (d ^ (c | ~a));
            b = Bits.RotateLeft32(b, 21) + c;

            State[0] = State[0] + a;
            State[1] = State[1] + b;
            State[2] = State[2] + c;
            State[3] = State[3] + d;

        }
    }
}