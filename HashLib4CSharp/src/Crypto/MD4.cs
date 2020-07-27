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
    internal sealed class MD4 : MDBase, ITransformBlock
    {
        internal MD4()
            : base(4, 16)
        {
        }

        public override IHash Clone() =>
            new MD4
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

            a += buffer[0] + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 3);
            d += buffer[1] + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 7);
            c += buffer[2] + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 11);
            b += buffer[3] + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 19);
            a += buffer[4] + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 3);
            d += buffer[5] + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 7);
            c += buffer[6] + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 11);
            b += buffer[7] + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 19);
            a += buffer[8] + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 3);
            d += buffer[9] + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 7);
            c += buffer[10] + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 11);
            b += buffer[11] + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 19);
            a += buffer[12] + ((b & c) | (~b & d));
            a = Bits.RotateLeft32(a, 3);
            d += buffer[13] + ((a & b) | (~a & c));
            d = Bits.RotateLeft32(d, 7);
            c += buffer[14] + ((d & a) | (~d & b));
            c = Bits.RotateLeft32(c, 11);
            b += buffer[15] + ((c & d) | (~c & a));
            b = Bits.RotateLeft32(b, 19);

            a += buffer[0] + C2 + ((b & (c | d)) | (c & d));
            a = Bits.RotateLeft32(a, 3);
            d += buffer[4] + C2 + ((a & (b | c)) | (b & c));
            d = Bits.RotateLeft32(d, 5);
            c += buffer[8] + C2 + ((d & (a | b)) | (a & b));
            c = Bits.RotateLeft32(c, 9);
            b += buffer[12] + C2 + ((c & (d | a)) | (d & a));
            b = Bits.RotateLeft32(b, 13);
            a += buffer[1] + C2 + ((b & (c | d)) | (c & d));
            a = Bits.RotateLeft32(a, 3);
            d += buffer[5] + C2 + ((a & (b | c)) | (b & c));
            d = Bits.RotateLeft32(d, 5);
            c += buffer[9] + C2 + ((d & (a | b)) | (a & b));
            c = Bits.RotateLeft32(c, 9);
            b += buffer[13] + C2 + ((c & (d | a)) | (d & a));
            b = Bits.RotateLeft32(b, 13);
            a += buffer[2] + C2 + ((b & (c | d)) | (c & d));
            a = Bits.RotateLeft32(a, 3);
            d += buffer[6] + C2 + ((a & (b | c)) | (b & c));
            d = Bits.RotateLeft32(d, 5);
            c += buffer[10] + C2 + ((d & (a | b)) | (a & b));
            c = Bits.RotateLeft32(c, 9);
            b += buffer[14] + C2 + ((c & (d | a)) | (d & a));
            b = Bits.RotateLeft32(b, 13);
            a += buffer[3] + C2 + ((b & (c | d)) | (c & d));
            a = Bits.RotateLeft32(a, 3);
            d += buffer[7] + C2 + ((a & (b | c)) | (b & c));
            d = Bits.RotateLeft32(d, 5);
            c += buffer[11] + C2 + ((d & (a | b)) | (a & b));
            c = Bits.RotateLeft32(c, 9);
            b += buffer[15] + C2 + ((c & (d | a)) | (d & a));
            b = Bits.RotateLeft32(b, 13);

            a += buffer[0] + C4 + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 3);
            d += buffer[8] + C4 + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 9);
            c += buffer[4] + C4 + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 11);
            b += buffer[12] + C4 + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 15);
            a += buffer[2] + C4 + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 3);
            d += buffer[10] + C4 + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 9);
            c += buffer[6] + C4 + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 11);
            b += buffer[14] + C4 + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 15);
            a += buffer[1] + C4 + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 3);
            d += buffer[9] + C4 + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 9);
            c += buffer[5] + C4 + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 11);
            b += buffer[13] + C4 + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 15);
            a += buffer[3] + C4 + (b ^ c ^ d);
            a = Bits.RotateLeft32(a, 3);
            d += buffer[11] + C4 + (a ^ b ^ c);
            d = Bits.RotateLeft32(d, 9);
            c += buffer[7] + C4 + (d ^ a ^ b);
            c = Bits.RotateLeft32(c, 11);
            b += buffer[15] + C4 + (c ^ d ^ a);
            b = Bits.RotateLeft32(b, 15);

            State[0] = State[0] + a;
            State[1] = State[1] + b;
            State[2] = State[2] + c;
            State[3] = State[3] + d;
        }
    }
}