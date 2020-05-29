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

namespace HashLib4CSharp.Hash32
{
    internal sealed class Jenkins3 : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        private int _initialValue;

        internal Jenkins3(int initialValue = 0)
            : base(4, 12)
        {
            _initialValue = initialValue;
        }

        public override IHash Clone()
        {
            var hashInstance = base.Clone();
            ((Jenkins3) hashInstance)._initialValue = _initialValue;
            return hashInstance;
        }

        protected override IHashResult ComputeAggregatedBytes(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            int i1, i2, i3, i4;

            var length = data.Length;

            var a = 0xDEADBEEF + (uint) length + (uint) _initialValue;
            var b = a;
            var c = b;

            if (length == 0) return new HashResult(c);

            var currentIndex = 0;
            while (length > 12)
            {
                i1 = data[currentIndex];
                currentIndex++;
                i2 = data[currentIndex] << 8;
                currentIndex++;
                i3 = data[currentIndex] << 16;
                currentIndex++;
                i4 = data[currentIndex] << 24;
                currentIndex++;

                a += (uint) (i1 | i2 | i3 | i4);

                i1 = data[currentIndex];
                currentIndex++;
                i2 = data[currentIndex] << 8;
                currentIndex++;
                i3 = data[currentIndex] << 16;
                currentIndex++;
                i4 = data[currentIndex] << 24;
                currentIndex++;

                b += (uint) (i1 | i2 | i3 | i4);

                i1 = data[currentIndex];
                currentIndex++;
                i2 = data[currentIndex] << 8;
                currentIndex++;
                i3 = data[currentIndex] << 16;
                currentIndex++;
                i4 = data[currentIndex] << 24;
                currentIndex++;

                c += (uint) (i1 | i2 | i3 | i4);

                a -= c;
                a ^= Bits.RotateLeft32(c, 4);
                c += b;
                b -= a;
                b ^= Bits.RotateLeft32(a, 6);
                a += c;
                c -= b;
                c ^= Bits.RotateLeft32(b, 8);
                b += a;
                a -= c;
                a ^= Bits.RotateLeft32(c, 16);
                c += b;
                b -= a;
                b ^= Bits.RotateLeft32(a, 19);
                a += c;
                c -= b;
                c ^= Bits.RotateLeft32(b, 4);
                b += a;

                length -= 12;
            }

            switch (length)
            {
                case 12:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    a += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    b += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;

                    c += (uint) (i1 | i2 | i3 | i4);
                    break;

                case 11:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    a += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    b += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;

                    c += (uint) (i1 | i2 | i3);
                    break;

                case 10:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    a += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    b += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;

                    c += (uint) (i1 | i2);
                    break;

                case 9:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    a += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    b += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];

                    c += (uint) i1;
                    break;

                case 8:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    a += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;

                    b += (uint) (i1 | i2 | i3 | i4);
                    break;

                case 7:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    a += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;

                    b += (uint) (i1 | i2 | i3);
                    break;

                case 6:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    a += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;

                    b += (uint) (i1 | i2);
                    break;

                case 5:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;
                    currentIndex++;

                    a += (uint) (i1 | i2 | i3 | i4);

                    i1 = data[currentIndex];

                    b += (uint) i1;
                    break;

                case 4:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;
                    currentIndex++;
                    i4 = data[currentIndex] << 24;

                    a += (uint) (i1 | i2 | i3 | i4);
                    break;

                case 3:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;
                    currentIndex++;
                    i3 = data[currentIndex] << 16;

                    a += (uint) (i1 | i2 | i3);
                    break;

                case 2:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex] << 8;

                    a += (uint) (i1 | i2);
                    break;

                case 1:
                    i1 = data[currentIndex];

                    a += (uint) i1;
                    break;
            }

            c ^= b;
            c -= Bits.RotateLeft32(b, 14);
            a ^= c;
            a -= Bits.RotateLeft32(c, 11);
            b ^= a;
            b -= Bits.RotateLeft32(a, 25);
            c ^= b;
            c -= Bits.RotateLeft32(b, 16);
            a ^= c;
            a -= Bits.RotateLeft32(c, 4);
            b ^= a;
            b -= Bits.RotateLeft32(a, 14);
            c ^= b;
            c -= Bits.RotateLeft32(b, 24);

            return new HashResult(c);
        }
    }
}