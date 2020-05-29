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

namespace HashLib4CSharp.Hash32
{
    internal sealed class SuperFast : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        internal SuperFast()
            : base(4, 4)
        {
        }

        protected override IHashResult ComputeAggregatedBytes(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            int i1, i2;

            if (data.Length == 0)
                return new HashResult(0);

            var length = data.Length;

            var hash = (uint) length;
            var currentIndex = 0;

            while (length >= 4)
            {
                i1 = data[currentIndex];
                currentIndex++;
                i2 = data[currentIndex] << 8;
                currentIndex++;
                hash = (ushort) (hash + (uint) (i1 | i2));
                var u1 = (uint) data[currentIndex];
                currentIndex++;
                var tmp = (uint) (((byte) u1 | data[currentIndex] << 8) << 11) ^ hash;
                currentIndex++;
                hash = (hash << 16) ^ tmp;
                hash += hash >> 11;

                length -= 4;
            }

            switch (length)
            {
                case 3:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex];
                    currentIndex++;
                    hash += (ushort) (i1 | i2 << 8);
                    hash ^= hash << 16;
                    hash ^= (uint) data[currentIndex] << 18;
                    hash += hash >> 11;
                    break;

                case 2:
                    i1 = data[currentIndex];
                    currentIndex++;
                    i2 = data[currentIndex];
                    hash += (ushort) (i1 | i2 << 8);
                    hash ^= hash << 11;
                    hash += hash >> 17;
                    break;

                case 1:
                    i1 = data[currentIndex];
                    hash += (uint) i1;
                    hash ^= hash << 10;
                    hash += hash >> 1;
                    break;
            }

            hash ^= hash << 3;
            hash += hash >> 5;
            hash ^= hash << 4;
            hash += hash >> 17;
            hash ^= hash << 25;
            hash += hash >> 6;

            return new HashResult(hash);
        }
    }
}