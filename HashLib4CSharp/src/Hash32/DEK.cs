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
using System.Linq;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Hash32
{
    internal sealed class DEK : MultipleTransformNonBlock, IHash32, ITransformBlock
    {
        internal DEK()
            : base(4, 1)
        {
        }

        protected override IHashResult ComputeAggregatedBytes(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            if (data.Length <= 0) return new HashResult((uint) 0);
            var hash = (uint) data.Length;

            hash = data.Aggregate(hash, (current, b) => Bits.RotateLeft32(current, 5) ^ b);

            return new HashResult(hash);
        }
    }
}