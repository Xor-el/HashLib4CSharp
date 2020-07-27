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

namespace HashLib4CSharp.Hash64
{
    internal class FNV64 : Hash, IHash64, ITransformBlock
    {
        protected ulong Hash;

        internal FNV64()
            : base(8, 1)
        {
        }

        public override IHash Clone() => new FNV64 {Hash = Hash, BufferSize = BufferSize};

        public override void Initialize() => Hash = 0;

        public override IHashResult TransformFinal()
        {
            var result = new HashResult(Hash);
            Initialize();
            return result;
        }

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var length = data.Length;
            var i = 0;
            var hash = Hash;
            while (length > 0)
            {
                hash = (hash * 1099511628211) ^ data[i];
                i++;
                length--;
            }

            Hash = hash;
        }
    }
}