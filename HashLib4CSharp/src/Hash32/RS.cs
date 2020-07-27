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
    internal sealed class RS : Hash, IHash32, ITransformBlock
    {
        private uint _a, _hash;
        private const uint B = 378551;

        internal RS()
            : base(4, 1)
        {
        }

        public override IHash Clone()
        {
            var hashInstance = new RS { _hash = _hash, _a = _a, BufferSize = BufferSize };
            return hashInstance;
        }

        public override void Initialize()
        {
            _hash = 0;
            _a = 63689;
        }

        public override IHashResult TransformFinal()
        {
            var result = new HashResult(_hash);
            Initialize();
            return result;
        }

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var length = data.Length;
            var i = 0;
            var hash = _hash;
            var a = _a;
            while (length > 0)
            {
                hash = (hash * a) + data[i];
                a *= B;
                i++;
                length--;
            }

            _a = a;
            _hash = hash;
        }
    }
}