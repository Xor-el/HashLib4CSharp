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
    internal sealed class SDBM : Hash, IHash32, ITransformBlock
    {
        private uint _hash;

        internal SDBM()
            : base(4, 1)
        {
        }

        public override IHash Clone()
        {
            return new SDBM { _hash = _hash, BufferSize = BufferSize };
        }

        public override void Initialize()
        {
            _hash = 0;
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
            while (length > 0)
            {
                hash = (uint)(data[i] + (long)(hash << 6) + (hash << 16) - hash);
                i++;
                length--;
            }

            _hash = hash;
        }
    }
}