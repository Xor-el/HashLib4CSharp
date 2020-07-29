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
using System.Diagnostics;
using System.Security.Cryptography;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Adapter
{
    internal sealed class HashToHashAlgorithmAdapter : HashAlgorithm
    {
        private readonly IHash _hash;

        internal HashToHashAlgorithmAdapter(IHash hash)
        {
            _hash = hash != null
                ? hash.Clone()
                : throw new ArgumentNullException(nameof(hash));
            HashSizeValue = _hash.HashSize * 8;
            Initialize();
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array == null) throw new ArgumentNullException(nameof(array));
            Debug.Assert(cbSize >= 0);
            Debug.Assert(ibStart >= 0);
            Debug.Assert(ibStart + cbSize <= array.Length);

            _hash.TransformByteSpan(array.AsSpan().Slice( ibStart, cbSize));
        }

        protected override byte[] HashFinal()
        {
            var hashValue = _hash.TransformFinal().GetBytes();
            HashValue = ArrayUtils.Clone(hashValue);
            return hashValue;
        }

        public override void Initialize() => _hash.Initialize();

        public override string ToString() => $"{GetType().Name}({_hash.Name})";
    }
}