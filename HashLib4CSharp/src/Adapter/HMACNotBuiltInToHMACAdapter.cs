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
    internal sealed class HMACNotBuiltInToHMACAdapter : HMAC
    {
        private readonly IHMACNotBuiltIn _hmacNotBuiltIn;

        internal HMACNotBuiltInToHMACAdapter(IHMACNotBuiltIn hmacNotBuiltIn)
        {
            _hmacNotBuiltIn = hmacNotBuiltIn != null
                ? (IHMACNotBuiltIn) hmacNotBuiltIn.Clone()
                : throw new ArgumentNullException(nameof(hmacNotBuiltIn));
            BlockSizeValue = hmacNotBuiltIn.BlockSize;
            HashSizeValue = hmacNotBuiltIn.HashSize * 8;
            Initialize();
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array == null) throw new ArgumentNullException(nameof(array));
            Debug.Assert(cbSize >= 0);
            Debug.Assert(ibStart >= 0);
            Debug.Assert(ibStart + cbSize <= array.Length);

            _hmacNotBuiltIn.TransformByteSpan(array.AsSpan().Slice(ibStart, cbSize));
        }

        protected override byte[] HashFinal()
        {
            var hashValue = _hmacNotBuiltIn.TransformFinal().GetBytes();
            HashValue = ArrayUtils.Clone(hashValue);
            return hashValue;
        }

        public override byte[] Key
        {
            get => _hmacNotBuiltIn.WorkingKey;
            set => _hmacNotBuiltIn.Key = value;
        }

        public override void Initialize() => _hmacNotBuiltIn.Initialize();

        public override string ToString() => $"{GetType().Name}({_hmacNotBuiltIn.Name})";
    }
}