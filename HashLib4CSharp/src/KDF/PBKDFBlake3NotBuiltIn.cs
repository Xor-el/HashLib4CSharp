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
using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Crypto;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.KDF
{
    internal sealed class PBKDFBlake3NotBuiltIn : KDFNotBuiltIn, IPBKDFBlake3NotBuiltIn
    {
        private byte[] _srcKey;
        private IXOF _xof;

        private const int derivationIVLen = 32;
        private const uint flagDeriveKeyContext = 1 << 5;
        private const uint flagDeriveKeyMaterial = 1 << 6;


        private PBKDFBlake3NotBuiltIn()
        {
        }

        // derives a subkey from ctx and srcKey. ctx should be hardcoded,
        // globally unique, and application-specific. A good format for ctx strings is:
        //
        // [application] [commit timestamp] [purpose]
        //
        // e.g.:
        //
        // example.com 2019-12-25 16:18:03 session tokens v1
        //
        // The purpose of these requirements is to ensure that an attacker cannot trick
        // two different applications into using the same context string.
        internal unsafe PBKDFBlake3NotBuiltIn(byte[] srcKey, byte[] ctx)
        {
            if (srcKey == null) throw new ArgumentNullException(nameof(srcKey));
            if (ctx == null) throw new ArgumentNullException(nameof(ctx));

            _srcKey = ArrayUtils.Clone(srcKey);

            var ivWords = ArrayUtils.Clone(Blake3.IV);

            // construct the derivation Hasher and get the derivationIV
            var derivationIv = new Blake3(derivationIVLen, ivWords, flagDeriveKeyContext)
                .ComputeByteSpan(ctx).GetBytes();

            fixed (byte* srcPtr = derivationIv)
            {
                fixed (uint* destPtr = ivWords)
                {
                    Converters.le32_copy(srcPtr, 0, destPtr, 0, Blake3.KeyLengthInBytes);
                }
            }

            _xof = new Blake3XOF(32, ivWords, flagDeriveKeyMaterial);
        }

        public override void Clear() => ArrayUtils.ZeroFill(_srcKey);

        public override string ToString() => Name;

        public override IKDFNotBuiltIn Clone() =>
            new PBKDFBlake3NotBuiltIn()
            {
                _srcKey = ArrayUtils.Clone(_srcKey),
                _xof = (IXOF) _xof.Clone()
            };

        public override byte[] GetBytes(int byteCount)
        {
            var result = new byte[byteCount];
            _xof.XofSizeInBits = (ulong) byteCount * 8;
            _xof.Initialize();
            _xof.TransformByteSpan(_srcKey);
            // derive the SubKey
            _xof.DoOutput(result.AsSpan());
            _xof.Initialize();
            return result;
        }

        public override async Task<byte[]> GetBytesAsync(int byteCount,
            CancellationToken cancellationToken = default) =>
            await Task.Run(() => GetBytes(byteCount), cancellationToken);

        public override string Name => GetType().Name;
    }
}