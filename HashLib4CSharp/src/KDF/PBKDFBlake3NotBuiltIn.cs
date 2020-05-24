using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Crypto;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.KDF
{
    internal sealed class PBKDFBlake3NotBuiltIn : KDFNotBuiltIn, IPBKDFBlake3NotBuiltIn
    {
        private readonly byte[] _srcKey;
        private readonly IXOF _xof;

        private const int derivationIVLen = 32;
        private const uint flagDeriveKeyContext = 1 << 5;
        private const uint flagDeriveKeyMaterial = 1 << 6;


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
            if (srcKey == null) throw new ArgumentNullHashLibException(nameof(srcKey));
            if (ctx == null) throw new ArgumentNullHashLibException(nameof(ctx));

            _srcKey = ArrayUtils.Clone(srcKey);

            var ivWords = ArrayUtils.Clone(Blake3.IV);

            // construct the derivation Hasher and get the derivationIV
            var derivationIV = new Blake3(derivationIVLen, ivWords, flagDeriveKeyContext)
                .ComputeBytes(ctx).GetBytes();

            fixed (byte* srcPtr = derivationIV)
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

        public override byte[] GetBytes(int byteCount)
        {
            var result = new byte[byteCount];
            _xof.XofSizeInBits = (ulong) byteCount * 8;
            _xof.Initialize();
            _xof.TransformBytes(_srcKey);
            // derive the SubKey
            _xof.DoOutput(result, 0, (ulong) result.Length);
            _xof.Initialize();
            return result;
        }

        public override async Task<byte[]> GetBytesAsync(int byteCount,
            CancellationToken cancellationToken = default(CancellationToken)) =>
            await Task.Run(() => GetBytes(byteCount), cancellationToken);

        public override string Name => GetType().Name;
    }
}