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
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using HashLib4CSharp.Crypto;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.KDF
{
    /// <summary>Implementation of scrypt, a password-based key derivation function.</summary>
    /// <remarks>
    /// Scrypt was created by Colin Percival and is specified in
    /// <a href="http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01">draft-josefsson-scrypt-kdf-01</a>.
    /// </remarks>
    internal sealed class PBKDFScryptNotBuiltIn : KDFNotBuiltIn, IPBKDFScryptNotBuiltIn
    {
        private byte[] _password, _salt;
        private int _cost, _blockSize, _parallelism;

        private const string InvalidByteCount = "byteCount must be a value greater than zero.";
        private const string InvalidCost = "Cost parameter must be > 1 and a power of 2.";
        private const string BlockSizeAndCostIncompatible = "Cost parameter must be > 1 and < 65536.";
        private const string BlockSizeTooSmall = "Block size must be >= 1.";

        private const string InvalidParallelism =
            "Parallelism parameter must be >= 1 and <= {0} (based on block size of {1})";

        private const string RoundsMustBeEven = "Number of Rounds Must be Even";

        private PBKDFScryptNotBuiltIn()
        {
        }

        internal PBKDFScryptNotBuiltIn(byte[] password, byte[] salt,
            int cost, int blockSize, int parallelism)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            ValidatePBKDFScryptInputs(cost, blockSize, parallelism);

            _password = ArrayUtils.Clone(password);
            _salt = ArrayUtils.Clone(salt);

            _cost = cost;
            _blockSize = blockSize;
            _parallelism = parallelism;
        }

        ~PBKDFScryptNotBuiltIn()
        {
            Clear();
        }

        private static void ValidatePBKDFScryptInputs(int cost, int blockSize,
            int parallelism)
        {
            if (cost <= 1 || !IsPowerOf2(cost))
                throw new ArgumentException(InvalidCost);

            // Only value of blockSize that cost (as an int) could be exceeded for is 1
            if (blockSize == 1 && cost >= 65536)
                throw new ArgumentException(BlockSizeAndCostIncompatible);

            if (blockSize < 1)
                throw new ArgumentException(BlockSizeTooSmall);

            var maxParallel = int.MaxValue / (128 * blockSize * 8);

            if (parallelism < 1 || parallelism > maxParallel)
                throw new ArgumentException(
                    string.Format(InvalidParallelism, maxParallel, blockSize));
        }

        public override void Clear()
        {
            ArrayUtils.ZeroFill(_password);
            ArrayUtils.ZeroFill(_salt);
        }

        /// <summary>
        /// Returns the pseudo-random bytes for this object.
        /// </summary>
        /// <param name="byteCount">The number of pseudo-random key bytes to generate.</param>
        /// <returns>A byte array filled with pseudo-random key bytes.</returns>
        /// /// <exception cref="ArgumentException">byteCount must be greater than zero.</exception>
        public override byte[] GetBytes(int byteCount)
        {
            if (byteCount <= 0)
                throw new ArgumentException(InvalidByteCount);

            return MfCrypt(_password, _salt, _cost, _blockSize, _parallelism, byteCount);
        }

        public override async Task<byte[]> GetBytesAsync(int byteCount,
            CancellationToken cancellationToken = default) =>
            await Task.Run(() => GetBytes(byteCount), cancellationToken);

        public override string Name => GetType().Name;

        public override string ToString() => Name;

        public override IKDFNotBuiltIn Clone() =>
            new PBKDFScryptNotBuiltIn()
            {
                _password = ArrayUtils.Clone(_password),
                _salt = ArrayUtils.Clone(_salt),
                _cost = _cost,
                _blockSize = _blockSize,
                _parallelism = _parallelism
            };

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ClearArray<T>(T[] input) => ArrayUtils.ZeroFill(input);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ClearAllArrays<T>(T[][] input) => ArrayUtils.ZeroFill(input);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsPowerOf2(int x) => x > 0 && (x & (x - 1)) == 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] SingleIterationPBKDF2(byte[] password,
            byte[] salt, int outputLength) =>
            new PBKDF2HMACNotBuiltIn(new SHA2_256(), password,
                salt, 1).GetBytes(outputLength);

        /// <summary>
        /// rotate left
        /// </summary>
        /// <param name="value">
        /// value to rotate
        /// </param>
        /// <param name="distance">
        /// distance to rotate value
        /// </param>
        /// <returns>
        /// rotated value
        /// </returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint RotateLeft32(uint value, int distance) => Bits.RotateLeft32(value, distance);

        /// <summary>
        /// lifted from <c>ClpSalsa20Engine.pas</c> in CryptoLib4Pascal with
        /// minor modifications.
        /// </summary>
        private static void SalsaCore(int rounds, uint[] input, uint[] x)
        {
            if (input.Length != 16)
                throw new ArgumentException("");

            if (x.Length != 16)
                throw new ArgumentException("");

            if (rounds % 2 != 0)
                throw new ArgumentException(RoundsMustBeEven);

            var x00 = input[0];
            var x01 = input[1];
            var x02 = input[2];
            var x03 = input[3];
            var x04 = input[4];
            var x05 = input[5];
            var x06 = input[6];
            var x07 = input[7];
            var x08 = input[8];
            var x09 = input[9];
            var x10 = input[10];
            var x11 = input[11];
            var x12 = input[12];
            var x13 = input[13];
            var x14 = input[14];
            var x15 = input[15];

            var i = rounds;
            while (i > 0)
            {
                x04 ^= RotateLeft32(x00 + x12, 7);
                x08 ^= RotateLeft32(x04 + x00, 9);
                x12 ^= RotateLeft32(x08 + x04, 13);
                x00 ^= RotateLeft32(x12 + x08, 18);
                x09 ^= RotateLeft32(x05 + x01, 7);
                x13 ^= RotateLeft32(x09 + x05, 9);
                x01 ^= RotateLeft32(x13 + x09, 13);
                x05 ^= RotateLeft32(x01 + x13, 18);
                x14 ^= RotateLeft32(x10 + x06, 7);
                x02 ^= RotateLeft32(x14 + x10, 9);
                x06 ^= RotateLeft32(x02 + x14, 13);
                x10 ^= RotateLeft32(x06 + x02, 18);
                x03 ^= RotateLeft32(x15 + x11, 7);
                x07 ^= RotateLeft32(x03 + x15, 9);
                x11 ^= RotateLeft32(x07 + x03, 13);
                x15 ^= RotateLeft32(x11 + x07, 18);

                x01 ^= RotateLeft32(x00 + x03, 7);
                x02 ^= RotateLeft32(x01 + x00, 9);
                x03 ^= RotateLeft32(x02 + x01, 13);
                x00 ^= RotateLeft32(x03 + x02, 18);
                x06 ^= RotateLeft32(x05 + x04, 7);
                x07 ^= RotateLeft32(x06 + x05, 9);
                x04 ^= RotateLeft32(x07 + x06, 13);
                x05 ^= RotateLeft32(x04 + x07, 18);
                x11 ^= RotateLeft32(x10 + x09, 7);
                x08 ^= RotateLeft32(x11 + x10, 9);
                x09 ^= RotateLeft32(x08 + x11, 13);
                x10 ^= RotateLeft32(x09 + x08, 18);
                x12 ^= RotateLeft32(x15 + x14, 7);
                x13 ^= RotateLeft32(x12 + x15, 9);
                x14 ^= RotateLeft32(x13 + x12, 13);
                x15 ^= RotateLeft32(x14 + x13, 18);

                i -= 2;
            }

            x[0] = x00 + input[0];
            x[1] = x01 + input[1];
            x[2] = x02 + input[2];
            x[3] = x03 + input[3];
            x[4] = x04 + input[4];
            x[5] = x05 + input[5];
            x[6] = x06 + input[6];
            x[7] = x07 + input[7];
            x[8] = x08 + input[8];
            x[9] = x09 + input[9];
            x[10] = x10 + input[10];
            x[11] = x11 + input[11];
            x[12] = x12 + input[12];
            x[13] = x13 + input[13];
            x[14] = x14 + input[14];
            x[15] = x15 + input[15];
        }

        private static void Xor(uint[] a, uint[] b, int bOffset, uint[] output)
        {
            var i = output.Length - 1;
            while (i >= 0)
            {
                output[i] = a[i] ^ b[bOffset + i];
                i--;
            }
        }

        private static unsafe void SMix(uint[] block, int blockOffset, int cost, int blockSize)
        {
            var blockCount = blockSize * 32;
            var blockX1 = new uint[16];
            var blockX2 = new uint[16];
            var blockY = new uint[blockCount];

            var x = new uint[blockCount];
            var v = new uint[cost * blockCount];

            try
            {
                int idx;
                fixed (uint* xPtr = x, blockPtr = &block[blockOffset])
                {
                    PointerUtils.MemMove(xPtr, blockPtr, blockCount * sizeof(uint));

                    var offset = 0;
                    idx = 0;
                    while (idx < cost)
                    {
                        fixed (uint* vPtr = &v[offset])
                        {
                            PointerUtils.MemMove(vPtr, xPtr, blockCount * sizeof(uint));
                        }

                        offset += blockCount;
                        BlockMix(x, blockX1, blockX2, blockY, blockSize);

                        fixed (uint* vPtr = &v[offset], blockYPtr = blockY)
                        {
                            PointerUtils.MemMove(vPtr, blockYPtr, blockCount * sizeof(uint));
                        }

                        offset += blockCount;
                        BlockMix(blockY, blockX1, blockX2, x, blockSize);
                        idx += 2;
                    }
                }

                var mask = (uint)cost - 1;
                idx = 0;
                while (idx < cost)
                {
                    var jdx = (int)(x[blockCount - 16] & mask);
                    fixed (uint* vPtr = &v[jdx * blockCount], blockYPtr = blockY)
                    {
                        PointerUtils.MemMove(blockYPtr, vPtr, blockCount * sizeof(uint));
                    }

                    Xor(blockY, x, 0, blockY);
                    BlockMix(blockY, blockX1, blockX2, x, blockSize);
                    idx++;
                }

                fixed (uint* xPtr = x, bPtr = &block[blockOffset])
                {
                    PointerUtils.MemMove(bPtr, xPtr, blockCount * sizeof(uint));
                }
            }
            finally
            {
                ClearArray(v);
                ClearAllArrays(new[] { x, blockX1, blockX2, blockY });
            }
        }

        private static unsafe void BlockMix(uint[] b, uint[] x1, uint[] x2, uint[] y, int r)
        {
            fixed (uint* bPtr = &b[b.Length - 16], x1Ptr = x1)
            {
                PointerUtils.MemMove(x1Ptr, bPtr, 16 * sizeof(uint));
            }

            var bOffset = 0;
            var yOffset = 0;
            var halfLen = b.Length / 2;

            var idx = 2 * r;

            fixed (uint* x1Ptr = x1)
            {
                while (idx > 0)
                {
                    Xor(x1, b, bOffset, x2);

                    SalsaCore(8, x2, x1);

                    fixed (uint* yPtr = &y[yOffset])
                    {
                        PointerUtils.MemMove(yPtr, x1Ptr, 16 * sizeof(uint));
                    }

                    yOffset = halfLen + bOffset - yOffset;
                    bOffset += 16;

                    idx--;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void DoSMix(uint[] block, int parallelism, int cost,
            int blockSize)
        {
            // single threaded version
            //   for (var idx = 0; idx < parallelism; idx++)
            //      SMix(block, idx * 32 * blockSize, cost, blockSize);

            Parallel.For(0, parallelism, idx => SMix(block, idx * 32 * blockSize, cost, blockSize));
        }

        private static unsafe byte[] MfCrypt(byte[] password, byte[] salt, int cost,
            int blockSize, int parallelism, int outputLength)
        {
            byte[] result;

            var bytesLength = blockSize * 128;
            var bytes = SingleIterationPBKDF2(password, salt,
                parallelism * bytesLength);
            var blockLength = bytes.Length / 4;
            var block = new uint[blockLength];

            try
            {
                fixed (uint* blockPtr = block)
                {
                    fixed (byte* bytesPtr = bytes)
                    {
                        Converters.le32_copy(bytesPtr, 0, blockPtr, 0,
                            bytes.Length * sizeof(byte));

                        DoSMix(block, parallelism, cost, blockSize);

                        Converters.le32_copy(blockPtr, 0, bytesPtr, 0,
                            block.Length * sizeof(uint));
                    }
                }

                result = SingleIterationPBKDF2(password, bytes, outputLength);
            }
            finally
            {
                ClearArray(block);
                ClearArray(bytes);
            }

            return result;
        }
    }
}