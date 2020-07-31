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
using System.Runtime.CompilerServices;
using HashLib4CSharp.Base;
using HashLib4CSharp.Interfaces;
using HashLib4CSharp.Params;
using HashLib4CSharp.Utils;

namespace HashLib4CSharp.Crypto
{
    internal class Blake2B : Hash, ICryptoNotBuiltIn, ITransformBlock
    {
        private const string InvalidConfigLength = "Config length must be 8 words";

        private const int BlockSizeInBytes = 128;

        private const ulong IV0 = 0x6A09E667F3BCC908;
        private const ulong IV1 = 0xBB67AE8584CAA73B;
        private const ulong IV2 = 0x3C6EF372FE94F82B;
        private const ulong IV3 = 0xA54FF53A5F1D36F1;
        private const ulong IV4 = 0x510E527FADE682D1;
        private const ulong IV5 = 0x9B05688C2B3E6C1F;
        private const ulong IV6 = 0x1F83D9ABFB41BD6B;
        private const ulong IV7 = 0x5BE0CD19137E2179;


        internal readonly Blake2BConfig Config;
        protected Blake2BTreeConfig TreeConfig;
        private readonly bool _doTransformKeyBlock;

        protected ulong[] State;
        protected ulong[] M;
        protected byte[] Buffer;

        protected int FilledBufferCount;
        protected ulong Counter0, Counter1, FinalizationFlag0, FinalizationFlag1;

        internal Blake2B(Blake2BConfig config, Blake2BTreeConfig treeConfig = null,
            bool doTransformKeyBlock = true)
            : base(config?.HashSize ?? throw new ArgumentNullException(nameof(config)), BlockSizeInBytes)
        {
            Config = config.Clone();
            TreeConfig = treeConfig?.Clone();
            _doTransformKeyBlock = doTransformKeyBlock;

            State = new ulong[8];
            M = new ulong[16];
            Buffer = new byte[BlockSizeInBytes];
        }

        internal Blake2B CloneInternal() =>
            new Blake2B(Config, TreeConfig, _doTransformKeyBlock)
            {
                State = ArrayUtils.Clone(State),
                Buffer = ArrayUtils.Clone(Buffer),
                FilledBufferCount = FilledBufferCount,
                Counter0 = Counter0,
                Counter1 = Counter1,
                FinalizationFlag0 = FinalizationFlag0,
                FinalizationFlag1 = FinalizationFlag1,
                BufferSize = BufferSize
            };

        public override string Name => $"{GetType().Name}_{HashSize * 8}";

        public override IHash Clone() => CloneInternal();

        public override unsafe void Initialize()
        {
            int idx;
            Span<byte> block = null;

            Span<ulong> rawConfig = Blake2BIvBuilder.ConfigB(Config, ref TreeConfig);

            if (_doTransformKeyBlock)
            {
                if (Config.Key.Length != 0)
                {
                    block = new byte[BlockSizeInBytes];
                    fixed (byte* ptrBlock = block, ptrKey = Config.Key)
                    {
                        PointerUtils.MemMove(ptrBlock, ptrKey, Config.Key.Length);
                    }
                }
            }

            if (rawConfig.Length != 8)
                throw new ArgumentException(InvalidConfigLength);

            State[0] = IV0;
            State[1] = IV1;
            State[2] = IV2;
            State[3] = IV3;
            State[4] = IV4;
            State[5] = IV5;
            State[6] = IV6;
            State[7] = IV7;

            Counter0 = 0;
            Counter1 = 0;
            FinalizationFlag0 = 0;
            FinalizationFlag1 = 0;

            FilledBufferCount = 0;

            ArrayUtils.ZeroFill(Buffer);
            ArrayUtils.ZeroFill(M);

            for (idx = 0; idx < 8; idx++)
                State[idx] = State[idx] ^ rawConfig[idx];

            if (!_doTransformKeyBlock) return;
            if (block == null) return;
            TransformByteSpan(block.Slice(0, block.Length));
        }

        public override unsafe void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var length = data.Length;
            var offset = 0;
            var bufferRemaining = BlockSizeInBytes - FilledBufferCount;

            if (FilledBufferCount > 0 && length > bufferRemaining)
            {
                if (bufferRemaining > 0)
                {
                    fixed (byte* bufferPtr = &Buffer[FilledBufferCount], dataPtr = &data[offset])
                    {
                        PointerUtils.MemMove(bufferPtr, dataPtr, bufferRemaining);
                    }
                }

                Blake2BIncrementCounter(BlockSizeInBytes);

                fixed (byte* bufferPtr = Buffer)
                {
                    Compress(bufferPtr, 0);
                }

                offset += bufferRemaining;
                length -= bufferRemaining;
                FilledBufferCount = 0;
            }

            fixed (byte* dataPtr = data)
            {
                while (length > BlockSizeInBytes)
                {
                    Blake2BIncrementCounter(BlockSizeInBytes);
                    Compress(dataPtr, offset);
                    offset += BlockSizeInBytes;
                    length -= BlockSizeInBytes;
                }
            }

            if (length > 0)
            {
                fixed (byte* bufferPtr = &Buffer[FilledBufferCount], dataPtr = &data[offset])
                {
                    PointerUtils.MemMove(bufferPtr, dataPtr, length);
                    FilledBufferCount += length;
                }
            }
        }

        public override unsafe IHashResult TransformFinal()
        {
            Finish();

            var buffer = new byte[HashSize];

            fixed (ulong* ptrState = State)
            {
                fixed (byte* ptrBuffer = buffer)
                {
                    Converters.le64_copy(ptrState, 0, ptrBuffer, 0,
                        buffer.Length);
                }
            }

            var result = new HashResult(buffer);
            Initialize();
            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void Compress(byte* block, int start)
        {
            fixed (ulong* ptrState = State, ptrM = M)
            {
                Converters.le64_copy(block, start, ptrM, 0, BlockSize);
                MixScalar(ptrState, ptrM);
            }
        }

        private unsafe void MixScalar(ulong* ptrState, ulong* ptrM)
        {
            var m0 = ptrM[0];
            var m1 = ptrM[1];
            var m2 = ptrM[2];
            var m3 = ptrM[3];
            var m4 = ptrM[4];
            var m5 = ptrM[5];
            var m6 = ptrM[6];
            var m7 = ptrM[7];
            var m8 = ptrM[8];
            var m9 = ptrM[9];
            var m10 = ptrM[10];
            var m11 = ptrM[11];
            var m12 = ptrM[12];
            var m13 = ptrM[13];
            var m14 = ptrM[14];
            var m15 = ptrM[15];

            var v0 = ptrState[0];
            var v1 = ptrState[1];
            var v2 = ptrState[2];
            var v3 = ptrState[3];
            var v4 = ptrState[4];
            var v5 = ptrState[5];
            var v6 = ptrState[6];
            var v7 = ptrState[7];

            var v8 = IV0;
            var v9 = IV1;
            var v10 = IV2;
            var v11 = IV3;
            var v12 = IV4 ^ Counter0;
            var v13 = IV5 ^ Counter1;
            var v14 = IV6 ^ FinalizationFlag0;
            var v15 = IV7 ^ FinalizationFlag1;

            // Rounds

            // ##### Round(0)
            // G(0, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m0;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m1;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(0, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m2;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m3;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(0, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m4;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m5;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(0, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m6;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m7;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(0, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m8;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m9;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(0, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m10;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m11;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(0, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m12;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m13;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(0, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m14;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m15;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(1)
            // G(1, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m14;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m10;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(1, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m4;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m8;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(1, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m9;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m15;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(1, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m13;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m6;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(1, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m1;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m12;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(1, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m0;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m2;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(1, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m11;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m7;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(1, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m5;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m3;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(2)
            // G(2, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m11;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m8;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(2, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m12;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m0;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(2, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m5;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m2;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(2, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m15;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m13;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(2, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m10;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m14;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(2, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m3;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m6;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(2, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m7;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m1;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(2, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m9;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m4;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(3)
            // G(3, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m7;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m9;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(3, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m3;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m1;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(3, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m13;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m12;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(3, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m11;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m14;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(3, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m2;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m6;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(3, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m5;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m10;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(3, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m4;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m0;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(3, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m15;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m8;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(4)
            // G(4, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m9;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m0;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(4, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m5;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m7;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(4, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m2;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m4;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(4, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m10;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m15;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(4, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m14;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m1;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(4, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m11;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m12;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(4, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m6;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m8;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(4, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m3;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m13;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(5)
            // G(5, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m2;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m12;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(5, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m6;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m10;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(5, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m0;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m11;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(5, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m8;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m3;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(5, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m4;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m13;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(5, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m7;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m5;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(5, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m15;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m14;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(5, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m1;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m9;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(6)
            // G(6, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m12;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m5;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(6, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m1;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m15;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(6, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m14;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m13;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(6, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m4;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m10;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(6, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m0;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m7;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(6, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m6;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m3;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(6, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m9;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m2;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(6, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m8;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m11;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(7)
            // G(7, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m13;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m11;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(7, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m7;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m14;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(7, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m12;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m1;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(7, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m3;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m9;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(7, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m5;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m0;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(7, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m15;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m4;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(7, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m8;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m6;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(7, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m2;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m10;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(8)
            // G(8, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m6;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m15;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(8, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m14;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m9;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(8, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m11;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m3;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(8, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m0;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m8;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(8, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m12;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m2;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(8, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m13;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m7;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(8, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m1;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m4;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(8, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m10;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m5;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(9)
            // G(9, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m10;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m2;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(9, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m8;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m4;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(9, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m7;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m6;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(9, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m1;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m5;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(9, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m15;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m11;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(9, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m9;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m14;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(9, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m3;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m12;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(9, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m13;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m0;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(10)
            // G(10, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m0;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m1;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(10, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m2;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m3;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(10, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m4;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m5;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(10, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m6;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m7;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(10, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m8;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m9;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(10, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m10;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m11;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(10, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m12;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m13;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(10, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m14;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m15;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // ##### Round(11)
            // G(11, 0, v0, v4, v8, v12)
            v0 = v0 + v4 + m14;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 32);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 24);
            v0 = v0 + v4 + m10;
            v12 ^= v0;
            v12 = Bits.RotateRight64(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight64(v4, 63);

            // G(11, 1, v1, v5, v9, v13)
            v1 = v1 + v5 + m4;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 32);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 24);
            v1 = v1 + v5 + m8;
            v13 ^= v1;
            v13 = Bits.RotateRight64(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight64(v5, 63);

            // G(11, 2, v2, v6, v10, v14)
            v2 = v2 + v6 + m9;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 32);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 24);
            v2 = v2 + v6 + m15;
            v14 ^= v2;
            v14 = Bits.RotateRight64(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight64(v6, 63);

            // G(11, 3, v3, v7, v11, v15)
            v3 = v3 + v7 + m13;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 32);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 24);
            v3 = v3 + v7 + m6;
            v15 ^= v3;
            v15 = Bits.RotateRight64(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight64(v7, 63);

            // G(11, 4, v0, v5, v10, v15)
            v0 = v0 + v5 + m1;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 32);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 24);
            v0 = v0 + v5 + m12;
            v15 ^= v0;
            v15 = Bits.RotateRight64(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight64(v5, 63);

            // G(11, 5, v1, v6, v11, v12)
            v1 = v1 + v6 + m0;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 32);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 24);
            v1 = v1 + v6 + m2;
            v12 ^= v1;
            v12 = Bits.RotateRight64(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight64(v6, 63);

            // G(11, 6, v2, v7, v8, v13)
            v2 = v2 + v7 + m11;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 32);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 24);
            v2 = v2 + v7 + m7;
            v13 ^= v2;
            v13 = Bits.RotateRight64(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight64(v7, 63);

            // G(11, 7, v3, v4, v9, v14)
            v3 = v3 + v4 + m5;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 32);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 24);
            v3 = v3 + v4 + m3;
            v14 ^= v3;
            v14 = Bits.RotateRight64(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight64(v4, 63);

            // Finalization
            ptrState[0] = ptrState[0] ^ v0 ^ v8;
            ptrState[1] = ptrState[1] ^ v1 ^ v9;
            ptrState[2] = ptrState[2] ^ v2 ^ v10;
            ptrState[3] = ptrState[3] ^ v3 ^ v11;
            ptrState[4] = ptrState[4] ^ v4 ^ v12;
            ptrState[5] = ptrState[5] ^ v5 ^ v13;
            ptrState[6] = ptrState[6] ^ v6 ^ v14;
            ptrState[7] = ptrState[7] ^ v7 ^ v15;
        }

        protected unsafe void Finish()
        {
            // Last compression
            Blake2BIncrementCounter((ulong)FilledBufferCount);

            FinalizationFlag0 = ulong.MaxValue;

            if (TreeConfig != null && TreeConfig.IsLastNode)
                FinalizationFlag1 = ulong.MaxValue;

            var count = Buffer.Length - FilledBufferCount;

            if (count > 0)
                ArrayUtils.Fill(Buffer, FilledBufferCount, count + FilledBufferCount, (byte)0);

            fixed (byte* bufferPtr = Buffer)
            {
                Compress(bufferPtr, 0);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Blake2BIncrementCounter(ulong incrementCount)
        {
            Counter0 += incrementCount;
            Counter1 += Convert.ToUInt64(Counter0 < incrementCount);
        }
    }

    internal sealed class Blake2XB : Blake2B, IXOF
    {
        private const string InvalidXofSize = "XOFSizeInBits must be multiples of 8 and be between {0} and {1} bytes.";
        private const string InvalidOutputLength = "Output length is above the digest length";
        private const string MaximumOutputLengthExceeded = "Maximum length is 2^32 blocks of 64 bytes";
        private const string WriteToXofAfterReadError = "'{0}' write to Xof after read not allowed";

        private const int Blake2BHashSize = 64;

        // Magic number to indicate an unknown length of digest
        private const uint UnknownDigestLengthInBytes = (uint)(((ulong)1 << 32) - 1);
        private const ulong MaxNumberBlocks = (ulong)1 << 32;

        // 2^32 blocks of 64 bytes (256GiB)
        // the maximum size in bytes the digest can produce when the length is unknown
        private const ulong UnknownMaxDigestLengthInBytes = MaxNumberBlocks * Blake2BHashSize;

        private ulong _xofSizeInBits, _digestPosition;

        private Blake2XBConfig _outputConfig;

        private byte[] _rootHashDigest, _buffer;
        private bool _finalized;

        public ulong XofSizeInBits
        {
            get => _xofSizeInBits;
            set => SetXofSizeInBitsInternal(value);
        }

        public unsafe void DoOutput(Span<byte> dest)
        {
            if (dest == null) throw new ArgumentNullException(nameof(dest));

            var outputLength = dest.Length;
            var destOffset = 0;

            if (XofSizeInBits >> 3 != UnknownDigestLengthInBytes)
            {
                if (_digestPosition + (ulong)outputLength > XofSizeInBits >> 3)
                    throw new ArgumentException(InvalidOutputLength);
            }
            else if (_digestPosition == UnknownMaxDigestLengthInBytes)
                throw new ArgumentException(MaximumOutputLengthExceeded);

            if (!_finalized)
            {
                Finish();
                _finalized = true;
            }

            if (_rootHashDigest == null)
            {
                // Get root digest
                _rootHashDigest = new byte[Blake2BHashSize];
                fixed (ulong* statePtr = State)
                {
                    fixed (byte* rootHashDigestPtr = _rootHashDigest)
                    {
                        Converters.le64_copy(statePtr, 0, rootHashDigestPtr, 0,
                            _rootHashDigest.Length);
                    }
                }
            }

            while (outputLength > 0)
            {
                if ((_digestPosition & Blake2BHashSize - 1) == 0)
                {
                    _outputConfig.Config.HashSize = ComputeStepLength();
                    _outputConfig.TreeConfig.InnerHashSize = Blake2BHashSize;

                    _buffer = new Blake2B(_outputConfig.Config, _outputConfig.TreeConfig)
                        .ComputeByteSpan(_rootHashDigest).GetBytes();
                    _outputConfig.TreeConfig.NodeOffset += 1;
                }

                var blockOffset = (int)(_digestPosition & (Blake2BHashSize - 1));

                var diff = _buffer.Length - blockOffset;

                var count = Math.Min(outputLength, diff);

                fixed (byte* bufferPtr = &_buffer[blockOffset], destPtr = &dest[destOffset])
                {
                    PointerUtils.MemMove(destPtr, bufferPtr, count);
                }

                outputLength -= count;
                destOffset += count;
                _digestPosition += (ulong)count;
            }
        }

        public override string Name => GetType().Name;

        private void DoOutput(byte[] dest, int destOffset, int outputLength)
        {
            DoOutput(dest.AsSpan().Slice(destOffset, outputLength));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Blake2BConfig CreateConfig(Blake2XBConfig config) =>
            config.Config ?? Blake2BConfig.DefaultConfig;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Blake2BTreeConfig CreateTreeConfig(Blake2XBConfig config) =>
            config.TreeConfig ?? Blake2BTreeConfig.SequentialTreeConfig;

        internal Blake2XB(Blake2XBConfig config) : this(CreateConfig(config),
            CreateTreeConfig(config))
        {
            _buffer = new byte[Blake2BHashSize];

            // Create initial config for output hashes.
            _outputConfig = Blake2XBConfig.CreateBlake2XBConfig(new Blake2BConfig
            {
                Salt = Config.Salt,
                Personalization = Config.Personalization
            }, Blake2BTreeConfig.DefaultTreeConfig);
        }

        private Blake2XB(Blake2BConfig config, Blake2BTreeConfig treeConfig)
            : base(config, treeConfig)
        {
        }

        public override void Initialize()
        {
            var xofSizeInBytes = XofSizeInBits >> 3;

            TreeConfig.NodeOffset = NodeOffsetWithXofDigestLength(xofSizeInBytes);
            _outputConfig.TreeConfig.NodeOffset = NodeOffsetWithXofDigestLength(xofSizeInBytes);

            _rootHashDigest = null;
            _digestPosition = 0;
            _finalized = false;

            ArrayUtils.ZeroFill(_buffer);
            base.Initialize();
        }

        public override IHash Clone() =>
            new Blake2XB(Config, TreeConfig)
            {
                // Blake2B Cloning
                M = ArrayUtils.Clone(M),
                State = ArrayUtils.Clone(State),
                Buffer = ArrayUtils.Clone(Buffer),
                FilledBufferCount = FilledBufferCount,
                Counter0 = Counter0,
                Counter1 = Counter1,
                FinalizationFlag0 = FinalizationFlag0,
                FinalizationFlag1 = FinalizationFlag1,
                BufferSize = BufferSize,
                // Blake2XB Cloning
                _digestPosition = _digestPosition,
                _outputConfig = _outputConfig.Clone(),
                _rootHashDigest = ArrayUtils.Clone(_rootHashDigest),
                _buffer = ArrayUtils.Clone(_buffer),
                _finalized = _finalized,
                // Xof Cloning
                XofSizeInBits = XofSizeInBits
            };

        public override void TransformByteSpan(ReadOnlySpan<byte> data)
        {
            if (_finalized)
                throw new InvalidOperationException(string.Format(WriteToXofAfterReadError, Name));

            base.TransformByteSpan(data);
        }

        public override IHashResult TransformFinal()
        {
            var buffer = GetResult();
            Debug.Assert((ulong)buffer.Length == XofSizeInBits >> 3);
            Initialize();

            return new HashResult(buffer);
        }

        private void SetXofSizeInBitsInternal(ulong xofSizeInBits)
        {
            var xofSizeInBytes = xofSizeInBits >> 3;
            if ((xofSizeInBits & 0x7) != 0 || xofSizeInBytes < 1 ||
                xofSizeInBytes > UnknownDigestLengthInBytes)
                throw new ArgumentException(
                    string.Format(InvalidXofSize, 1, (ulong)UnknownDigestLengthInBytes));

            _xofSizeInBits = xofSizeInBits;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong NodeOffsetWithXofDigestLength(ulong xofSizeInBytes) => xofSizeInBytes << 32;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private int ComputeStepLength()
        {
            var xofSizeInBytes = XofSizeInBits >> 3;
            var diff = xofSizeInBytes - _digestPosition;

            if (xofSizeInBytes == UnknownDigestLengthInBytes)
                return Blake2BHashSize;

            return (int)Math.Min(Blake2BHashSize, diff);
        }

        private byte[] GetResult()
        {
            var xofSizeInBytes = (int)(XofSizeInBits >> 3);

            var result = new byte[xofSizeInBytes];

            DoOutput(result, 0, xofSizeInBytes);

            return result;
        }
    }
}