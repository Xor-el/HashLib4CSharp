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
    internal class Blake2S : Hash, ICryptoNotBuiltIn, ITransformBlock
    {
        private const string InvalidConfigLength = "Config length must be 8 words";

        private const int BlockSizeInBytes = 64;

        private const uint IV0 = 0x6A09E667;
        private const uint IV1 = 0xBB67AE85;
        private const uint IV2 = 0x3C6EF372;
        private const uint IV3 = 0xA54FF53A;
        private const uint IV4 = 0x510E527F;
        private const uint IV5 = 0x9B05688C;
        private const uint IV6 = 0x1F83D9AB;
        private const uint IV7 = 0x5BE0CD19;

        internal readonly Blake2SConfig Config;
        protected Blake2STreeConfig TreeConfig;
        private readonly bool _doTransformKeyBlock;

        protected uint[] State;
        protected uint[] M;
        protected byte[] Buffer;

        protected int FilledBufferCount;
        protected uint Counter0, Counter1, FinalizationFlag0, FinalizationFlag1;

        internal Blake2S(Blake2SConfig config, Blake2STreeConfig treeConfig = null,
            bool doTransformKeyBlock = true)
            : base(config?.HashSize ?? throw new ArgumentNullException(nameof(config)), BlockSizeInBytes)
        {
            Config = config.Clone();
            TreeConfig = treeConfig?.Clone();
            _doTransformKeyBlock = doTransformKeyBlock;

            State = new uint[8];
            M = new uint[16];
            Buffer = new byte[BlockSizeInBytes];
        }

        internal Blake2S CloneInternal() =>
            new Blake2S(Config, TreeConfig, _doTransformKeyBlock)
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

            Span<uint> rawConfig = Blake2SIvBuilder.ConfigB(Config, ref TreeConfig);

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

                Blake2SIncrementCounter(BlockSizeInBytes);

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
                    Blake2SIncrementCounter(BlockSizeInBytes);
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

            fixed (uint* ptrState = State)
            {
                fixed (byte* ptrBuffer = buffer)
                {
                    Converters.le32_copy(ptrState, 0, ptrBuffer, 0,
                        buffer.Length);
                }
            }

            var result = new HashResult(buffer);
            Initialize();
            return result;
        }

        private unsafe void Compress(byte* block, int start)
        {
            fixed (uint* ptrState = State, ptrM = M)
            {
                Converters.le32_copy(block, start, ptrM, 0, BlockSize);
                MixScalar(ptrState, ptrM);
            }
        }

        private unsafe void MixScalar(uint* ptrState, uint* ptrM)
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

            // Round 1.
            v0 += m0;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m2;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m4;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m6;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m5;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m7;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m3;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m1;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m8;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m10;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m12;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m14;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m13;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m15;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m11;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m9;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 2.
            v0 += m14;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m4;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m9;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m13;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m15;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m6;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m8;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m10;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m1;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m0;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m11;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m5;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m7;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m3;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m2;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m12;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 3.
            v0 += m11;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m12;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m5;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m15;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m2;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m13;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m0;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m8;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m10;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m3;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m7;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m9;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m1;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m4;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m6;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m14;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 4.
            v0 += m7;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m3;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m13;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m11;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m12;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m14;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m1;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m9;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m2;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m5;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m4;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m15;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m0;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m8;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m10;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m6;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 5.
            v0 += m9;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m5;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m2;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m10;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m4;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m15;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m7;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m0;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m14;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m11;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m6;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m3;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m8;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m13;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m12;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m1;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 6.
            v0 += m2;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m6;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m0;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m8;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m11;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m3;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m10;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m12;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m4;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m7;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m15;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m1;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m14;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m9;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m5;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m13;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 7.
            v0 += m12;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m1;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m14;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m4;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m13;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m10;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m15;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m5;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m0;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m6;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m9;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m8;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m2;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m11;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m3;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m7;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 8.
            v0 += m13;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m7;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m12;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m3;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m1;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m9;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m14;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m11;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m5;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m15;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m8;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m2;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m6;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m10;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m4;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m0;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 9.
            v0 += m6;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m14;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m11;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m0;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m3;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m8;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m9;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m15;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m12;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m13;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m1;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m10;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m4;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m5;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m7;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m2;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);

            // Round 10.
            v0 += m10;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 16);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 12);
            v1 += m8;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 16);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 12);
            v2 += m7;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 16);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 12);
            v3 += m1;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 16);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 12);
            v2 += m6;
            v2 += v6;
            v14 ^= v2;
            v14 = Bits.RotateRight32(v14, 8);
            v10 += v14;
            v6 ^= v10;
            v6 = Bits.RotateRight32(v6, 7);
            v3 += m5;
            v3 += v7;
            v15 ^= v3;
            v15 = Bits.RotateRight32(v15, 8);
            v11 += v15;
            v7 ^= v11;
            v7 = Bits.RotateRight32(v7, 7);
            v1 += m4;
            v1 += v5;
            v13 ^= v1;
            v13 = Bits.RotateRight32(v13, 8);
            v9 += v13;
            v5 ^= v9;
            v5 = Bits.RotateRight32(v5, 7);
            v0 += m2;
            v0 += v4;
            v12 ^= v0;
            v12 = Bits.RotateRight32(v12, 8);
            v8 += v12;
            v4 ^= v8;
            v4 = Bits.RotateRight32(v4, 7);
            v0 += m15;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 16);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 12);
            v1 += m9;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 16);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 12);
            v2 += m3;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 16);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 12);
            v3 += m13;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 16);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 12);
            v2 += m12;
            v2 += v7;
            v13 ^= v2;
            v13 = Bits.RotateRight32(v13, 8);
            v8 += v13;
            v7 ^= v8;
            v7 = Bits.RotateRight32(v7, 7);
            v3 += m0;
            v3 += v4;
            v14 ^= v3;
            v14 = Bits.RotateRight32(v14, 8);
            v9 += v14;
            v4 ^= v9;
            v4 = Bits.RotateRight32(v4, 7);
            v1 += m14;
            v1 += v6;
            v12 ^= v1;
            v12 = Bits.RotateRight32(v12, 8);
            v11 += v12;
            v6 ^= v11;
            v6 = Bits.RotateRight32(v6, 7);
            v0 += m11;
            v0 += v5;
            v15 ^= v0;
            v15 = Bits.RotateRight32(v15, 8);
            v10 += v15;
            v5 ^= v10;
            v5 = Bits.RotateRight32(v5, 7);
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
            Blake2SIncrementCounter((uint)FilledBufferCount);

            FinalizationFlag0 = uint.MaxValue;

            if (TreeConfig != null && TreeConfig.IsLastNode)
                FinalizationFlag1 = uint.MaxValue;

            var count = Buffer.Length - FilledBufferCount;

            if (count > 0)
                ArrayUtils.Fill(Buffer, FilledBufferCount, count + FilledBufferCount, (byte)0);

            fixed (byte* bufferPtr = Buffer)
            {
                Compress(bufferPtr, 0);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Blake2SIncrementCounter(uint incrementCount)
        {
            Counter0 += incrementCount;
            Counter1 += Convert.ToUInt32(Counter0 < incrementCount);
        }
    }

    internal sealed class Blake2XS : Blake2S, IXOF
    {
        private const string InvalidXofSize = "XOFSizeInBits must be multiples of 8 and be between {0} and {1} bytes.";
        private const string InvalidOutputLength = "Output length is above the digest length";
        private const string MaximumOutputLengthExceeded = "Maximum length is 2^32 blocks of 32 bytes";
        private const string WriteToXofAfterReadError = "'{0}' write to Xof after read not allowed";

        private const int Blake2SHashSize = 32;

        // Magic number to indicate an unknown length of digest
        private const uint UnknownDigestLengthInBytes = (ushort)(((uint)1 << 16) - 1);
        private const ulong MaxNumberBlocks = (ulong)1 << 32;

        // 2^32 blocks of 32 bytes (128GiB)
        // the maximum size in bytes the digest can produce when the length is unknown
        private const ulong UnknownMaxDigestLengthInBytes = MaxNumberBlocks * Blake2SHashSize;

        private ulong _xofSizeInBits, _digestPosition;
        private Blake2XSConfig _outputConfig;

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
                _rootHashDigest = new byte[Blake2SHashSize];
                fixed (uint* statePtr = State)
                {
                    fixed (byte* rootHashDigestPtr = _rootHashDigest)
                    {
                        Converters.le32_copy(statePtr, 0, rootHashDigestPtr, 0,
                            _rootHashDigest.Length);
                    }
                }
            }

            while (outputLength > 0)
            {
                if ((_digestPosition & Blake2SHashSize - 1) == 0)
                {
                    _outputConfig.Config.HashSize = ComputeStepLength();
                    _outputConfig.TreeConfig.InnerHashSize = Blake2SHashSize;

                    _buffer = new Blake2S(_outputConfig.Config, _outputConfig.TreeConfig)
                        .ComputeByteSpan(_rootHashDigest).GetBytes();
                    _outputConfig.TreeConfig.NodeOffset += 1;
                }

                var blockOffset = (int)(_digestPosition & (Blake2SHashSize - 1));

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
        private static Blake2SConfig CreateConfig(Blake2XSConfig config) =>
            config.Config ?? Blake2SConfig.DefaultConfig;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Blake2STreeConfig CreateTreeConfig(Blake2XSConfig config) =>
            config.TreeConfig ?? Blake2STreeConfig.SequentialTreeConfig;

        internal Blake2XS(Blake2XSConfig config) : this(CreateConfig(config),
            CreateTreeConfig(config))
        {
            _buffer = new byte[Blake2SHashSize];

            // Create initial config for output hashes.
            _outputConfig = Blake2XSConfig.CreateBlake2XSConfig(new Blake2SConfig
            {
                Salt = Config.Salt,
                Personalization = Config.Personalization
            }, Blake2STreeConfig.DefaultTreeConfig);
        }

        private Blake2XS(Blake2SConfig config, Blake2STreeConfig treeConfig)
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
            new Blake2XS(Config, TreeConfig)
            {
                // Blake2S Cloning
                M = ArrayUtils.Clone(M),
                State = ArrayUtils.Clone(State),
                Buffer = ArrayUtils.Clone(Buffer),
                FilledBufferCount = FilledBufferCount,
                Counter0 = Counter0,
                Counter1 = Counter1,
                FinalizationFlag0 = FinalizationFlag0,
                FinalizationFlag1 = FinalizationFlag1,
                BufferSize = BufferSize,
                // Blake2XS Cloning
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
                return Blake2SHashSize;

            return (int)Math.Min(Blake2SHashSize, diff);
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